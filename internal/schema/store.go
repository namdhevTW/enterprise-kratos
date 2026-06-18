package schema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/enterprise-idp/idpd/internal/dbutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when no active schema exists for a tenant.
var ErrNotFound = errors.New("schema not found")

// Schema represents a row in identity_schemas.
type Schema struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Version  int
	Schema   json.RawMessage
	IsActive bool
}

// defaultSchemaJSON is the minimal default identity schema used when a tenant
// has not configured a custom one. Full JSON-Schema validation is added in step 6.
var defaultSchemaJSON = json.RawMessage(`{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "email": {"type": "string", "format": "email"}
  },
  "required": ["email"]
}`)

// Store provides DB-backed access to identity_schemas.
type Store struct {
	pool dbutil.Querier
}

// NewStore constructs a Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: dbutil.Wrap(pool)}
}

// GetActive returns the highest-versioned active schema for tenantID.
// Returns ErrNotFound (wrapped) when none exists.
func (s *Store) GetActive(ctx context.Context, tenantID uuid.UUID) (*Schema, error) {
	var sch Schema
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, version, schema, is_active
		FROM identity_schemas
		WHERE tenant_id = $1 AND is_active = true
		ORDER BY version DESC
		LIMIT 1
	`, tenantID).Scan(&sch.ID, &sch.TenantID, &sch.Version, &raw, &sch.IsActive)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("schema.GetActive tenant=%s: %w", tenantID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("schema.GetActive tenant=%s: %w", tenantID, err)
	}
	sch.Schema = json.RawMessage(raw)
	return &sch, nil
}

// EnsureDefault returns the active schema for tenantID, creating a default one
// if none exists yet.
func (s *Store) EnsureDefault(ctx context.Context, tenantID uuid.UUID) (*Schema, error) {
	sch, err := s.GetActive(ctx, tenantID)
	if err == nil {
		return sch, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	// No schema yet — insert the default.
	var created Schema
	var raw []byte
	insertErr := s.pool.QueryRow(ctx, `
		INSERT INTO identity_schemas (tenant_id, version, schema, is_active)
		VALUES ($1, 1, $2, true)
		RETURNING id, tenant_id, version, schema, is_active
	`, tenantID, []byte(defaultSchemaJSON)).
		Scan(&created.ID, &created.TenantID, &created.Version, &raw, &created.IsActive)
	if insertErr != nil {
		// A concurrent request may have inserted one; try fetching again.
		if sch2, getErr := s.GetActive(ctx, tenantID); getErr == nil {
			return sch2, nil
		}
		return nil, fmt.Errorf("schema.EnsureDefault tenant=%s: %w", tenantID, insertErr)
	}
	created.Schema = json.RawMessage(raw)
	return &created, nil
}
