package sso

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

// ErrNotFound is returned when no provider matches the query.
var ErrNotFound = errors.New("sso provider not found")

// Store provides DB-backed access to tenant_sso_providers.
type Store struct {
	pool dbutil.Querier
}

// NewStore constructs a Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: dbutil.Wrap(pool)}
}

// Create inserts a new SSO provider row.
func (s *Store) Create(ctx context.Context, tenantID uuid.UUID, typ, provider string, config json.RawMessage) (*Provider, error) {
	var p Provider
	var cfgRaw []byte
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant_sso_providers (tenant_id, type, provider, config)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, type, provider, config, enabled
	`, tenantID, typ, provider, []byte(config)).
		Scan(&p.ID, &p.TenantID, &p.Type, &p.Provider, &cfgRaw, &p.Enabled)
	if err != nil {
		return nil, fmt.Errorf("sso.Create tenant=%s type=%s: %w", tenantID, typ, err)
	}
	p.Config = json.RawMessage(cfgRaw)
	return &p, nil
}

// Get returns a single SSO provider by tenant + provider ID.
func (s *Store) Get(ctx context.Context, tenantID, providerID uuid.UUID) (*Provider, error) {
	var p Provider
	var cfgRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, type, provider, config, enabled
		FROM tenant_sso_providers
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, providerID).
		Scan(&p.ID, &p.TenantID, &p.Type, &p.Provider, &cfgRaw, &p.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("sso.Get %s: %w", providerID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("sso.Get tenant=%s id=%s: %w", tenantID, providerID, err)
	}
	p.Config = json.RawMessage(cfgRaw)
	return &p, nil
}

// List returns all SSO providers for a tenant.
func (s *Store) List(ctx context.Context, tenantID uuid.UUID) ([]*Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, type, provider, config, enabled
		FROM tenant_sso_providers
		WHERE tenant_id = $1
		ORDER BY type, provider
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sso.List tenant=%s: %w", tenantID, err)
	}
	defer rows.Close()

	var providers []*Provider
	for rows.Next() {
		var p Provider
		var cfgRaw []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Type, &p.Provider, &cfgRaw, &p.Enabled); err != nil {
			return nil, fmt.Errorf("sso.List scan: %w", err)
		}
		p.Config = json.RawMessage(cfgRaw)
		providers = append(providers, &p)
	}
	return providers, rows.Err()
}

// ListByType returns enabled SSO providers of a given type for a tenant.
func (s *Store) ListByType(ctx context.Context, tenantID uuid.UUID, typ string) ([]*Provider, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, type, provider, config, enabled
		FROM tenant_sso_providers
		WHERE tenant_id = $1 AND type = $2 AND enabled = true
		ORDER BY provider
	`, tenantID, typ)
	if err != nil {
		return nil, fmt.Errorf("sso.ListByType tenant=%s type=%s: %w", tenantID, typ, err)
	}
	defer rows.Close()

	var providers []*Provider
	for rows.Next() {
		var p Provider
		var cfgRaw []byte
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Type, &p.Provider, &cfgRaw, &p.Enabled); err != nil {
			return nil, fmt.Errorf("sso.ListByType scan: %w", err)
		}
		p.Config = json.RawMessage(cfgRaw)
		providers = append(providers, &p)
	}
	return providers, rows.Err()
}

// Delete removes an SSO provider row.
func (s *Store) Delete(ctx context.Context, tenantID, providerID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM tenant_sso_providers WHERE tenant_id = $1 AND id = $2`,
		tenantID, providerID,
	)
	if err != nil {
		return fmt.Errorf("sso.Delete tenant=%s id=%s: %w", tenantID, providerID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("sso.Delete %s: %w", providerID, ErrNotFound)
	}
	return nil
}

// SetEnabled toggles the enabled flag on an SSO provider.
func (s *Store) SetEnabled(ctx context.Context, tenantID, providerID uuid.UUID, enabled bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE tenant_sso_providers SET enabled = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, providerID, enabled,
	)
	if err != nil {
		return fmt.Errorf("sso.SetEnabled tenant=%s id=%s: %w", tenantID, providerID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("sso.SetEnabled %s: %w", providerID, ErrNotFound)
	}
	return nil
}
