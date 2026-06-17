package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when no credential matches the query.
var ErrNotFound = errors.New("credential not found")

// Credential represents a row in identity_credentials.
type Credential struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	IdentityID   uuid.UUID
	Type         string
	Identifiers  []string
	Config       json.RawMessage
}

// Store provides read access to identity_credentials.
// Write operations (create, delete) are handled by the registration and
// settings flow engines in later steps.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore constructs a Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// GetByIdentifier finds the credential where identifier appears in the
// identifiers TEXT[] column. Returns ErrNotFound (wrapped) when no match.
func (s *Store) GetByIdentifier(ctx context.Context, tenantID uuid.UUID, credType, identifier string) (*Credential, error) {
	var c Credential
	var configRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, identity_id, type, identifiers, config
		FROM identity_credentials
		WHERE tenant_id = $1 AND type = $2 AND $3 = ANY(identifiers)
		LIMIT 1
	`, tenantID, credType, identifier).
		Scan(&c.ID, &c.TenantID, &c.IdentityID, &c.Type, &c.Identifiers, &configRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("identity.GetByIdentifier tenant=%s type=%s: %w", tenantID, credType, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("identity.GetByIdentifier tenant=%s type=%s: %w", tenantID, credType, err)
	}
	if err := json.Unmarshal(configRaw, &c.Config); err != nil {
		return nil, fmt.Errorf("identity.GetByIdentifier decode config: %w", err)
	}
	return &c, nil
}

// GetByIdentityAndType loads a specific credential type for an identity.
// Returns ErrNotFound (wrapped) when no match exists.
func (s *Store) GetByIdentityAndType(ctx context.Context, tenantID, identityID uuid.UUID, credType string) (*Credential, error) {
	var c Credential
	var configRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, identity_id, type, identifiers, config
		FROM identity_credentials
		WHERE tenant_id = $1 AND identity_id = $2 AND type = $3
		LIMIT 1
	`, tenantID, identityID, credType).
		Scan(&c.ID, &c.TenantID, &c.IdentityID, &c.Type, &c.Identifiers, &configRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("identity.GetByIdentityAndType identity=%s type=%s: %w", identityID, credType, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("identity.GetByIdentityAndType identity=%s type=%s: %w", identityID, credType, err)
	}
	if err := json.Unmarshal(configRaw, &c.Config); err != nil {
		return nil, fmt.Errorf("identity.GetByIdentityAndType decode config: %w", err)
	}
	return &c, nil
}

// CreateCredential inserts a new credential row. Used by registration and
// settings flows in later steps.
func (s *Store) CreateCredential(ctx context.Context, tenantID, identityID uuid.UUID, credType string, identifiers []string, config json.RawMessage) (*Credential, error) {
	var c Credential
	var configRaw []byte
	err := s.pool.QueryRow(ctx, `
		INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, tenant_id, identity_id, type, identifiers, config
	`, tenantID, identityID, credType, identifiers, []byte(config)).
		Scan(&c.ID, &c.TenantID, &c.IdentityID, &c.Type, &c.Identifiers, &configRaw)
	if err != nil {
		return nil, fmt.Errorf("identity.CreateCredential tenant=%s identity=%s type=%s: %w", tenantID, identityID, credType, err)
	}
	if err := json.Unmarshal(configRaw, &c.Config); err != nil {
		return nil, fmt.Errorf("identity.CreateCredential decode config: %w", err)
	}
	return &c, nil
}
