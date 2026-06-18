package identity

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

// ErrNotFound is returned when no identity or credential matches the query.
var ErrNotFound = errors.New("credential not found")

const (
	StateActive              = "active"
	StatePendingVerification = "pending_verification"
)

// Identity represents a row in the identities table.
type Identity struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	SchemaID uuid.UUID
	Traits   json.RawMessage
	State    string
}

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
	pool dbutil.Querier
}

// NewStore constructs a Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: dbutil.Wrap(pool)}
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

// CreateIdentity inserts a new identity row and returns it.
func (s *Store) CreateIdentity(ctx context.Context, tenantID, schemaID uuid.UUID, traits json.RawMessage, state string) (*Identity, error) {
	var ident Identity
	var traitsRaw []byte
	err := s.pool.QueryRow(ctx, `
		INSERT INTO identities (tenant_id, schema_id, traits, state)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, schema_id, traits, state
	`, tenantID, schemaID, []byte(traits), state).
		Scan(&ident.ID, &ident.TenantID, &ident.SchemaID, &traitsRaw, &ident.State)
	if err != nil {
		return nil, fmt.Errorf("identity.CreateIdentity tenant=%s: %w", tenantID, err)
	}
	ident.Traits = json.RawMessage(traitsRaw)
	return &ident, nil
}

// GetIdentity returns an identity by tenant + id. Returns ErrNotFound (wrapped) when absent.
func (s *Store) GetIdentity(ctx context.Context, tenantID, identityID uuid.UUID) (*Identity, error) {
	var ident Identity
	var traitsRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, schema_id, traits, state
		FROM identities
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, identityID).
		Scan(&ident.ID, &ident.TenantID, &ident.SchemaID, &traitsRaw, &ident.State)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("identity.GetIdentity %s: %w", identityID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("identity.GetIdentity tenant=%s id=%s: %w", tenantID, identityID, err)
	}
	ident.Traits = json.RawMessage(traitsRaw)
	return &ident, nil
}

// UpdateIdentityState changes the state column of an identity.
func (s *Store) UpdateIdentityState(ctx context.Context, tenantID, identityID uuid.UUID, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE identities SET state = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, identityID, state,
	)
	if err != nil {
		return fmt.Errorf("identity.UpdateIdentityState tenant=%s id=%s: %w", tenantID, identityID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("identity.UpdateIdentityState %s: %w", identityID, ErrNotFound)
	}
	return nil
}

// GetIdentityIDByIdentifier finds the identity that owns a credential with the
// given identifier value, regardless of credential type. Used by the recovery
// flow to locate an account by email across all credential types.
func (s *Store) GetIdentityIDByIdentifier(ctx context.Context, tenantID uuid.UUID, identifier string) (uuid.UUID, error) {
	var identityID uuid.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT identity_id FROM identity_credentials
		WHERE tenant_id = $1 AND $2 = ANY(identifiers)
		LIMIT 1
	`, tenantID, identifier).Scan(&identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("identity.GetIdentityIDByIdentifier %q: %w", identifier, ErrNotFound)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("identity.GetIdentityIDByIdentifier tenant=%s: %w", tenantID, err)
	}
	return identityID, nil
}

// UpdateTraits replaces the traits JSONB for an identity.
func (s *Store) UpdateTraits(ctx context.Context, tenantID, identityID uuid.UUID, traits json.RawMessage) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE identities SET traits = $3 WHERE tenant_id = $1 AND id = $2`,
		tenantID, identityID, []byte(traits),
	)
	if err != nil {
		return fmt.Errorf("identity.UpdateTraits tenant=%s id=%s: %w", tenantID, identityID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("identity.UpdateTraits %s: %w", identityID, ErrNotFound)
	}
	return nil
}

// UpsertCredential inserts a new credential or replaces the config and
// identifiers of an existing one (matched by tenant+identity+type).
func (s *Store) UpsertCredential(ctx context.Context, tenantID, identityID uuid.UUID, credType string, identifiers []string, config json.RawMessage) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, type, identifiers) DO UPDATE
		  SET config = EXCLUDED.config,
		      identifiers = EXCLUDED.identifiers
	`, tenantID, identityID, credType, identifiers, []byte(config))
	if err != nil {
		return fmt.Errorf("identity.UpsertCredential tenant=%s identity=%s type=%s: %w",
			tenantID, identityID, credType, err)
	}
	return nil
}
