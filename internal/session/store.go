package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/enterprise-idp/idpd/internal/dbutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store provides DB-backed access to the sessions table.
type Store struct {
	pool dbutil.Querier
}

// NewStore constructs a Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: dbutil.Wrap(pool)}
}

// Create inserts a new active session and returns it.
func (s *Store) Create(ctx context.Context, tenantID, identityID uuid.UUID, aal string, amr []string, ttl time.Duration) (*Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("session.Create generate token: %w", err)
	}

	if amr == nil {
		amr = []string{}
	}
	amrJSON, err := json.Marshal(amr)
	if err != nil {
		return nil, fmt.Errorf("session.Create marshal amr: %w", err)
	}

	expiresAt := time.Now().Add(ttl)

	var sess Session
	var amrRaw []byte
	err = s.pool.QueryRow(ctx, `
		INSERT INTO sessions (tenant_id, identity_id, token, expires_at, authenticator_assurance_level, amr)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, tenant_id, identity_id, token, expires_at, authenticator_assurance_level, amr, active
	`, tenantID, identityID, token, expiresAt, aal, amrJSON).
		Scan(&sess.ID, &sess.TenantID, &sess.IdentityID, &sess.Token,
			&sess.ExpiresAt, &sess.AAL, &amrRaw, &sess.Active)
	if err != nil {
		return nil, fmt.Errorf("session.Create tenant=%s identity=%s: %w", tenantID, identityID, err)
	}

	if err := decodeAMR(amrRaw, &sess.AMR); err != nil {
		return nil, fmt.Errorf("session.Create decode amr: %w", err)
	}
	return &sess, nil
}

// GetByToken looks up an active, non-expired session by tenant + token.
func (s *Store) GetByToken(ctx context.Context, tenantID uuid.UUID, token string) (*Session, error) {
	var sess Session
	var amrRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, identity_id, token, expires_at, authenticator_assurance_level, amr, active
		FROM sessions
		WHERE tenant_id = $1 AND token = $2
	`, tenantID, token).
		Scan(&sess.ID, &sess.TenantID, &sess.IdentityID, &sess.Token,
			&sess.ExpiresAt, &sess.AAL, &amrRaw, &sess.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("session.GetByToken: %w", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("session.GetByToken tenant=%s: %w", tenantID, err)
	}
	if !sess.Active {
		return nil, fmt.Errorf("session.GetByToken: %w", ErrRevoked)
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, fmt.Errorf("session.GetByToken: %w", ErrExpired)
	}
	if err := decodeAMR(amrRaw, &sess.AMR); err != nil {
		return nil, fmt.Errorf("session.GetByToken decode amr: %w", err)
	}
	return &sess, nil
}

// Revoke marks a session as inactive.
func (s *Store) Revoke(ctx context.Context, tenantID, sessionID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET active = false WHERE tenant_id = $1 AND id = $2`,
		tenantID, sessionID,
	)
	if err != nil {
		return fmt.Errorf("session.Revoke tenant=%s id=%s: %w", tenantID, sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session.Revoke: %w", ErrNotFound)
	}
	return nil
}

// RevokeByToken revokes the session identified by its token value.
func (s *Store) RevokeByToken(ctx context.Context, tenantID uuid.UUID, token string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sessions SET active = false WHERE tenant_id = $1 AND token = $2`,
		tenantID, token,
	)
	if err != nil {
		return fmt.Errorf("session.RevokeByToken tenant=%s: %w", tenantID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session.RevokeByToken: %w", ErrNotFound)
	}
	return nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeAMR(raw []byte, dst *[]string) error {
	if len(raw) == 0 || string(raw) == "null" {
		*dst = []string{}
		return nil
	}
	return json.Unmarshal(raw, dst)
}
