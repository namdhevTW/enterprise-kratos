package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoginPolicy controls which authentication methods are allowed for login.
type LoginPolicy struct {
	AllowedFirstFactors  []string `json:"allowed_first_factors"`
	AllowedSecondFactors []string `json:"allowed_second_factors"`
	MFARequired          bool     `json:"mfa_required"`
	SSOOnly              bool     `json:"sso_only"`
}

// RegistrationPolicy controls self-service registration behaviour.
type RegistrationPolicy struct {
	Enabled             bool `json:"enabled"`
	RequireVerification bool `json:"require_verification"`
}

// SessionPolicy controls session lifetime and assurance requirements.
type SessionPolicy struct {
	TTL               string `json:"ttl"`
	RequiredAAL       string `json:"required_aal"`
	InactivityTimeout string `json:"inactivity_timeout"`
}

// RecoveryPolicy controls account recovery options.
type RecoveryPolicy struct {
	Enabled        bool     `json:"enabled"`
	AllowedMethods []string `json:"allowed_methods"`
}

// FlowPolicy is the per-tenant policy that governs all self-service flows.
type FlowPolicy struct {
	Login        LoginPolicy        `json:"login"`
	Registration RegistrationPolicy `json:"registration"`
	Session      SessionPolicy      `json:"session"`
	Recovery     RecoveryPolicy     `json:"recovery"`
}

// Default returns a sensible policy for tenants that have no explicit row.
func Default() *FlowPolicy {
	return &FlowPolicy{
		Login: LoginPolicy{
			AllowedFirstFactors:  []string{"password"},
			AllowedSecondFactors: []string{},
			MFARequired:          false,
			SSOOnly:              false,
		},
		Registration: RegistrationPolicy{
			Enabled:             true,
			RequireVerification: false,
		},
		Session: SessionPolicy{
			TTL:               "24h",
			RequiredAAL:       "aal1",
			InactivityTimeout: "1h",
		},
		Recovery: RecoveryPolicy{
			Enabled:        true,
			AllowedMethods: []string{"link"},
		},
	}
}

// Store provides DB-backed access to tenant_flow_policies.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore constructs a Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Get returns the FlowPolicy for tenantID, falling back to Default() when no row exists.
func (s *Store) Get(ctx context.Context, tenantID uuid.UUID) (*FlowPolicy, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT policy FROM tenant_flow_policies WHERE tenant_id = $1`,
		tenantID,
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("policy.Get tenant=%s: %w", tenantID, err)
	}

	var p FlowPolicy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("policy.Get decode tenant=%s: %w", tenantID, err)
	}
	return &p, nil
}

// Upsert inserts or replaces the FlowPolicy for tenantID.
func (s *Store) Upsert(ctx context.Context, tenantID uuid.UUID, p *FlowPolicy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("policy.Upsert marshal tenant=%s: %w", tenantID, err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO tenant_flow_policies (tenant_id, policy)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET policy = EXCLUDED.policy
	`, tenantID, raw)
	if err != nil {
		return fmt.Errorf("policy.Upsert tenant=%s: %w", tenantID, err)
	}
	return nil
}
