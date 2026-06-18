package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options controls a single migration run.
type Options struct {
	TargetTenantSlug string
	TargetTenantName string // defaults to slug if empty
	IncludeSessions  bool
}

// Migrator reads from a Kratos instance and writes to the IDP.
type Migrator struct {
	cfg    *KratosConfig
	src    *KratosReader // Kratos source DB
	dst    *pgxpool.Pool // IDP target DB
	opts   Options
}

// New constructs a Migrator.
func New(cfg *KratosConfig, src *KratosReader, dst *pgxpool.Pool, opts Options) *Migrator {
	if opts.TargetTenantName == "" {
		opts.TargetTenantName = opts.TargetTenantSlug
	}
	return &Migrator{cfg: cfg, src: src, dst: dst, opts: opts}
}

// Run executes the full migration and reports progress to slog.
func (m *Migrator) Run(ctx context.Context) error {
	slog.Info("migration starting", "tenant", m.opts.TargetTenantSlug)

	tenantID, err := m.ensureTenant(ctx)
	if err != nil {
		return fmt.Errorf("ensure tenant: %w", err)
	}
	slog.Info("tenant ready", "tenant_id", tenantID)

	schemaID, err := m.migrateSchema(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	slog.Info("identity schema migrated", "schema_id", schemaID)

	if err := m.migratePolicy(ctx, tenantID); err != nil {
		return fmt.Errorf("migrate policy: %w", err)
	}
	slog.Info("flow policy migrated")

	// providerMap: Kratos provider string ID → IDP provider UUID
	providerMap, err := m.migrateSSO(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("migrate SSO providers: %w", err)
	}
	slog.Info("SSO providers migrated", "count", len(providerMap))

	identityMap, err := m.migrateIdentities(ctx, tenantID, schemaID, providerMap)
	if err != nil {
		return fmt.Errorf("migrate identities: %w", err)
	}
	slog.Info("identities migrated", "count", len(identityMap))

	if m.opts.IncludeSessions {
		n, err := m.migrateSessions(ctx, tenantID, identityMap)
		if err != nil {
			return fmt.Errorf("migrate sessions: %w", err)
		}
		slog.Info("sessions migrated", "count", n)
	}

	slog.Info("migration complete")
	return nil
}

// ---- Step 1: ensure tenant --------------------------------------------------

func (m *Migrator) ensureTenant(ctx context.Context) (uuid.UUID, error) {
	var id uuid.UUID
	err := m.dst.QueryRow(ctx, `
		INSERT INTO tenants (slug, name, state)
		VALUES ($1, $2, 'active')
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`, m.opts.TargetTenantSlug, m.opts.TargetTenantName).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("upsert tenant: %w", err)
	}
	return id, nil
}

// ---- Step 2: identity schema ------------------------------------------------

func (m *Migrator) migrateSchema(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	// Use the Kratos default schema.
	defaultID := m.cfg.Identity.DefaultSchemaID
	var schemaURL string
	for _, s := range m.cfg.Identity.Schemas {
		if s.ID == defaultID {
			schemaURL = s.URL
			break
		}
	}

	var schemaJSON json.RawMessage
	if schemaURL == "" {
		slog.Warn("no identity schema URL found in Kratos config; using minimal default")
		schemaJSON = json.RawMessage(`{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "email": {"type": "string", "format": "email"}
  },
  "required": ["email"]
}`)
	} else {
		var err error
		schemaJSON, err = FetchSchema(schemaURL)
		if err != nil {
			return uuid.Nil, fmt.Errorf("fetch schema from %q: %w", schemaURL, err)
		}
	}

	// Deactivate any existing active schemas before inserting.
	if _, err := m.dst.Exec(ctx,
		`UPDATE identity_schemas SET is_active = false WHERE tenant_id = $1 AND is_active = true`,
		tenantID,
	); err != nil {
		return uuid.Nil, fmt.Errorf("deactivate old schemas: %w", err)
	}

	var id uuid.UUID
	if err := m.dst.QueryRow(ctx, `
		INSERT INTO identity_schemas (tenant_id, version, schema, is_active)
		VALUES ($1, 1, $2, true)
		RETURNING id
	`, tenantID, []byte(schemaJSON)).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("insert schema: %w", err)
	}
	return id, nil
}

// ---- Step 3: flow policy ----------------------------------------------------

func (m *Migrator) migratePolicy(ctx context.Context, tenantID uuid.UUID) error {
	sessionTTL := "24h"
	if m.cfg.Session.Lifespan != "" {
		sessionTTL = m.cfg.Session.Lifespan
	}

	recoveryMethods := []string{}
	if m.cfg.SelfService.Flows.Recovery.Enabled {
		use := m.cfg.SelfService.Flows.Recovery.Use
		if use == "" {
			use = "link"
		}
		recoveryMethods = append(recoveryMethods, use)
	}

	policy := map[string]any{
		"login": map[string]any{
			"allowed_first_factors":  m.cfg.AllowedFirstFactors(),
			"allowed_second_factors": []string{},
			"mfa_required":           false,
			"sso_only":               !m.cfg.SelfService.Methods.Password.Enabled && m.cfg.SelfService.Methods.OIDC.Enabled,
		},
		"registration": map[string]any{
			"enabled":              true,
			"require_verification": m.cfg.RequireVerification(),
		},
		"session": map[string]any{
			"ttl":                sessionTTL,
			"required_aal":       "aal1",
			"inactivity_timeout": "1h",
		},
		"recovery": map[string]any{
			"enabled":         m.cfg.SelfService.Flows.Recovery.Enabled,
			"allowed_methods": recoveryMethods,
		},
	}

	raw, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	_, err = m.dst.Exec(ctx, `
		INSERT INTO tenant_flow_policies (tenant_id, policy)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET policy = EXCLUDED.policy
	`, tenantID, raw)
	return err
}

// ---- Step 4: SSO providers --------------------------------------------------

// migrateSSO inserts OIDC providers from the Kratos config into tenant_sso_providers.
// Returns a map from Kratos provider ID string → IDP provider UUID.
func (m *Migrator) migrateSSO(ctx context.Context, tenantID uuid.UUID) (map[string]uuid.UUID, error) {
	providerMap := make(map[string]uuid.UUID)

	for _, p := range m.cfg.SelfService.Methods.OIDC.Config.Providers {
		scopes := p.Scope
		if len(scopes) == 0 {
			scopes = []string{"openid", "email", "profile"}
		}
		cfg := map[string]any{
			"client_id":     p.ClientID,
			"client_secret": p.ClientSecret,
			"issuer_url":    p.IssuerURL,
			"scopes":        scopes,
		}
		raw, _ := json.Marshal(cfg)

		var providerID uuid.UUID
		// Upsert by (tenant_id, provider name) — no natural unique key, so we
		// check for an existing row first to support re-runs.
		err := m.dst.QueryRow(ctx, `
			SELECT id FROM tenant_sso_providers
			WHERE tenant_id = $1 AND type = 'oidc' AND provider = $2
			LIMIT 1
		`, tenantID, p.Provider).Scan(&providerID)

		if errors.Is(err, pgx.ErrNoRows) {
			if err := m.dst.QueryRow(ctx, `
				INSERT INTO tenant_sso_providers (tenant_id, type, provider, config)
				VALUES ($1, 'oidc', $2, $3)
				RETURNING id
			`, tenantID, p.Provider, raw).Scan(&providerID); err != nil {
				return nil, fmt.Errorf("insert SSO provider %q: %w", p.ID, err)
			}
			slog.Info("SSO provider created", "provider", p.Provider, "id", providerID)
		} else if err != nil {
			return nil, fmt.Errorf("lookup SSO provider %q: %w", p.ID, err)
		} else {
			slog.Info("SSO provider already exists", "provider", p.Provider, "id", providerID)
		}

		providerMap[p.ID] = providerID
	}

	return providerMap, nil
}

// ---- Step 5: identities + credentials ---------------------------------------

// migrateIdentities reads identities and credentials from Kratos, writes them
// to the IDP, and returns a mapping of Kratos identity UUID → IDP identity UUID.
func (m *Migrator) migrateIdentities(ctx context.Context, tenantID, schemaID uuid.UUID, providerMap map[string]uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	kratosIdentities, err := m.src.Identities(ctx)
	if err != nil {
		return nil, err
	}
	kratosCreds, err := m.src.Credentials(ctx)
	if err != nil {
		return nil, err
	}

	// Index credentials by identity ID.
	credsByIdentity := make(map[uuid.UUID][]*KratosCredential, len(kratosCreds))
	for _, c := range kratosCreds {
		credsByIdentity[c.IdentityID] = append(credsByIdentity[c.IdentityID], c)
	}

	identityMap := make(map[uuid.UUID]uuid.UUID, len(kratosIdentities))
	skipped := 0

	for _, ki := range kratosIdentities {
		state := ki.State
		if state != "active" && state != "inactive" {
			state = "active"
		}
		// Map Kratos "inactive" → IDP "pending_verification"
		idpState := state
		if state == "inactive" {
			idpState = "pending_verification"
		}

		var newIdentityID uuid.UUID
		if err := m.dst.QueryRow(ctx, `
			INSERT INTO identities (tenant_id, schema_id, traits, state)
			VALUES ($1, $2, $3, $4)
			RETURNING id
		`, tenantID, schemaID, []byte(ki.Traits), idpState).Scan(&newIdentityID); err != nil {
			slog.Warn("identity insert failed, skipping", "kratos_id", ki.ID, "err", err)
			skipped++
			continue
		}

		identityMap[ki.ID] = newIdentityID

		for _, kc := range credsByIdentity[ki.ID] {
			if err := m.migrateCredential(ctx, tenantID, newIdentityID, kc, providerMap); err != nil {
				slog.Warn("credential skipped", "type", kc.Type, "identity", ki.ID, "err", err)
			}
		}
	}

	if skipped > 0 {
		slog.Warn("identities skipped due to errors", "count", skipped)
	}
	return identityMap, nil
}

// migrateCredential translates a single Kratos credential to the IDP format.
func (m *Migrator) migrateCredential(ctx context.Context, tenantID, identityID uuid.UUID, kc *KratosCredential, providerMap map[string]uuid.UUID) error {
	switch kc.Type {
	case "password":
		return m.migratePasswordCred(ctx, tenantID, identityID, kc)
	case "oidc":
		return m.migrateOIDCCred(ctx, tenantID, identityID, kc, providerMap)
	default:
		// totp, lookup_secret, webauthn — out of scope; owned by enterprise services
		slog.Debug("credential type skipped", "type", kc.Type)
		return nil
	}
}

// migratePasswordCred maps a Kratos password credential to the IDP.
// Kratos stores the hash as {"hashed_password":"$argon2id$..."} or bcrypt.
// Our format is identical so we pass the config through unchanged.
func (m *Migrator) migratePasswordCred(ctx context.Context, tenantID, identityID uuid.UUID, kc *KratosCredential) error {
	identifiers := kc.Identifiers
	if len(identifiers) == 0 {
		return fmt.Errorf("password credential has no identifiers")
	}

	// Validate Kratos config has hashed_password
	var check struct {
		HashedPassword string `json:"hashed_password"`
	}
	if err := json.Unmarshal(kc.Config, &check); err != nil || check.HashedPassword == "" {
		return fmt.Errorf("password credential config missing hashed_password")
	}

	_, err := m.dst.Exec(ctx, `
		INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
		VALUES ($1, $2, 'password', $3, $4)
		ON CONFLICT DO NOTHING
	`, tenantID, identityID, identifiers, []byte(kc.Config))
	return err
}

// migrateOIDCCred maps a Kratos OIDC credential to the IDP.
// Kratos stores OIDC as {"providers":[{"subject":"...","provider":"google",...}]}.
// Our format: one credential per provider entry, identifier = "{providerID}:{subject}".
func (m *Migrator) migrateOIDCCred(ctx context.Context, tenantID, identityID uuid.UUID, kc *KratosCredential, providerMap map[string]uuid.UUID) error {
	var kratosOIDC struct {
		Providers []struct {
			Subject  string `json:"subject"`
			Provider string `json:"provider"`
			Email    string `json:"initial_id_token"` // not available, best effort
		} `json:"providers"`
	}
	if err := json.Unmarshal(kc.Config, &kratosOIDC); err != nil {
		return fmt.Errorf("parse OIDC credential config: %w", err)
	}

	for _, entry := range kratosOIDC.Providers {
		providerID, ok := providerMap[entry.Provider]
		if !ok {
			slog.Warn("OIDC provider not in map, skipping credential", "provider", entry.Provider)
			continue
		}

		credIdentifier := fmt.Sprintf("%s:%s", providerID, entry.Subject)
		cfg, _ := json.Marshal(map[string]any{
			"provider_id":   providerID.String(),
			"provider_type": entry.Provider,
			"subject":       entry.Subject,
		})

		_, err := m.dst.Exec(ctx, `
			INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
			VALUES ($1, $2, 'oidc', $3, $4)
			ON CONFLICT DO NOTHING
		`, tenantID, identityID, []string{credIdentifier}, cfg)
		if err != nil {
			return fmt.Errorf("insert OIDC credential: %w", err)
		}
	}
	return nil
}

// ---- Step 6: sessions (optional) --------------------------------------------

func (m *Migrator) migrateSessions(ctx context.Context, tenantID uuid.UUID, identityMap map[uuid.UUID]uuid.UUID) (int, error) {
	kratosSessions, err := m.src.ActiveSessions(ctx)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, ks := range kratosSessions {
		newIdentityID, ok := identityMap[ks.IdentityID]
		if !ok {
			slog.Debug("session references unknown identity, skipping", "identity", ks.IdentityID)
			continue
		}

		aal := ks.AAL
		if aal == "" {
			aal = "aal1"
		}

		// Preserve the original token if it doesn't collide; otherwise skip.
		_, err := m.dst.Exec(ctx, `
			INSERT INTO sessions (tenant_id, identity_id, token, expires_at, authenticator_assurance_level, active)
			VALUES ($1, $2, $3, $4, $5, true)
			ON CONFLICT DO NOTHING
		`, tenantID, newIdentityID, ks.Token, ks.ExpiresAt, aal)
		if err != nil {
			slog.Warn("session insert failed", "id", ks.ID, "err", err)
			continue
		}
		count++
	}
	return count, nil
}

// Ensure time.Time is used.
var _ = time.Now
