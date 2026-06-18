package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/enterprise-idp/idpd/internal/schema"
	"github.com/enterprise-idp/idpd/internal/session"
	"github.com/enterprise-idp/idpd/internal/sso"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// CallbackResult is returned by HandleCallback on success.
type CallbackResult struct {
	Session    *session.Session
	IdentityID uuid.UUID
	IsNew      bool // true when the identity was just provisioned (JIT)
}

// Store interfaces used by the OIDC Engine (same duck-typing pattern as flow engines).
type oidcProviderGetter interface {
	Get(ctx context.Context, tenantID, providerID uuid.UUID) (*sso.Provider, error)
}
type oidcFlowStorer interface {
	Get(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	Update(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error
}
type oidcIdentityStorer interface {
	GetByIdentifier(ctx context.Context, tenantID uuid.UUID, credType, identifier string) (*identity.Credential, error)
	GetIdentity(ctx context.Context, tenantID, identityID uuid.UUID) (*identity.Identity, error)
	CreateIdentity(ctx context.Context, tenantID, schemaID uuid.UUID, traits json.RawMessage, state string) (*identity.Identity, error)
	CreateCredential(ctx context.Context, tenantID, identityID uuid.UUID, credType string, identifiers []string, config json.RawMessage) (*identity.Credential, error)
}
type oidcSchemaEnsurer interface {
	EnsureDefault(ctx context.Context, tenantID uuid.UUID) (*schema.Schema, error)
}
type oidcSessionCreator interface {
	Create(ctx context.Context, tenantID, identityID uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error)
}
type oidcPolicyGetter interface {
	Get(ctx context.Context, tenantID uuid.UUID) (*policy.FlowPolicy, error)
}

// Engine drives the OIDC redirect + callback flow.
type Engine struct {
	providers  oidcProviderGetter
	flows      oidcFlowStorer
	identities oidcIdentityStorer
	schemas    oidcSchemaEnsurer
	sessions   oidcSessionCreator
	policies   oidcPolicyGetter

	// providerCache caches go-oidc Provider instances keyed by issuer URL.
	// Creating a Provider fetches the discovery document (network call) so we
	// reuse instances across requests for the same issuer.
	cacheMu       sync.RWMutex
	providerCache map[string]*gooidc.Provider
}

// New constructs an OIDC Engine.
func New(
	providers oidcProviderGetter,
	flows oidcFlowStorer,
	identities oidcIdentityStorer,
	schemas oidcSchemaEnsurer,
	sessions oidcSessionCreator,
	policies oidcPolicyGetter,
) *Engine {
	return &Engine{
		providers:     providers,
		flows:         flows,
		identities:    identities,
		schemas:       schemas,
		sessions:      sessions,
		policies:      policies,
		providerCache: make(map[string]*gooidc.Provider),
	}
}

// InitiateLogin advances an existing login flow into the OIDC redirect phase.
// Returns the authorization URL the browser should be redirected to.
func (e *Engine) InitiateLogin(ctx context.Context, tenantID, flowID, providerID uuid.UUID) (string, error) {
	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return "", fmt.Errorf("oidc.InitiateLogin: %w", err)
	}
	if f.State != flow.StatePending {
		return "", fmt.Errorf("oidc.InitiateLogin: flow is %s", f.State)
	}

	p, err := e.providers.Get(ctx, tenantID, providerID)
	if err != nil {
		return "", fmt.Errorf("oidc.InitiateLogin: %w", err)
	}
	if !p.Enabled {
		return "", fmt.Errorf("oidc.InitiateLogin: provider %s is disabled", providerID)
	}
	if p.Type != "oidc" {
		return "", fmt.Errorf("oidc.InitiateLogin: provider %s is type %s, not oidc", providerID, p.Type)
	}

	var cfg sso.OIDCConfig
	if err := json.Unmarshal(p.Config, &cfg); err != nil {
		return "", fmt.Errorf("oidc.InitiateLogin: parse provider config: %w", err)
	}

	oidcProvider, err := e.getOIDCProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("oidc.InitiateLogin: load OIDC provider: %w", err)
	}

	nonce, err := randomBase64(16)
	if err != nil {
		return "", fmt.Errorf("oidc.InitiateLogin: generate nonce: %w", err)
	}
	codeVerifier, err := randomBase64(32)
	if err != nil {
		return "", fmt.Errorf("oidc.InitiateLogin: generate code verifier: %w", err)
	}
	codeChallenge := pkceChallenge(codeVerifier)

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Scopes:       scopes,
		Endpoint:     oidcProvider.Endpoint(),
	}

	// state = flowID so the callback can look up the flow
	authURL := oauth2Cfg.AuthCodeURL(
		flowID.String(),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// Store OIDC state inside the flow for the callback to verify.
	if f.UI.Internal == nil {
		f.UI.Internal = &flow.UIInternal{Phase: "first_factor"}
	}
	f.UI.Internal.OIDCProviderID = providerID.String()
	f.UI.Internal.OIDCNonce = nonce
	f.UI.Internal.OIDCCodeVerifier = codeVerifier

	if err := e.flows.Update(ctx, tenantID, flowID, flow.StatePending, f.IdentityID, f.UI); err != nil {
		return "", fmt.Errorf("oidc.InitiateLogin: persist flow state: %w", err)
	}

	return authURL, nil
}

// HandleCallback processes the OAuth2 authorization code callback.
// state must equal the flowID. Returns the issued session on success.
func (e *Engine) HandleCallback(ctx context.Context, tenantID uuid.UUID, state, code string) (*CallbackResult, error) {
	flowID, err := uuid.Parse(state)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: invalid state %q: %w", state, err)
	}

	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: %w", err)
	}
	if f.State != flow.StatePending {
		return nil, fmt.Errorf("oidc.HandleCallback: flow is %s", f.State)
	}
	if f.UI.Internal == nil || f.UI.Internal.OIDCProviderID == "" {
		return nil, fmt.Errorf("oidc.HandleCallback: no OIDC state in flow")
	}

	providerID, err := uuid.Parse(f.UI.Internal.OIDCProviderID)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: invalid provider_id in flow: %w", err)
	}
	nonce := f.UI.Internal.OIDCNonce
	codeVerifier := f.UI.Internal.OIDCCodeVerifier

	p, err := e.providers.Get(ctx, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: load provider: %w", err)
	}

	var cfg sso.OIDCConfig
	if err := json.Unmarshal(p.Config, &cfg); err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: parse provider config: %w", err)
	}

	oidcProvider, err := e.getOIDCProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: load OIDC provider: %w", err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}
	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Scopes:       scopes,
		Endpoint:     oidcProvider.Endpoint(),
	}

	token, err := oauth2Cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("oidc.HandleCallback: no id_token in token response")
	}

	verifier := oidcProvider.Verifier(&gooidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: verify id_token: %w", err)
	}

	if idToken.Nonce != nonce {
		return nil, fmt.Errorf("oidc.HandleCallback: nonce mismatch")
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: extract claims: %w", err)
	}

	// Credential identifier scoped to this provider to avoid cross-provider collisions.
	credIdentifier := fmt.Sprintf("%s:%s", providerID, claims.Sub)

	// Look up existing OIDC credential.
	existingCred, lookupErr := e.identities.GetByIdentifier(ctx, tenantID, "oidc", credIdentifier)

	var identityID uuid.UUID
	isNew := false

	if lookupErr == nil {
		// Existing user — verify identity is active.
		ident, idErr := e.identities.GetIdentity(ctx, tenantID, existingCred.IdentityID)
		if idErr != nil {
			return nil, fmt.Errorf("oidc.HandleCallback: load identity: %w", idErr)
		}
		if ident.State != identity.StateActive {
			return nil, fmt.Errorf("oidc.HandleCallback: identity is %s", ident.State)
		}
		identityID = existingCred.IdentityID
	} else if errors.Is(lookupErr, identity.ErrNotFound) {
		// JIT provisioning — create identity + credential.
		sch, schErr := e.schemas.EnsureDefault(ctx, tenantID)
		if schErr != nil {
			return nil, fmt.Errorf("oidc.HandleCallback: ensure schema: %w", schErr)
		}

		traits, _ := json.Marshal(map[string]any{
			"email": claims.Email,
			"name":  claims.Name,
		})
		ident, idErr := e.identities.CreateIdentity(ctx, tenantID, sch.ID, traits, identity.StateActive)
		if idErr != nil {
			return nil, fmt.Errorf("oidc.HandleCallback: create identity: %w", idErr)
		}

		credConfig, _ := json.Marshal(map[string]any{
			"provider_id":   providerID.String(),
			"provider_type": p.Provider,
			"subject":       claims.Sub,
			"email":         claims.Email,
		})
		if _, credErr := e.identities.CreateCredential(ctx, tenantID, ident.ID, "oidc",
			[]string{credIdentifier}, credConfig); credErr != nil {
			return nil, fmt.Errorf("oidc.HandleCallback: create credential: %w", credErr)
		}

		identityID = ident.ID
		isNew = true
	} else {
		return nil, fmt.Errorf("oidc.HandleCallback: credential lookup: %w", lookupErr)
	}

	pol, err := e.policies.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: load policy: %w", err)
	}
	sessionTTL := parseSessionTTL(pol)

	sess, err := e.sessions.Create(ctx, tenantID, identityID, "aal1", []string{"oidc"}, sessionTTL)
	if err != nil {
		return nil, fmt.Errorf("oidc.HandleCallback: create session: %w", err)
	}

	f.UI.Internal = &flow.UIInternal{Phase: "complete", CompletedAAL: "aal1", CompletedAMR: []string{"oidc"}}
	_ = e.flows.Update(ctx, tenantID, flowID, flow.StateSuccess, &identityID, f.UI)

	return &CallbackResult{
		Session:    sess,
		IdentityID: identityID,
		IsNew:      isNew,
	}, nil
}

// ---- helpers ----------------------------------------------------------------

func (e *Engine) getOIDCProvider(ctx context.Context, issuerURL string) (*gooidc.Provider, error) {
	e.cacheMu.RLock()
	if p, ok := e.providerCache[issuerURL]; ok {
		e.cacheMu.RUnlock()
		return p, nil
	}
	e.cacheMu.RUnlock()

	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	// Double-check after acquiring write lock.
	if p, ok := e.providerCache[issuerURL]; ok {
		return p, nil
	}

	p, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	e.providerCache[issuerURL] = p
	return p, nil
}

func randomBase64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func parseSessionTTL(pol *policy.FlowPolicy) time.Duration {
	d, err := time.ParseDuration(pol.Session.TTL)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
}
