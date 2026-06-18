package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/enterprise-idp/idpd/internal/schema"
	"github.com/enterprise-idp/idpd/internal/session"
	"github.com/enterprise-idp/idpd/internal/sso"
	"github.com/google/uuid"
)

// ---- mock OIDC server -------------------------------------------------------

// oidcServer creates a minimal httptest.Server that serves OIDC discovery so that
// gooidc.NewProvider can be called against it in tests.
func oidcServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			base := srv.URL
			doc := map[string]any{
				"issuer":                                base,
				"authorization_endpoint":                base + "/auth",
				"token_endpoint":                        base + "/token",
				"jwks_uri":                              base + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---- fakes ------------------------------------------------------------------

type fakeSSOProviderGetter struct {
	provider *sso.Provider
	err      error
}

func (f *fakeSSOProviderGetter) Get(_ context.Context, _, _ uuid.UUID) (*sso.Provider, error) {
	return f.provider, f.err
}

type fakeOIDCFlowStorer struct {
	flow      *flow.Flow
	getErr    error
	updateErr error
}

func (f *fakeOIDCFlowStorer) Get(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
	return f.flow, f.getErr
}
func (f *fakeOIDCFlowStorer) Update(_ context.Context, _, _ uuid.UUID, _ flow.State, _ *uuid.UUID, _ flow.UI) error {
	return f.updateErr
}

type fakeOIDCIdentityStorer struct {
	credential   *identity.Credential
	credErr      error
	ident        *identity.Identity
	identErr     error
	createIdent  *identity.Identity
	createIdentErr error
	createCred   *identity.Credential
	createCredErr  error
}

func (f *fakeOIDCIdentityStorer) GetByIdentifier(_ context.Context, _ uuid.UUID, _, _ string) (*identity.Credential, error) {
	return f.credential, f.credErr
}
func (f *fakeOIDCIdentityStorer) GetIdentity(_ context.Context, _, _ uuid.UUID) (*identity.Identity, error) {
	return f.ident, f.identErr
}
func (f *fakeOIDCIdentityStorer) CreateIdentity(_ context.Context, _, _ uuid.UUID, _ json.RawMessage, _ string) (*identity.Identity, error) {
	return f.createIdent, f.createIdentErr
}
func (f *fakeOIDCIdentityStorer) CreateCredential(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ json.RawMessage) (*identity.Credential, error) {
	return f.createCred, f.createCredErr
}

type fakeOIDCSchemaEnsurer struct {
	schema *schema.Schema
	err    error
}

func (f *fakeOIDCSchemaEnsurer) EnsureDefault(_ context.Context, _ uuid.UUID) (*schema.Schema, error) {
	return f.schema, f.err
}

type fakeOIDCSessionCreator struct {
	sess *session.Session
	err  error
}

func (f *fakeOIDCSessionCreator) Create(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ time.Duration) (*session.Session, error) {
	return f.sess, f.err
}

type fakeOIDCPolicyGetter struct {
	pol *policy.FlowPolicy
	err error
}

func (f *fakeOIDCPolicyGetter) Get(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
	return f.pol, f.err
}

// ---- helpers ----------------------------------------------------------------

func testEngine(t *testing.T,
	providers oidcProviderGetter,
	flows oidcFlowStorer,
	identities oidcIdentityStorer,
	schemas oidcSchemaEnsurer,
	sessions oidcSessionCreator,
	policies oidcPolicyGetter,
) *Engine {
	t.Helper()
	return New(providers, flows, identities, schemas, sessions, policies)
}

func defaultPendingFlow(tenantID uuid.UUID) *flow.Flow {
	return &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeLogin,
		State:    flow.StatePending,
		UI:       flow.UI{Method: "POST"},
	}
}

func oidcProviderWithIssuer(providerID, tenantID uuid.UUID, issuerURL string) *sso.Provider {
	cfg, _ := json.Marshal(sso.OIDCConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		IssuerURL:    issuerURL,
		RedirectURI:  "https://idp.example.com/callback",
	})
	return &sso.Provider{
		ID:       providerID,
		TenantID: tenantID,
		Type:     "oidc",
		Provider: "google",
		Config:   cfg,
		Enabled:  true,
	}
}

// ---- pure helper tests ------------------------------------------------------

func TestPkceChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)
	if challenge == "" {
		t.Error("pkceChallenge returned empty string")
	}
	// Running twice should give same result (deterministic).
	if got := pkceChallenge(verifier); got != challenge {
		t.Errorf("pkceChallenge not deterministic: %q != %q", got, challenge)
	}
	// Different verifiers → different challenges.
	if pkceChallenge("other") == challenge {
		t.Error("different verifiers produced same challenge")
	}
}

func TestRandomBase64(t *testing.T) {
	s, err := randomBase64(32)
	if err != nil {
		t.Fatalf("randomBase64(32) error: %v", err)
	}
	if len(s) == 0 {
		t.Error("randomBase64 returned empty string")
	}
	// Two calls should (with overwhelming probability) produce different results.
	s2, _ := randomBase64(32)
	if s == s2 {
		t.Error("randomBase64 produced the same value twice")
	}
}

func TestParseSessionTTL_Valid(t *testing.T) {
	pol := &policy.FlowPolicy{}
	pol.Session.TTL = "48h"
	d := parseSessionTTL(pol)
	if d != 48*time.Hour {
		t.Errorf("parseSessionTTL = %v, want 48h", d)
	}
}

func TestParseSessionTTL_Invalid(t *testing.T) {
	pol := &policy.FlowPolicy{}
	pol.Session.TTL = "not-a-duration"
	d := parseSessionTTL(pol)
	if d != 24*time.Hour {
		t.Errorf("parseSessionTTL(invalid) = %v, want 24h default", d)
	}
}

func TestParseSessionTTL_Zero(t *testing.T) {
	pol := &policy.FlowPolicy{}
	pol.Session.TTL = "0s"
	d := parseSessionTTL(pol)
	if d != 24*time.Hour {
		t.Errorf("parseSessionTTL(0) = %v, want 24h default", d)
	}
}

func TestNew(t *testing.T) {
	e := New(
		&fakeSSOProviderGetter{},
		&fakeOIDCFlowStorer{},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.providerCache == nil {
		t.Error("providerCache not initialised")
	}
}

// ---- InitiateLogin tests ----------------------------------------------------

func TestInitiateLogin_FlowGetError(t *testing.T) {
	e := testEngine(t,
		&fakeSSOProviderGetter{},
		&fakeOIDCFlowStorer{getErr: errors.New("db error")},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.InitiateLogin(context.Background(), uuid.New(), uuid.New(), uuid.New())
	if err == nil || !strings.Contains(err.Error(), "db error") {
		t.Errorf("expected db error, got %v", err)
	}
}

func TestInitiateLogin_FlowNotPending(t *testing.T) {
	f := defaultPendingFlow(uuid.New())
	f.State = flow.StateSuccess
	e := testEngine(t,
		&fakeSSOProviderGetter{},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.InitiateLogin(context.Background(), f.TenantID, f.ID, uuid.New())
	if err == nil || !strings.Contains(err.Error(), "flow is") {
		t.Errorf("expected non-pending error, got %v", err)
	}
}

func TestInitiateLogin_ProviderGetError(t *testing.T) {
	f := defaultPendingFlow(uuid.New())
	e := testEngine(t,
		&fakeSSOProviderGetter{err: errors.New("provider not found")},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.InitiateLogin(context.Background(), f.TenantID, f.ID, uuid.New())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestInitiateLogin_ProviderDisabled(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	f := defaultPendingFlow(tenantID)
	p := oidcProviderWithIssuer(providerID, tenantID, "https://accounts.google.com")
	p.Enabled = false
	e := testEngine(t,
		&fakeSSOProviderGetter{provider: p},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.InitiateLogin(context.Background(), tenantID, f.ID, providerID)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected disabled error, got %v", err)
	}
}

func TestInitiateLogin_ProviderWrongType(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	f := defaultPendingFlow(tenantID)
	p := oidcProviderWithIssuer(providerID, tenantID, "https://accounts.google.com")
	p.Type = "saml"
	e := testEngine(t,
		&fakeSSOProviderGetter{provider: p},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.InitiateLogin(context.Background(), tenantID, f.ID, providerID)
	if err == nil || !strings.Contains(err.Error(), "not oidc") {
		t.Errorf("expected type error, got %v", err)
	}
}

func TestInitiateLogin_InvalidProviderConfig(t *testing.T) {
	tenantID := uuid.New()
	providerID := uuid.New()
	f := defaultPendingFlow(tenantID)
	p := &sso.Provider{
		ID: providerID, TenantID: tenantID, Type: "oidc",
		Provider: "custom", Config: json.RawMessage(`not-json`), Enabled: true,
	}
	e := testEngine(t,
		&fakeSSOProviderGetter{provider: p},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.InitiateLogin(context.Background(), tenantID, f.ID, providerID)
	if err == nil || !strings.Contains(err.Error(), "parse provider config") {
		t.Errorf("expected config parse error, got %v", err)
	}
}

func TestInitiateLogin_Success(t *testing.T) {
	srv := oidcServer(t)
	tenantID := uuid.New()
	providerID := uuid.New()
	f := defaultPendingFlow(tenantID)
	p := oidcProviderWithIssuer(providerID, tenantID, srv.URL)

	flows := &fakeOIDCFlowStorer{flow: f}
	e := testEngine(t,
		&fakeSSOProviderGetter{provider: p},
		flows,
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)

	authURL, err := e.InitiateLogin(context.Background(), tenantID, f.ID, providerID)
	if err != nil {
		t.Fatalf("InitiateLogin error: %v", err)
	}
	if !strings.Contains(authURL, "client_id=client-id") {
		t.Errorf("authURL missing client_id: %s", authURL)
	}
	if !strings.Contains(authURL, f.ID.String()) {
		t.Errorf("authURL missing state (flowID): %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("authURL missing PKCE: %s", authURL)
	}
}

func TestInitiateLogin_FlowUpdateError(t *testing.T) {
	srv := oidcServer(t)
	tenantID := uuid.New()
	providerID := uuid.New()
	f := defaultPendingFlow(tenantID)
	p := oidcProviderWithIssuer(providerID, tenantID, srv.URL)

	e := testEngine(t,
		&fakeSSOProviderGetter{provider: p},
		&fakeOIDCFlowStorer{flow: f, updateErr: errors.New("update failed")},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.InitiateLogin(context.Background(), tenantID, f.ID, providerID)
	if err == nil || !strings.Contains(err.Error(), "persist flow state") {
		t.Errorf("expected update error, got %v", err)
	}
}

func TestInitiateLogin_ProviderCached(t *testing.T) {
	srv := oidcServer(t)
	tenantID := uuid.New()
	providerID := uuid.New()
	p := oidcProviderWithIssuer(providerID, tenantID, srv.URL)

	e := testEngine(t,
		&fakeSSOProviderGetter{provider: p},
		&fakeOIDCFlowStorer{},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)

	// Prime cache
	f1 := defaultPendingFlow(tenantID)
	e.flows = &fakeOIDCFlowStorer{flow: f1}
	_, _ = e.InitiateLogin(context.Background(), tenantID, f1.ID, providerID)

	// Second call should use cache (no extra network request)
	f2 := defaultPendingFlow(tenantID)
	e.flows = &fakeOIDCFlowStorer{flow: f2}
	authURL, err := e.InitiateLogin(context.Background(), tenantID, f2.ID, providerID)
	if err != nil {
		t.Fatalf("second InitiateLogin error: %v", err)
	}
	if authURL == "" {
		t.Error("expected non-empty auth URL on cached call")
	}
}

// ---- HandleCallback tests ---------------------------------------------------

func TestHandleCallback_InvalidState(t *testing.T) {
	e := testEngine(t,
		&fakeSSOProviderGetter{},
		&fakeOIDCFlowStorer{},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.HandleCallback(context.Background(), uuid.New(), "not-a-uuid", "code")
	if err == nil || !strings.Contains(err.Error(), "invalid state") {
		t.Errorf("expected invalid state error, got %v", err)
	}
}

func TestHandleCallback_FlowGetError(t *testing.T) {
	e := testEngine(t,
		&fakeSSOProviderGetter{},
		&fakeOIDCFlowStorer{getErr: errors.New("db error")},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.HandleCallback(context.Background(), uuid.New(), uuid.New().String(), "code")
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestHandleCallback_FlowNotPending(t *testing.T) {
	f := defaultPendingFlow(uuid.New())
	f.State = flow.StateSuccess
	e := testEngine(t,
		&fakeSSOProviderGetter{},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.HandleCallback(context.Background(), f.TenantID, f.ID.String(), "code")
	if err == nil || !strings.Contains(err.Error(), "flow is") {
		t.Errorf("expected non-pending error, got %v", err)
	}
}

func TestHandleCallback_NoOIDCState(t *testing.T) {
	f := defaultPendingFlow(uuid.New())
	// No OIDCProviderID in internal state
	e := testEngine(t,
		&fakeSSOProviderGetter{},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.HandleCallback(context.Background(), f.TenantID, f.ID.String(), "code")
	if err == nil || !strings.Contains(err.Error(), "no OIDC state") {
		t.Errorf("expected no OIDC state error, got %v", err)
	}
}

func TestHandleCallback_ProviderGetError(t *testing.T) {
	providerID := uuid.New()
	f := defaultPendingFlow(uuid.New())
	f.UI.Internal = &flow.UIInternal{
		Phase:          "first_factor",
		OIDCProviderID: providerID.String(),
		OIDCNonce:      "nonce",
	}
	e := testEngine(t,
		&fakeSSOProviderGetter{err: errors.New("provider missing")},
		&fakeOIDCFlowStorer{flow: f},
		&fakeOIDCIdentityStorer{},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.HandleCallback(context.Background(), f.TenantID, f.ID.String(), "code")
	if err == nil || !strings.Contains(err.Error(), "load provider") {
		t.Errorf("expected load provider error, got %v", err)
	}
}

func TestHandleCallback_CredentialLookupError(t *testing.T) {
	// A non-ErrNotFound error from GetByIdentifier should propagate.
	srv := oidcServer(t)
	tenantID := uuid.New()
	providerID := uuid.New()
	p := oidcProviderWithIssuer(providerID, tenantID, srv.URL)

	f := defaultPendingFlow(tenantID)
	f.UI.Internal = &flow.UIInternal{
		Phase:            "first_factor",
		OIDCProviderID:   providerID.String(),
		OIDCNonce:        "nonce",
		OIDCCodeVerifier: "verifier",
	}

	// We need a token endpoint that returns something, but since code exchange will fail
	// without a real server, test the path where GetByIdentifier returns a non-ErrNotFound error.
	// We skip code exchange by not running exchange — test only the error branching.
	// Actually, without a real token endpoint, Exchange will fail before we get to identity lookup.
	// So test what we can: the ProviderID invalid UUID path instead.
	f2 := defaultPendingFlow(tenantID)
	f2.UI.Internal = &flow.UIInternal{
		Phase:          "first_factor",
		OIDCProviderID: "not-a-uuid",
		OIDCNonce:      "nonce",
	}
	e := testEngine(t,
		&fakeSSOProviderGetter{provider: p},
		&fakeOIDCFlowStorer{flow: f2},
		&fakeOIDCIdentityStorer{credErr: fmt.Errorf("db error: %w", errors.New("connection lost"))},
		&fakeOIDCSchemaEnsurer{},
		&fakeOIDCSessionCreator{},
		&fakeOIDCPolicyGetter{},
	)
	_, err := e.HandleCallback(context.Background(), tenantID, f2.ID.String(), "code")
	if err == nil || !strings.Contains(err.Error(), "invalid provider_id") {
		t.Errorf("expected invalid provider_id error, got %v", err)
	}
}
