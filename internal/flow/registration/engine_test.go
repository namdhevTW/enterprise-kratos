package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	authnregistry "github.com/enterprise-idp/idpd/internal/authenticator/registry"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/enterprise-idp/idpd/internal/schema"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Stub implementations
// ---------------------------------------------------------------------------

// stubFlowStorer is a controllable in-memory implementation of flowStorer.
type stubFlowStorer struct {
	createFn func(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error)
	getFn    func(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	updateFn func(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error
}

func (s *stubFlowStorer) Create(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error) {
	if s.createFn != nil {
		return s.createFn(ctx, tenantID, flowType, ui, expiresAt)
	}
	f := &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flowType,
		State:    flow.StatePending,
		UI:       ui,
		ExpiresAt: expiresAt,
	}
	return f, nil
}

func (s *stubFlowStorer) Get(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	if s.getFn != nil {
		return s.getFn(ctx, tenantID, flowID)
	}
	return nil, fmt.Errorf("stubFlowStorer.Get: no stub configured")
}

func (s *stubFlowStorer) Update(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error {
	if s.updateFn != nil {
		return s.updateFn(ctx, tenantID, flowID, state, identityID, ui)
	}
	return nil
}

// stubPolicyGetter is a controllable implementation of policyGetter.
type stubPolicyGetter struct {
	getFn func(ctx context.Context, tenantID uuid.UUID) (*policy.FlowPolicy, error)
}

func (s *stubPolicyGetter) Get(ctx context.Context, tenantID uuid.UUID) (*policy.FlowPolicy, error) {
	if s.getFn != nil {
		return s.getFn(ctx, tenantID)
	}
	return policy.Default(), nil
}

// stubIdentityStorer is a controllable implementation of identityStorer.
type stubIdentityStorer struct {
	getByIdentifierFn  func(ctx context.Context, tenantID uuid.UUID, credType, identifier string) (*identity.Credential, error)
	createIdentityFn   func(ctx context.Context, tenantID, schemaID uuid.UUID, traits json.RawMessage, state string) (*identity.Identity, error)
	createCredentialFn func(ctx context.Context, tenantID, identityID uuid.UUID, credType string, identifiers []string, config json.RawMessage) (*identity.Credential, error)
}

func (s *stubIdentityStorer) GetByIdentifier(ctx context.Context, tenantID uuid.UUID, credType, identifier string) (*identity.Credential, error) {
	if s.getByIdentifierFn != nil {
		return s.getByIdentifierFn(ctx, tenantID, credType, identifier)
	}
	// Default: not found (expected happy path for registration)
	return nil, fmt.Errorf("not found: %w", identity.ErrNotFound)
}

func (s *stubIdentityStorer) CreateIdentity(ctx context.Context, tenantID, schemaID uuid.UUID, traits json.RawMessage, state string) (*identity.Identity, error) {
	if s.createIdentityFn != nil {
		return s.createIdentityFn(ctx, tenantID, schemaID, traits, state)
	}
	return &identity.Identity{
		ID:       uuid.New(),
		TenantID: tenantID,
		SchemaID: schemaID,
		Traits:   traits,
		State:    state,
	}, nil
}

func (s *stubIdentityStorer) CreateCredential(ctx context.Context, tenantID, identityID uuid.UUID, credType string, identifiers []string, config json.RawMessage) (*identity.Credential, error) {
	if s.createCredentialFn != nil {
		return s.createCredentialFn(ctx, tenantID, identityID, credType, identifiers, config)
	}
	return &identity.Credential{
		ID:          uuid.New(),
		TenantID:    tenantID,
		IdentityID:  identityID,
		Type:        credType,
		Identifiers: identifiers,
		Config:      config,
	}, nil
}

// stubSchemaEnsurer is a controllable implementation of schemaEnsurer.
type stubSchemaEnsurer struct {
	ensureDefaultFn func(ctx context.Context, tenantID uuid.UUID) (*schema.Schema, error)
}

func (s *stubSchemaEnsurer) EnsureDefault(ctx context.Context, tenantID uuid.UUID) (*schema.Schema, error) {
	if s.ensureDefaultFn != nil {
		return s.ensureDefaultFn(ctx, tenantID)
	}
	return &schema.Schema{
		ID:       uuid.New(),
		TenantID: tenantID,
		Version:  1,
		IsActive: true,
	}, nil
}

// stubAuthnReg is a controllable implementation of authnReg.
type stubAuthnReg struct {
	getFn func(id string) (authenticator.Authenticator, error)
}

func (s *stubAuthnReg) Get(id string) (authenticator.Authenticator, error) {
	if s.getFn != nil {
		return s.getFn(id)
	}
	return nil, fmt.Errorf("registry.Get %q: %w", id, authnregistry.ErrNotFound)
}

// stubVerificationIniter is a controllable implementation of verificationIniter.
type stubVerificationIniter struct {
	initFlowFn func(ctx context.Context, tenantID, identityID uuid.UUID) (*flow.Flow, string, error)
}

func (s *stubVerificationIniter) InitFlow(ctx context.Context, tenantID, identityID uuid.UUID) (*flow.Flow, string, error) {
	if s.initFlowFn != nil {
		return s.initFlowFn(ctx, tenantID, identityID)
	}
	vf := &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeVerification,
		State:    flow.StatePending,
	}
	return vf, "plaintext-token-abc", nil
}

// stubAuthenticator is a minimal implementation of authenticator.Authenticator.
type stubAuthenticator struct {
	id          string
	authnType   authenticator.Type
	startFlowFn func(ctx context.Context, r *authenticator.StartFlowRequest) (*authenticator.FlowState, error)
	enrollFn    func(ctx context.Context, r *authenticator.EnrollRequest) (*authenticator.EnrollResult, error)
}

func (a *stubAuthenticator) ID() string   { return a.id }
func (a *stubAuthenticator) Type() authenticator.Type { return a.authnType }

func (a *stubAuthenticator) StartFlow(ctx context.Context, r *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
	if a.startFlowFn != nil {
		return a.startFlowFn(ctx, r)
	}
	return &authenticator.FlowState{Nodes: []authenticator.UINode{}}, nil
}

func (a *stubAuthenticator) CompleteFlow(ctx context.Context, r *authenticator.CompleteFlowRequest) (*authenticator.AuthResult, error) {
	return nil, errors.New("stubAuthenticator: CompleteFlow not implemented")
}

func (a *stubAuthenticator) Enroll(ctx context.Context, r *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
	if a.enrollFn != nil {
		return a.enrollFn(ctx, r)
	}
	return &authenticator.EnrollResult{
		CredentialType:   "password",
		Identifiers:      nil,
		CredentialConfig: json.RawMessage(`{"hashed_password":"$2a$12$x"}`),
	}, nil
}

func (a *stubAuthenticator) Unenroll(ctx context.Context, r *authenticator.UnenrollRequest) error {
	return errors.New("stubAuthenticator: Unenroll not implemented")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// defaultPasswordAuthn returns a stub authenticator that always succeeds for
// the "password" method.
func defaultPasswordAuthn() *stubAuthenticator {
	return &stubAuthenticator{
		id:        "password",
		authnType: authenticator.FirstFactor,
	}
}

// defaultSubmitValues returns the minimal set of values required for a
// successful SubmitFlow call using the "password" method.
func defaultSubmitValues() map[string]string {
	return map[string]string{
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	}
}

// newDefaultEngine wires up an Engine with all happy-path stubs.
// The caller can override individual fields before calling methods.
func newDefaultEngine(
	flows flowStorer,
	policies policyGetter,
	identities identityStorer,
	schemas schemaEnsurer,
	authn authnReg,
	verif verificationIniter,
) *Engine {
	return New(flows, policies, identities, schemas, authn, verif)
}

// pendingRegistrationFlow returns a *flow.Flow whose state, type, and tenant
// are set correctly for a valid SubmitFlow call.
func pendingRegistrationFlow(tenantID uuid.UUID) *flow.Flow {
	return &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeRegistration,
		State:    flow.StatePending,
		UI: flow.UI{
			Method:   "POST",
			Internal: &flow.UIInternal{Phase: "register"},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
}

// ---------------------------------------------------------------------------
// InitFlow tests
// ---------------------------------------------------------------------------

func TestInitFlow_Success(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			if id == "password" {
				return defaultPasswordAuthn(), nil
			}
			return nil, fmt.Errorf("registry.Get %q: %w", id, authnregistry.ErrNotFound)
		},
	}

	var capturedFlowType flow.Type
	var capturedTenantID uuid.UUID
	flows := &stubFlowStorer{
		createFn: func(ctx context.Context, tid uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error) {
			capturedFlowType = flowType
			capturedTenantID = tid
			return &flow.Flow{
				ID:        uuid.New(),
				TenantID:  tid,
				Type:      flowType,
				State:     flow.StatePending,
				UI:        ui,
				ExpiresAt: expiresAt,
			}, nil
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	f, err := eng.InitFlow(ctx, tenantID)

	if err != nil {
		t.Fatalf("InitFlow returned unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("InitFlow returned nil flow")
	}
	if capturedFlowType != flow.TypeRegistration {
		t.Errorf("expected flow type %q, got %q", flow.TypeRegistration, capturedFlowType)
	}
	if capturedTenantID != tenantID {
		t.Errorf("expected tenantID %s, got %s", tenantID, capturedTenantID)
	}
	if f.State != flow.StatePending {
		t.Errorf("expected state %q, got %q", flow.StatePending, f.State)
	}
	// UI should contain at least the traits.email input node
	hasEmailNode := false
	for _, node := range f.UI.Nodes {
		if node.Attributes.Name == "traits.email" {
			hasEmailNode = true
			break
		}
	}
	if !hasEmailNode {
		t.Error("expected UI to contain a traits.email input node")
	}
}

func TestInitFlow_RegistrationDisabled(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Registration.Enabled = false

	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}

	eng := newDefaultEngine(&stubFlowStorer{}, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	f, err := eng.InitFlow(ctx, tenantID)

	if err == nil {
		t.Fatal("expected error when registration is disabled, got nil")
	}
	if f != nil {
		t.Errorf("expected nil flow when registration is disabled, got %+v", f)
	}
}

func TestInitFlow_PolicyError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	policyErr := errors.New("db connection refused")

	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return nil, policyErr
		},
	}

	eng := newDefaultEngine(&stubFlowStorer{}, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.InitFlow(ctx, tenantID)

	if err == nil {
		t.Fatal("expected error from policy.Get, got nil")
	}
	if !errors.Is(err, policyErr) {
		t.Errorf("expected error to wrap policyErr, got: %v", err)
	}
}

func TestInitFlow_FlowsCreateError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	createErr := errors.New("storage write failed")

	flows := &stubFlowStorer{
		createFn: func(_ context.Context, _ uuid.UUID, _ flow.Type, _ flow.UI, _ time.Time) (*flow.Flow, error) {
			return nil, createErr
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.InitFlow(ctx, tenantID)

	if err == nil {
		t.Fatal("expected error from flows.Create, got nil")
	}
	if !errors.Is(err, createErr) {
		t.Errorf("expected error to wrap createErr, got: %v", err)
	}
}

func TestInitFlow_AuthenticatorStartFlowError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	startErr := errors.New("authenticator start failed")

	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			a := &stubAuthenticator{
				id:        id,
				authnType: authenticator.FirstFactor,
				startFlowFn: func(_ context.Context, _ *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
					return nil, startErr
				},
			}
			return a, nil
		},
	}

	eng := newDefaultEngine(&stubFlowStorer{}, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.InitFlow(ctx, tenantID)

	if err == nil {
		t.Fatal("expected error from authenticator.StartFlow, got nil")
	}
	if !errors.Is(err, startErr) {
		t.Errorf("expected error to wrap startErr, got: %v", err)
	}
}

func TestInitFlow_AuthenticatorNotFoundIsSkipped(t *testing.T) {
	// ErrNotFound from the authenticator registry must be silently skipped,
	// not propagated as an error.
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Login.AllowedFirstFactors = []string{"password", "oidc"} // oidc not registered

	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}

	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			if id == "password" {
				return defaultPasswordAuthn(), nil
			}
			return nil, fmt.Errorf("registry.Get %q: %w", id, authnregistry.ErrNotFound)
		},
	}

	eng := newDefaultEngine(&stubFlowStorer{}, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	f, err := eng.InitFlow(ctx, tenantID)

	if err != nil {
		t.Fatalf("expected nil error when one authenticator is missing, got: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil flow")
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow tests
// ---------------------------------------------------------------------------

func TestSubmitFlow_SuccessNoVerification(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Registration.Enabled = true
	pol.Registration.RequireVerification = false
	pol.Login.AllowedFirstFactors = []string{"password"}
	pol.Session.TTL = "12h"

	existingFlow := pendingRegistrationFlow(tenantID)

	flows := &stubFlowStorer{
		getFn: func(_ context.Context, tid, fid uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}

	eng := newDefaultEngine(flows, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	result, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err != nil {
		t.Fatalf("SubmitFlow returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("SubmitFlow returned nil result")
	}
	if !result.Completed {
		t.Error("expected result.Completed = true when verification is not required")
	}
	if result.NeedsVerification {
		t.Error("expected result.NeedsVerification = false")
	}
	if result.IdentityID == uuid.Nil {
		t.Error("expected non-nil IdentityID")
	}
	if result.SessionTTL != 12*time.Hour {
		t.Errorf("expected SessionTTL = 12h, got %v", result.SessionTTL)
	}
}

func TestSubmitFlow_SuccessWithVerification(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Registration.Enabled = true
	pol.Registration.RequireVerification = true
	pol.Login.AllowedFirstFactors = []string{"password"}

	existingFlow := pendingRegistrationFlow(tenantID)
	verifFlowID := uuid.New()
	const expectedToken = "verification-token-xyz"

	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}

	var capturedIdentityID uuid.UUID
	verif := &stubVerificationIniter{
		initFlowFn: func(_ context.Context, tid, iid uuid.UUID) (*flow.Flow, string, error) {
			capturedIdentityID = iid
			return &flow.Flow{ID: verifFlowID, TenantID: tid, Type: flow.TypeVerification, State: flow.StatePending}, expectedToken, nil
		},
	}

	eng := newDefaultEngine(flows, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, authnStub, verif)
	result, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err != nil {
		t.Fatalf("SubmitFlow returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("SubmitFlow returned nil result")
	}
	if result.Completed {
		t.Error("expected result.Completed = false when verification is required")
	}
	if !result.NeedsVerification {
		t.Error("expected result.NeedsVerification = true")
	}
	if result.VerificationFlowID != verifFlowID {
		t.Errorf("expected VerificationFlowID %s, got %s", verifFlowID, result.VerificationFlowID)
	}
	if result.VerificationToken != expectedToken {
		t.Errorf("expected VerificationToken %q, got %q", expectedToken, result.VerificationToken)
	}
	if capturedIdentityID == uuid.Nil {
		t.Error("expected verif.InitFlow to receive a non-nil identityID")
	}
}

func TestSubmitFlow_RegistrationDisabled(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Registration.Enabled = false

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}

	eng := newDefaultEngine(flows, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error when registration is disabled, got nil")
	}
}

func TestSubmitFlow_MethodNotAllowed(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Registration.Enabled = true
	pol.Login.AllowedFirstFactors = []string{"password"}

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}

	eng := newDefaultEngine(flows, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "totp", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error when method is not allowed, got nil")
	}
}

func TestSubmitFlow_FlowNotPending(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	for _, state := range []flow.State{flow.StateSuccess, flow.StateFailed, flow.StateExpired} {
		state := state
		t.Run(string(state), func(t *testing.T) {
			f := pendingRegistrationFlow(tenantID)
			f.State = state

			flows := &stubFlowStorer{
				getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
					return f, nil
				},
			}

			eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
			_, err := eng.SubmitFlow(ctx, tenantID, f.ID, "password", defaultSubmitValues())

			if err == nil {
				t.Fatalf("expected error for flow state %q, got nil", state)
			}
		})
	}
}

func TestSubmitFlow_WrongFlowType(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	f := &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeLogin, // wrong type
		State:    flow.StatePending,
		UI:       flow.UI{Internal: &flow.UIInternal{Phase: "first_factor"}},
	}

	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, f.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error for wrong flow type, got nil")
	}
}

func TestSubmitFlow_FlowGetError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	getErr := errors.New("flow not found in db")

	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, getErr
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, uuid.New(), "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error from flows.Get, got nil")
	}
	if !errors.Is(err, getErr) {
		t.Errorf("expected error to wrap getErr, got: %v", err)
	}
}

func TestSubmitFlow_MissingIdentifier(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}

	values := map[string]string{
		"password": "S3cret!",
		// no traits.email or identifier
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", values)

	if err == nil {
		t.Fatal("expected error for missing identifier, got nil")
	}
}

func TestSubmitFlow_DuplicateIdentifier(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}

	// GetByIdentifier returns a credential (no error) → duplicate
	identities := &stubIdentityStorer{
		getByIdentifierFn: func(_ context.Context, _ uuid.UUID, _, _ string) (*identity.Credential, error) {
			return &identity.Credential{
				ID:         uuid.New(),
				IdentityID: uuid.New(),
				Type:       "password",
			}, nil
		},
	}

	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error for duplicate identifier, got nil")
	}
}

func TestSubmitFlow_DuplicateCheckUnexpectedError(t *testing.T) {
	// GetByIdentifier returns an error that is NOT identity.ErrNotFound.
	// This must propagate as an error, not be silently swallowed.
	tenantID := uuid.New()
	ctx := context.Background()
	dbErr := errors.New("unexpected db error")

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	identities := &stubIdentityStorer{
		getByIdentifierFn: func(_ context.Context, _ uuid.UUID, _, _ string) (*identity.Credential, error) {
			return nil, dbErr
		},
	}

	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error from unexpected GetByIdentifier error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected error to wrap dbErr, got: %v", err)
	}
}

func TestSubmitFlow_EnrollError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	enrollErr := errors.New("bcrypt internal error")

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return &stubAuthenticator{
				id:        id,
				authnType: authenticator.FirstFactor,
				enrollFn: func(_ context.Context, _ *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
					return nil, enrollErr
				},
			}, nil
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error from enroll failure, got nil")
	}
	if !errors.Is(err, enrollErr) {
		t.Errorf("expected error to wrap enrollErr, got: %v", err)
	}
}

func TestSubmitFlow_SchemaError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	schemaErr := errors.New("schema store unavailable")

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}
	schemas := &stubSchemaEnsurer{
		ensureDefaultFn: func(_ context.Context, _ uuid.UUID) (*schema.Schema, error) {
			return nil, schemaErr
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, schemas, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error from schema failure, got nil")
	}
	if !errors.Is(err, schemaErr) {
		t.Errorf("expected error to wrap schemaErr, got: %v", err)
	}
}

func TestSubmitFlow_CreateIdentityError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	createIdentErr := errors.New("identity insert failed")

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}
	identities := &stubIdentityStorer{
		createIdentityFn: func(_ context.Context, _, _ uuid.UUID, _ json.RawMessage, _ string) (*identity.Identity, error) {
			return nil, createIdentErr
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error from CreateIdentity failure, got nil")
	}
	if !errors.Is(err, createIdentErr) {
		t.Errorf("expected error to wrap createIdentErr, got: %v", err)
	}
}

func TestSubmitFlow_CreateCredentialError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	createCredErr := errors.New("credential insert failed")

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}
	identities := &stubIdentityStorer{
		createCredentialFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ json.RawMessage) (*identity.Credential, error) {
			return nil, createCredErr
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error from CreateCredential failure, got nil")
	}
	if !errors.Is(err, createCredErr) {
		t.Errorf("expected error to wrap createCredErr, got: %v", err)
	}
}

func TestSubmitFlow_VerificationInitError(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()
	verifErr := errors.New("verification store failed")

	pol := policy.Default()
	pol.Registration.Enabled = true
	pol.Registration.RequireVerification = true
	pol.Login.AllowedFirstFactors = []string{"password"}

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}
	verif := &stubVerificationIniter{
		initFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, string, error) {
			return nil, "", verifErr
		},
	}

	eng := newDefaultEngine(flows, policies, &stubIdentityStorer{}, &stubSchemaEnsurer{}, authnStub, verif)
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err == nil {
		t.Fatal("expected error from verif.InitFlow failure, got nil")
	}
	if !errors.Is(err, verifErr) {
		t.Errorf("expected error to wrap verifErr, got: %v", err)
	}
}

func TestSubmitFlow_IdentityStateActivWhenNoVerification(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Registration.Enabled = true
	pol.Registration.RequireVerification = false
	pol.Login.AllowedFirstFactors = []string{"password"}

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}

	var capturedState string
	identities := &stubIdentityStorer{
		createIdentityFn: func(_ context.Context, _, _ uuid.UUID, _ json.RawMessage, state string) (*identity.Identity, error) {
			capturedState = state
			return &identity.Identity{ID: uuid.New(), TenantID: tenantID, State: state}, nil
		},
	}

	eng := newDefaultEngine(flows, policies, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err != nil {
		t.Fatalf("SubmitFlow returned unexpected error: %v", err)
	}
	if capturedState != identity.StateActive {
		t.Errorf("expected identity state %q, got %q", identity.StateActive, capturedState)
	}
}

func TestSubmitFlow_IdentityStatePendingWhenVerificationRequired(t *testing.T) {
	tenantID := uuid.New()
	ctx := context.Background()

	pol := policy.Default()
	pol.Registration.Enabled = true
	pol.Registration.RequireVerification = true
	pol.Login.AllowedFirstFactors = []string{"password"}

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil
		},
	}

	var capturedState string
	identities := &stubIdentityStorer{
		createIdentityFn: func(_ context.Context, _, _ uuid.UUID, _ json.RawMessage, state string) (*identity.Identity, error) {
			capturedState = state
			return &identity.Identity{ID: uuid.New(), TenantID: tenantID, State: state}, nil
		},
	}

	eng := newDefaultEngine(flows, policies, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err != nil {
		t.Fatalf("SubmitFlow returned unexpected error: %v", err)
	}
	if capturedState != identity.StatePendingVerification {
		t.Errorf("expected identity state %q, got %q", identity.StatePendingVerification, capturedState)
	}
}

func TestSubmitFlow_EnrollResultIdentifiersUsedWhenPresent(t *testing.T) {
	// When Enroll returns non-empty Identifiers, those must be stored as the
	// credential identifiers, not the email identifier.
	tenantID := uuid.New()
	ctx := context.Background()

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}

	const oidcSubject = "sub-12345"
	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return &stubAuthenticator{
				id:        id,
				authnType: authenticator.FirstFactor,
				enrollFn: func(_ context.Context, _ *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
					return &authenticator.EnrollResult{
						CredentialType:   id,
						Identifiers:      []string{oidcSubject},
						CredentialConfig: json.RawMessage(`{}`),
					}, nil
				},
			}, nil
		},
	}

	var capturedIdentifiers []string
	identities := &stubIdentityStorer{
		createCredentialFn: func(_ context.Context, _, _ uuid.UUID, _ string, ids []string, _ json.RawMessage) (*identity.Credential, error) {
			capturedIdentifiers = ids
			return &identity.Credential{ID: uuid.New()}, nil
		},
	}

	pol := policy.Default()
	pol.Login.AllowedFirstFactors = []string{"password"}
	policies := &stubPolicyGetter{
		getFn: func(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
			return pol, nil
		},
	}

	eng := newDefaultEngine(flows, policies, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", defaultSubmitValues())

	if err != nil {
		t.Fatalf("SubmitFlow returned unexpected error: %v", err)
	}
	if len(capturedIdentifiers) != 1 || capturedIdentifiers[0] != oidcSubject {
		t.Errorf("expected identifiers [%q], got %v", oidcSubject, capturedIdentifiers)
	}
}

func TestSubmitFlow_EnrollResultEmptyIdentifiersFallsBackToEmail(t *testing.T) {
	// When Enroll returns nil/empty Identifiers, the email from the form must
	// be used as the sole credential identifier.
	tenantID := uuid.New()
	ctx := context.Background()
	const email = "user@example.com"

	existingFlow := pendingRegistrationFlow(tenantID)
	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return existingFlow, nil
		},
	}

	authnStub := &stubAuthnReg{
		getFn: func(id string) (authenticator.Authenticator, error) {
			return defaultPasswordAuthn(), nil // Identifiers is nil
		},
	}

	var capturedIdentifiers []string
	identities := &stubIdentityStorer{
		createCredentialFn: func(_ context.Context, _, _ uuid.UUID, _ string, ids []string, _ json.RawMessage) (*identity.Credential, error) {
			capturedIdentifiers = ids
			return &identity.Credential{ID: uuid.New()}, nil
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, identities, &stubSchemaEnsurer{}, authnStub, &stubVerificationIniter{})
	values := map[string]string{"traits.email": email, "password": "S3cr3t!"}
	_, err := eng.SubmitFlow(ctx, tenantID, existingFlow.ID, "password", values)

	if err != nil {
		t.Fatalf("SubmitFlow returned unexpected error: %v", err)
	}
	if len(capturedIdentifiers) != 1 || capturedIdentifiers[0] != email {
		t.Errorf("expected identifiers [%q], got %v", email, capturedIdentifiers)
	}
}

// ---------------------------------------------------------------------------
// extractIdentifier tests
// ---------------------------------------------------------------------------

func TestExtractIdentifier_TraitsEmailField(t *testing.T) {
	values := map[string]string{
		"traits.email": "alice@example.com",
		"identifier":   "should-not-be-used",
	}
	got := extractIdentifier(values)
	if got != "alice@example.com" {
		t.Errorf("expected 'alice@example.com', got %q", got)
	}
}

func TestExtractIdentifier_IdentifierField(t *testing.T) {
	values := map[string]string{
		"identifier": "bob@example.com",
	}
	got := extractIdentifier(values)
	if got != "bob@example.com" {
		t.Errorf("expected 'bob@example.com', got %q", got)
	}
}

func TestExtractIdentifier_TraitsJSONBlob(t *testing.T) {
	traitsJSON := `{"email":"carol@example.com","name":"Carol"}`
	values := map[string]string{
		"traits": traitsJSON,
	}
	got := extractIdentifier(values)
	if got != "carol@example.com" {
		t.Errorf("expected 'carol@example.com', got %q", got)
	}
}

func TestExtractIdentifier_TraitsJSONBlobMissingEmail(t *testing.T) {
	values := map[string]string{
		"traits": `{"name":"Dave"}`,
	}
	got := extractIdentifier(values)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestExtractIdentifier_TraitsJSONBlobInvalidJSON(t *testing.T) {
	values := map[string]string{
		"traits": `not-valid-json`,
	}
	got := extractIdentifier(values)
	if got != "" {
		t.Errorf("expected empty string for invalid JSON, got %q", got)
	}
}

func TestExtractIdentifier_EmptyValues(t *testing.T) {
	got := extractIdentifier(map[string]string{})
	if got != "" {
		t.Errorf("expected empty string for empty values, got %q", got)
	}
}

func TestExtractIdentifier_NilMap(t *testing.T) {
	got := extractIdentifier(nil)
	if got != "" {
		t.Errorf("expected empty string for nil map, got %q", got)
	}
}

func TestExtractIdentifier_TraitsEmailTakesPrecedenceOverIdentifier(t *testing.T) {
	values := map[string]string{
		"traits.email": "first@example.com",
		"identifier":   "second@example.com",
		"traits":       `{"email":"third@example.com"}`,
	}
	got := extractIdentifier(values)
	if got != "first@example.com" {
		t.Errorf("traits.email should take precedence, expected 'first@example.com', got %q", got)
	}
}

func TestExtractIdentifier_IdentifierTakesPrecedenceOverTraitsBlob(t *testing.T) {
	values := map[string]string{
		"identifier": "second@example.com",
		"traits":     `{"email":"third@example.com"}`,
	}
	got := extractIdentifier(values)
	if got != "second@example.com" {
		t.Errorf("identifier should take precedence over traits JSON, expected 'second@example.com', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// buildTraits tests
// ---------------------------------------------------------------------------

func TestBuildTraits_MergesTraitsFieldsWithEmail(t *testing.T) {
	values := map[string]string{
		"traits.email":    "alice@example.com",
		"traits.username": "alice",
		"password":        "secret", // non-traits key — must be excluded
	}
	raw := buildTraits(values, "alice@example.com")

	var traits map[string]any
	if err := json.Unmarshal(raw, &traits); err != nil {
		t.Fatalf("buildTraits returned invalid JSON: %v", err)
	}
	if traits["email"] != "alice@example.com" {
		t.Errorf("expected email 'alice@example.com', got %v", traits["email"])
	}
	if traits["username"] != "alice" {
		t.Errorf("expected username 'alice', got %v", traits["username"])
	}
	if _, ok := traits["password"]; ok {
		t.Error("expected 'password' key to be excluded from traits")
	}
}

func TestBuildTraits_IdentifierAlwaysIncluded(t *testing.T) {
	// Even when no traits.* keys are present, the email identifier must be in traits.
	raw := buildTraits(map[string]string{"method": "password"}, "only@example.com")

	var traits map[string]any
	if err := json.Unmarshal(raw, &traits); err != nil {
		t.Fatalf("buildTraits returned invalid JSON: %v", err)
	}
	if traits["email"] != "only@example.com" {
		t.Errorf("expected email 'only@example.com', got %v", traits["email"])
	}
}

func TestBuildTraits_TraitsEmailOverridesIdentifierParam(t *testing.T) {
	// When traits.email is explicitly set in values, the identifier param value
	// should not overwrite it (the traits.email strip puts it in traits["email"]).
	// In practice they are the same value, but we verify the JSONB is valid.
	values := map[string]string{
		"traits.email": "a@example.com",
	}
	raw := buildTraits(values, "a@example.com")

	var traits map[string]any
	if err := json.Unmarshal(raw, &traits); err != nil {
		t.Fatalf("buildTraits returned invalid JSON: %v", err)
	}
	if traits["email"] != "a@example.com" {
		t.Errorf("expected email 'a@example.com', got %v", traits["email"])
	}
}

func TestBuildTraits_EmptyValues(t *testing.T) {
	raw := buildTraits(map[string]string{}, "x@example.com")
	var traits map[string]any
	if err := json.Unmarshal(raw, &traits); err != nil {
		t.Fatalf("buildTraits returned invalid JSON: %v", err)
	}
	if len(traits) != 1 {
		t.Errorf("expected exactly 1 trait key (email), got %d: %v", len(traits), traits)
	}
}

// ---------------------------------------------------------------------------
// parseSessionTTL tests
// ---------------------------------------------------------------------------

func TestParseSessionTTL_ValidDuration(t *testing.T) {
	tests := []struct {
		ttl  string
		want time.Duration
	}{
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
		{"48h", 48 * time.Hour},
		{"24h", 24 * time.Hour},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.ttl, func(t *testing.T) {
			pol := &policy.FlowPolicy{Session: policy.SessionPolicy{TTL: tt.ttl}}
			got := parseSessionTTL(pol)
			if got != tt.want {
				t.Errorf("parseSessionTTL(%q) = %v, want %v", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestParseSessionTTL_InvalidDuration(t *testing.T) {
	invalids := []string{"not-a-duration", "1 hour", "forever", ""}
	for _, s := range invalids {
		s := s
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			pol := &policy.FlowPolicy{Session: policy.SessionPolicy{TTL: s}}
			got := parseSessionTTL(pol)
			if got != 24*time.Hour {
				t.Errorf("parseSessionTTL(%q) = %v, want 24h (default)", s, got)
			}
		})
	}
}

func TestParseSessionTTL_ZeroOrNegativeDuration(t *testing.T) {
	tests := []struct {
		ttl string
	}{
		{"0s"},
		{"-1h"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.ttl, func(t *testing.T) {
			pol := &policy.FlowPolicy{Session: policy.SessionPolicy{TTL: tt.ttl}}
			got := parseSessionTTL(pol)
			if got != 24*time.Hour {
				t.Errorf("parseSessionTTL(%q) = %v, want 24h (default for zero/negative)", tt.ttl, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetFlow tests
// ---------------------------------------------------------------------------

func TestGetFlow_DelegatestoFlowStorer(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	ctx := context.Background()

	expectedFlow := &flow.Flow{
		ID:       flowID,
		TenantID: tenantID,
		Type:     flow.TypeRegistration,
		State:    flow.StatePending,
	}

	flows := &stubFlowStorer{
		getFn: func(_ context.Context, tid, fid uuid.UUID) (*flow.Flow, error) {
			if tid != tenantID || fid != flowID {
				return nil, fmt.Errorf("unexpected ids")
			}
			return expectedFlow, nil
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	got, err := eng.GetFlow(ctx, tenantID, flowID)

	if err != nil {
		t.Fatalf("GetFlow returned unexpected error: %v", err)
	}
	if got != expectedFlow {
		t.Errorf("GetFlow returned wrong flow: got %+v, want %+v", got, expectedFlow)
	}
}

func TestGetFlow_PropagatesError(t *testing.T) {
	ctx := context.Background()
	getErr := errors.New("flow not found")

	flows := &stubFlowStorer{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, getErr
		},
	}

	eng := newDefaultEngine(flows, &stubPolicyGetter{}, &stubIdentityStorer{}, &stubSchemaEnsurer{}, &stubAuthnReg{}, &stubVerificationIniter{})
	_, err := eng.GetFlow(ctx, uuid.New(), uuid.New())

	if !errors.Is(err, getErr) {
		t.Errorf("expected error to wrap getErr, got: %v", err)
	}
}
