package login

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
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Fake implementations
// ---------------------------------------------------------------------------

// fakeFlowStore implements flowStorer.
type fakeFlowStore struct {
	// Create
	createFlow *flow.Flow
	createErr  error

	// Get
	getFlow *flow.Flow
	getErr  error

	// Update — records last call args
	updateErr       error
	lastUpdateState flow.State
	lastUpdateUI    flow.UI
}

func (f *fakeFlowStore) Create(_ context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.createFlow != nil {
		return f.createFlow, nil
	}
	// Build a minimal flow so callers always get something valid.
	return &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flowType,
		State:    flow.StatePending,
		UI:       ui,
	}, nil
}

func (f *fakeFlowStore) Get(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
	return f.getFlow, f.getErr
}

func (f *fakeFlowStore) Update(_ context.Context, _, _ uuid.UUID, state flow.State, _ *uuid.UUID, ui flow.UI) error {
	f.lastUpdateState = state
	f.lastUpdateUI = ui
	return f.updateErr
}

// fakePolicyGetter implements policyGetter.
type fakePolicyGetter struct {
	pol *policy.FlowPolicy
	err error
}

func (f *fakePolicyGetter) Get(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
	return f.pol, f.err
}

// fakeCredReader implements credReader.
type fakeCredReader struct {
	byIdentifierCred *identity.Credential
	byIdentifierErr  error

	byIdentityAndTypeCred *identity.Credential
	byIdentityAndTypeErr  error
}

func (f *fakeCredReader) GetByIdentifier(_ context.Context, _ uuid.UUID, _, _ string) (*identity.Credential, error) {
	return f.byIdentifierCred, f.byIdentifierErr
}

func (f *fakeCredReader) GetByIdentityAndType(_ context.Context, _, _ uuid.UUID, _ string) (*identity.Credential, error) {
	return f.byIdentityAndTypeCred, f.byIdentityAndTypeErr
}

// fakeAuthnReg implements authnReg.
type fakeAuthnReg struct {
	auths map[string]authenticator.Authenticator
	// err is returned for every Get call when set (overrides per-key lookup).
	err error
}

func newFakeAuthnReg() *fakeAuthnReg {
	return &fakeAuthnReg{auths: make(map[string]authenticator.Authenticator)}
}

func (f *fakeAuthnReg) register(a authenticator.Authenticator) {
	f.auths[a.ID()] = a
}

func (f *fakeAuthnReg) Get(id string) (authenticator.Authenticator, error) {
	if f.err != nil {
		return nil, f.err
	}
	a, ok := f.auths[id]
	if !ok {
		return nil, fmt.Errorf("registry.Get %q: %w", id, authnregistry.ErrNotFound)
	}
	return a, nil
}

// fakeAuthenticator implements authenticator.Authenticator.
type fakeAuthenticator struct {
	id   string
	kind authenticator.Type

	startFlowState *authenticator.FlowState
	startFlowErr   error

	completeFlowResult *authenticator.AuthResult
	completeFlowErr    error
}

func newFakeAuthenticator(id string, kind authenticator.Type) *fakeAuthenticator {
	return &fakeAuthenticator{
		id:   id,
		kind: kind,
		startFlowState: &authenticator.FlowState{
			Nodes: []authenticator.UINode{
				{
					Type:  "input",
					Group: id,
					Attributes: authenticator.UINodeAttrs{
						Name:     id + "_input",
						Type:     "text",
						Required: true,
					},
				},
			},
		},
		completeFlowResult: &authenticator.AuthResult{
			AAL: "aal1",
			AMR: []string{id},
		},
	}
}

func (f *fakeAuthenticator) ID() string                  { return f.id }
func (f *fakeAuthenticator) Type() authenticator.Type    { return f.kind }

func (f *fakeAuthenticator) StartFlow(_ context.Context, _ *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
	return f.startFlowState, f.startFlowErr
}

func (f *fakeAuthenticator) CompleteFlow(_ context.Context, _ *authenticator.CompleteFlowRequest) (*authenticator.AuthResult, error) {
	if f.completeFlowErr != nil {
		return nil, f.completeFlowErr
	}
	result := *f.completeFlowResult
	return &result, nil
}

func (f *fakeAuthenticator) Enroll(_ context.Context, _ *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeAuthenticator) Unenroll(_ context.Context, _ *authenticator.UnenrollRequest) error {
	return errors.New("not implemented")
}

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

// testCredential builds a minimal identity.Credential for use in tests.
func testCredential(identityID uuid.UUID, config json.RawMessage) *identity.Credential {
	return &identity.Credential{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		IdentityID:  identityID,
		Type:        "password",
		Identifiers: []string{"user@example.com"},
		Config:      config,
	}
}

// testFlow builds a minimal flow.Flow in the given state and phase.
func testFlow(tenantID uuid.UUID, state flow.State, phase string) *flow.Flow {
	f := &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeLogin,
		State:    state,
		UI: flow.UI{
			Method: "POST",
		},
	}
	if phase != "" {
		f.UI.Internal = &flow.UIInternal{
			Phase:       phase,
			AuthnStates: map[string]string{},
		}
	}
	return f
}

// defaultPolicy returns a copy of the default policy, easy to tweak in tests.
func defaultPolicy() *policy.FlowPolicy {
	p := policy.Default()
	return p
}

// mfaPolicy returns a policy with MFA required and totp as the second factor.
func mfaPolicy() *policy.FlowPolicy {
	p := policy.Default()
	p.Login.MFARequired = true
	p.Login.AllowedSecondFactors = []string{"totp"}
	return p
}

// ---------------------------------------------------------------------------
// InitFlow tests
// ---------------------------------------------------------------------------

func TestInitFlow_Success(t *testing.T) {
	tenantID := uuid.New()
	pol := defaultPolicy() // allowed first factors: ["password"]

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	store := &fakeFlowStore{}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, reg)

	f, err := eng.InitFlow(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil flow")
	}
	if f.State != flow.StatePending {
		t.Errorf("expected state pending, got %s", f.State)
	}
	if f.UI.Internal == nil || f.UI.Internal.Phase != "first_factor" {
		t.Error("expected UI.Internal.Phase = first_factor")
	}
	// Should have identifier node + password node + submit node.
	if len(f.UI.Nodes) < 2 {
		t.Errorf("expected at least 2 nodes, got %d", len(f.UI.Nodes))
	}
}

func TestInitFlow_PolicyGetError(t *testing.T) {
	polErr := errors.New("db down")
	eng := New(
		&fakeFlowStore{},
		&fakePolicyGetter{err: polErr},
		&fakeCredReader{},
		newFakeAuthnReg(),
	)

	_, err := eng.InitFlow(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error from policy.Get")
	}
	if !errors.Is(err, polErr) {
		t.Errorf("expected wrapped polErr, got: %v", err)
	}
}

func TestInitFlow_FlowCreateError(t *testing.T) {
	pol := defaultPolicy()
	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	createErr := errors.New("insert failed")
	store := &fakeFlowStore{createErr: createErr}

	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, reg)

	_, err := eng.InitFlow(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error from flows.Create")
	}
	if !errors.Is(err, createErr) {
		t.Errorf("expected wrapped createErr, got: %v", err)
	}
}

func TestInitFlow_AuthenticatorNotRegistered_ErrNotFoundIsSkipped(t *testing.T) {
	// Policy lists "oidc" but the authenticator is not registered.
	// Engine should skip it silently and still create the flow.
	pol := defaultPolicy()
	pol.Login.AllowedFirstFactors = []string{"oidc", "password"}

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	reg := newFakeAuthnReg()
	reg.register(pwAuthn) // "oidc" deliberately absent → ErrNotFound

	store := &fakeFlowStore{}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, reg)

	f, err := eng.InitFlow(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("expected ErrNotFound to be skipped, got: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil flow")
	}
}

func TestInitFlow_AuthenticatorStartFlowError(t *testing.T) {
	pol := defaultPolicy()
	startErr := errors.New("totp service unavailable")

	brokenAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	brokenAuthn.startFlowErr = startErr

	reg := newFakeAuthnReg()
	reg.register(brokenAuthn)

	eng := New(&fakeFlowStore{}, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, reg)

	_, err := eng.InitFlow(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error from StartFlow")
	}
	if !errors.Is(err, startErr) {
		t.Errorf("expected wrapped startErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetFlow tests
// ---------------------------------------------------------------------------

func TestGetFlow_DelegatesToFlowStore(t *testing.T) {
	tenantID := uuid.New()
	expected := testFlow(tenantID, flow.StatePending, "first_factor")

	store := &fakeFlowStore{getFlow: expected}
	eng := New(store, &fakePolicyGetter{pol: defaultPolicy()}, &fakeCredReader{}, newFakeAuthnReg())

	got, err := eng.GetFlow(context.Background(), tenantID, expected.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Error("expected the same flow pointer returned by the store")
	}
}

func TestGetFlow_PropagatesStoreError(t *testing.T) {
	storeErr := errors.New("not found")
	store := &fakeFlowStore{getErr: storeErr}
	eng := New(store, &fakePolicyGetter{pol: defaultPolicy()}, &fakeCredReader{}, newFakeAuthnReg())

	_, err := eng.GetFlow(context.Background(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatal("expected error from store.Get")
	}
	if !errors.Is(err, storeErr) {
		t.Errorf("expected wrapped storeErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — non-pending flow guard
// ---------------------------------------------------------------------------

func TestSubmitFlow_NonPendingFlowReturnsError(t *testing.T) {
	tenantID := uuid.New()

	for _, state := range []flow.State{flow.StateSuccess, flow.StateFailed, flow.StateExpired} {
		t.Run(string(state), func(t *testing.T) {
			f := testFlow(tenantID, state, "first_factor")
			store := &fakeFlowStore{getFlow: f}
			eng := New(store, &fakePolicyGetter{pol: defaultPolicy()}, &fakeCredReader{}, newFakeAuthnReg())

			_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
				"identifier": "user@example.com",
				"password":   "secret",
			})
			if err == nil {
				t.Fatalf("expected error for %s flow", state)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — unknown phase
// ---------------------------------------------------------------------------

func TestSubmitFlow_UnknownPhaseReturnsError(t *testing.T) {
	tenantID := uuid.New()
	f := testFlow(tenantID, flow.StatePending, "third_dimension")
	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: defaultPolicy()}, &fakeCredReader{}, newFakeAuthnReg())

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", nil)
	if err == nil {
		t.Fatal("expected error for unknown phase")
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — first_factor
// ---------------------------------------------------------------------------

func TestSubmitFlow_FirstFactor_SuccessNoMFA(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := defaultPolicy() // MFARequired = false
	f := testFlow(tenantID, flow.StatePending, "first_factor")

	cred := testCredential(identityID, json.RawMessage(`{"hash":"$bcrypt$..."}`))

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	result, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correcthorsebatterystaple",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Completed {
		t.Error("expected Completed = true")
	}
	if result.IdentityID != identityID {
		t.Errorf("expected identityID %s, got %s", identityID, result.IdentityID)
	}
	if result.AAL != "aal1" {
		t.Errorf("expected AAL aal1, got %s", result.AAL)
	}
	if len(result.AMR) == 0 || result.AMR[0] != "password" {
		t.Errorf("unexpected AMR: %v", result.AMR)
	}
	if store.lastUpdateState != flow.StateSuccess {
		t.Errorf("expected flow updated to success, got %s", store.lastUpdateState)
	}
}

func TestSubmitFlow_FirstFactor_SuccessMFARequired_AdvancesToSecondFactor(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := mfaPolicy() // MFARequired = true, AllowedSecondFactors = ["totp"]

	f := testFlow(tenantID, flow.StatePending, "first_factor")
	cred := testCredential(identityID, json.RawMessage(`{}`))

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}

	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)

	reg := newFakeAuthnReg()
	reg.register(pwAuthn)
	reg.register(totpAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	result, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correct",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Completed {
		t.Error("expected Completed = false while waiting for second factor")
	}
	if store.lastUpdateState != flow.StatePending {
		t.Errorf("expected flow kept pending, got %s", store.lastUpdateState)
	}
	if store.lastUpdateUI.Internal == nil || store.lastUpdateUI.Internal.Phase != "second_factor" {
		t.Error("expected phase advanced to second_factor")
	}
}

func TestSubmitFlow_FirstFactor_BadMethod(t *testing.T) {
	tenantID := uuid.New()
	pol := defaultPolicy() // only "password" allowed
	f := testFlow(tenantID, flow.StatePending, "first_factor")

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, newFakeAuthnReg())

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "magic_link", map[string]string{
		"identifier": "user@example.com",
	})
	if err == nil {
		t.Fatal("expected error for disallowed method")
	}
}

func TestSubmitFlow_FirstFactor_MissingIdentifier(t *testing.T) {
	tenantID := uuid.New()
	pol := defaultPolicy()
	f := testFlow(tenantID, flow.StatePending, "first_factor")

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"password": "secret",
		// "identifier" deliberately omitted
	})
	if err == nil {
		t.Fatal("expected error for missing identifier")
	}
}

func TestSubmitFlow_FirstFactor_CredentialNotFound_ErrNotFound(t *testing.T) {
	tenantID := uuid.New()
	pol := defaultPolicy()
	f := testFlow(tenantID, flow.StatePending, "first_factor")

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	// Wrap ErrNotFound the same way the real store does.
	notFoundErr := fmt.Errorf("identity.GetByIdentifier: %w", identity.ErrNotFound)
	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierErr: notFoundErr}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "ghost@example.com",
		"password":   "any",
	})
	if err == nil {
		t.Fatal("expected error for credential not found")
	}
	// Should surface as generic "invalid credentials", not exposing ErrNotFound.
	if errors.Is(err, identity.ErrNotFound) {
		t.Error("ErrNotFound must not propagate to the caller (information leak)")
	}
}

func TestSubmitFlow_FirstFactor_CredentialLookupError(t *testing.T) {
	tenantID := uuid.New()
	pol := defaultPolicy()
	f := testFlow(tenantID, flow.StatePending, "first_factor")

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	dbErr := errors.New("network timeout")
	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierErr: dbErr}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "any",
	})
	if err == nil {
		t.Fatal("expected error from credential lookup")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

func TestSubmitFlow_FirstFactor_CompleteFlowFailure(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()
	pol := defaultPolicy()
	f := testFlow(tenantID, flow.StatePending, "first_factor")

	cred := testCredential(identityID, json.RawMessage(`{}`))
	authnErr := errors.New("wrong password")

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowErr = authnErr
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "wrong",
	})
	if err == nil {
		t.Fatal("expected error from CompleteFlow")
	}
	if !errors.Is(err, authnErr) {
		t.Errorf("expected wrapped authnErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — second_factor
// ---------------------------------------------------------------------------

func TestSubmitFlow_SecondFactor_SuccessAAL2(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := mfaPolicy()

	f := testFlow(tenantID, flow.StatePending, "second_factor")
	f.IdentityID = &identityID
	f.UI.Internal.CompletedAAL = "aal1"
	f.UI.Internal.CompletedAMR = []string{"password"}
	f.UI.Internal.AuthnStates = map[string]string{"totp": "tok123"}

	cred := testCredential(identityID, json.RawMessage(`{"secret":"JBSWY3DPEHPK3PXP"}`))
	cred.Type = "totp"

	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)
	totpAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal2",
		AMR:        []string{"totp"},
	}

	reg := newFakeAuthnReg()
	reg.register(totpAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentityAndTypeCred: cred}, reg)

	result, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "totp", map[string]string{
		"totp_code": "123456",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Completed {
		t.Error("expected Completed = true after second factor")
	}
	if result.AAL != "aal2" {
		t.Errorf("expected AAL aal2, got %s", result.AAL)
	}
	// AMR should include both factors.
	if len(result.AMR) != 2 {
		t.Errorf("expected 2 AMR entries (password+totp), got %v", result.AMR)
	}
	if store.lastUpdateState != flow.StateSuccess {
		t.Errorf("expected flow updated to success, got %s", store.lastUpdateState)
	}
}

func TestSubmitFlow_SecondFactor_BadMethod(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := mfaPolicy() // only "totp" allowed as second factor
	f := testFlow(tenantID, flow.StatePending, "second_factor")
	f.IdentityID = &identityID

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, newFakeAuthnReg())

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "passkey", map[string]string{})
	if err == nil {
		t.Fatal("expected error for disallowed second factor method")
	}
}

func TestSubmitFlow_SecondFactor_NoIdentityIDOnFlow(t *testing.T) {
	tenantID := uuid.New()
	pol := mfaPolicy()

	f := testFlow(tenantID, flow.StatePending, "second_factor")
	// f.IdentityID intentionally nil

	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)
	reg := newFakeAuthnReg()
	reg.register(totpAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "totp", map[string]string{
		"totp_code": "123456",
	})
	if err == nil {
		t.Fatal("expected error when identity_id is not set")
	}
}

func TestSubmitFlow_SecondFactor_CredentialNotFound(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()
	pol := mfaPolicy()

	f := testFlow(tenantID, flow.StatePending, "second_factor")
	f.IdentityID = &identityID

	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)
	reg := newFakeAuthnReg()
	reg.register(totpAuthn)

	notFoundErr := fmt.Errorf("identity.GetByIdentityAndType: %w", identity.ErrNotFound)
	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentityAndTypeErr: notFoundErr}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "totp", map[string]string{
		"totp_code": "123456",
	})
	if err == nil {
		t.Fatal("expected error for credential not found")
	}
}

func TestSubmitFlow_SecondFactor_CompleteFlowFailure(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()
	pol := mfaPolicy()

	f := testFlow(tenantID, flow.StatePending, "second_factor")
	f.IdentityID = &identityID

	cred := testCredential(identityID, json.RawMessage(`{}`))
	cred.Type = "totp"

	authnErr := errors.New("invalid TOTP code")
	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)
	totpAuthn.completeFlowErr = authnErr
	reg := newFakeAuthnReg()
	reg.register(totpAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentityAndTypeCred: cred}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "totp", map[string]string{
		"totp_code": "000000",
	})
	if err == nil {
		t.Fatal("expected error from second factor CompleteFlow")
	}
	if !errors.Is(err, authnErr) {
		t.Errorf("expected wrapped authnErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseSessionTTL tests
// ---------------------------------------------------------------------------

func TestParseSessionTTL_ValidDuration(t *testing.T) {
	pol := defaultPolicy()
	pol.Session.TTL = "12h"
	got := parseSessionTTL(pol)
	if got != 12*time.Hour {
		t.Errorf("expected 12h, got %v", got)
	}
}

func TestParseSessionTTL_InvalidString_DefaultsTo24h(t *testing.T) {
	pol := defaultPolicy()
	pol.Session.TTL = "not-a-duration"
	got := parseSessionTTL(pol)
	if got != 24*time.Hour {
		t.Errorf("expected default 24h for invalid TTL, got %v", got)
	}
}

func TestParseSessionTTL_ZeroDuration_DefaultsTo24h(t *testing.T) {
	pol := defaultPolicy()
	pol.Session.TTL = "0s"
	got := parseSessionTTL(pol)
	if got != 24*time.Hour {
		t.Errorf("expected default 24h for zero TTL, got %v", got)
	}
}

func TestParseSessionTTL_EmptyString_DefaultsTo24h(t *testing.T) {
	pol := defaultPolicy()
	pol.Session.TTL = ""
	got := parseSessionTTL(pol)
	if got != 24*time.Hour {
		t.Errorf("expected default 24h for empty TTL, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// containsStr tests
// ---------------------------------------------------------------------------

func TestContainsStr_Found(t *testing.T) {
	if !containsStr([]string{"password", "oidc", "saml"}, "oidc") {
		t.Error("expected to find 'oidc'")
	}
}

func TestContainsStr_NotFound(t *testing.T) {
	if containsStr([]string{"password", "oidc"}, "totp") {
		t.Error("expected not to find 'totp'")
	}
}

func TestContainsStr_EmptySlice(t *testing.T) {
	if containsStr([]string{}, "password") {
		t.Error("expected not to find anything in empty slice")
	}
}

func TestContainsStr_EmptyNeedle(t *testing.T) {
	if containsStr([]string{"password", ""}, "") {
		// empty string is in the slice — should be found
	}
	if !containsStr([]string{"password", ""}, "") {
		t.Error("expected to find empty string when it is in the slice")
	}
}

// ---------------------------------------------------------------------------
// appendFlowError — indirect coverage via CompleteFlow failure path
// ---------------------------------------------------------------------------

func TestAppendFlowError_UpdatesFlowMessages(t *testing.T) {
	// When CompleteFlow returns an error, appendFlowError should be called and
	// the flow store should be updated with an error message node.
	tenantID := uuid.New()
	identityID := uuid.New()
	pol := defaultPolicy()

	f := testFlow(tenantID, flow.StatePending, "first_factor")
	cred := testCredential(identityID, json.RawMessage(`{}`))

	authnErr := errors.New("bad password")
	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowErr = authnErr
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	_, _ = eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "wrong",
	})

	// appendFlowError calls Update with StatePending and a messages slice.
	if store.lastUpdateState != flow.StatePending {
		t.Errorf("expected flow updated with pending state after error, got %s", store.lastUpdateState)
	}
	if len(store.lastUpdateUI.Messages) == 0 {
		t.Error("expected error message to be appended to flow UI")
	}
	if store.lastUpdateUI.Messages[0].Type != "error" {
		t.Errorf("expected message type 'error', got %q", store.lastUpdateUI.Messages[0].Type)
	}
}

// ---------------------------------------------------------------------------
// advanceToSecondFactor — second-factor authenticator not registered is skipped
// ---------------------------------------------------------------------------

func TestAdvanceToSecondFactor_UnregisteredAuthenticatorSkipped(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := mfaPolicy()
	pol.Login.AllowedSecondFactors = []string{"passkey", "totp"}

	f := testFlow(tenantID, flow.StatePending, "first_factor")
	cred := testCredential(identityID, json.RawMessage(`{}`))

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}
	// Only "totp" registered, "passkey" absent → should be skipped silently.
	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)

	reg := newFakeAuthnReg()
	reg.register(pwAuthn)
	reg.register(totpAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	result, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correct",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Completed {
		t.Error("expected Completed = false while MFA pending")
	}
	if store.lastUpdateUI.Internal == nil || store.lastUpdateUI.Internal.Phase != "second_factor" {
		t.Error("expected phase = second_factor")
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — policy.Get error during submit
// ---------------------------------------------------------------------------

func TestSubmitFlow_PolicyGetError(t *testing.T) {
	tenantID := uuid.New()
	f := testFlow(tenantID, flow.StatePending, "first_factor")
	polErr := errors.New("policy store offline")

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{err: polErr}, &fakeCredReader{}, newFakeAuthnReg())

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
	})
	if err == nil {
		t.Fatal("expected error when policy.Get fails during SubmitFlow")
	}
	if !errors.Is(err, polErr) {
		t.Errorf("expected wrapped polErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — flow store Get error during submit
// ---------------------------------------------------------------------------

func TestSubmitFlow_FlowGetError(t *testing.T) {
	storeErr := errors.New("flow not found")
	store := &fakeFlowStore{getErr: storeErr}
	eng := New(store, &fakePolicyGetter{pol: defaultPolicy()}, &fakeCredReader{}, newFakeAuthnReg())

	_, err := eng.SubmitFlow(context.Background(), uuid.New(), uuid.New(), "password", nil)
	if err == nil {
		t.Fatal("expected error when flows.Get fails")
	}
	if !errors.Is(err, storeErr) {
		t.Errorf("expected wrapped storeErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — flow update error after successful first factor (no MFA)
// ---------------------------------------------------------------------------

func TestSubmitFlow_FirstFactor_FlowUpdateError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()
	pol := defaultPolicy()

	f := testFlow(tenantID, flow.StatePending, "first_factor")
	cred := testCredential(identityID, json.RawMessage(`{}`))

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	updateErr := errors.New("db write failed")
	store := &fakeFlowStore{getFlow: f, updateErr: updateErr}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correct",
	})
	if err == nil {
		t.Fatal("expected error from flows.Update")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("expected wrapped updateErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — flow update error after successful second factor
// ---------------------------------------------------------------------------

func TestSubmitFlow_SecondFactor_FlowUpdateError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()
	pol := mfaPolicy()

	f := testFlow(tenantID, flow.StatePending, "second_factor")
	f.IdentityID = &identityID
	f.UI.Internal.CompletedAMR = []string{"password"}

	cred := testCredential(identityID, json.RawMessage(`{}`))
	cred.Type = "totp"

	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)
	totpAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal2",
		AMR:        []string{"totp"},
	}
	reg := newFakeAuthnReg()
	reg.register(totpAuthn)

	updateErr := errors.New("db write failed")
	store := &fakeFlowStore{getFlow: f, updateErr: updateErr}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentityAndTypeCred: cred}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "totp", map[string]string{
		"totp_code": "123456",
	})
	if err == nil {
		t.Fatal("expected error from flows.Update on second factor completion")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("expected wrapped updateErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow — first_factor with nil UI.Internal (defaults to first_factor)
// ---------------------------------------------------------------------------

func TestSubmitFlow_NilUIInternal_DefaultsToFirstFactor(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()
	pol := defaultPolicy()

	// Build a flow with no Internal set — engine should default to first_factor.
	f := &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeLogin,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			// Internal is nil intentionally
		},
	}

	cred := testCredential(identityID, json.RawMessage(`{}`))
	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	result, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correct",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Completed {
		t.Error("expected Completed = true for first-factor with nil Internal")
	}
}

// ---------------------------------------------------------------------------
// Session TTL is surfaced in SubmitResult
// ---------------------------------------------------------------------------

func TestSubmitFlow_SessionTTLInResult(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := defaultPolicy()
	pol.Session.TTL = "8h"

	f := testFlow(tenantID, flow.StatePending, "first_factor")
	cred := testCredential(identityID, json.RawMessage(`{}`))

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}
	reg := newFakeAuthnReg()
	reg.register(pwAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	result, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correct",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SessionTTL != 8*time.Hour {
		t.Errorf("expected SessionTTL 8h, got %v", result.SessionTTL)
	}
}
