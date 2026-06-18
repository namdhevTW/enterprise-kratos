package login

// engine_extra_test.go — supplementary tests for branches not covered by engine_test.go.
// Fake types (fakeFlowStore, fakePolicyGetter, fakeCredReader, fakeAuthnReg, fakeAuthenticator)
// are defined in engine_test.go and are available here because both files share package login.

import (
	"context"
	"errors"
	"testing"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Branch 1: InitFlow — authn.Get returns an error that is NOT ErrNotFound
// ---------------------------------------------------------------------------

// TestInitFlow_AuthenticatorUnexpectedRegistryError covers the branch at
// engine.go line 98-100 where aErr != nil AND !errors.Is(aErr, ErrNotFound).
func TestInitFlow_AuthenticatorUnexpectedRegistryError(t *testing.T) {
	pol := defaultPolicy()
	pol.Login.AllowedFirstFactors = []string{"password"}

	unexpectedErr := errors.New("internal registry corruption")

	// fakeAuthnReg.err makes every Get call return this error, regardless of key.
	// Because it is not wrapped with authnregistry.ErrNotFound, the engine must
	// propagate it rather than skip.
	reg := &fakeAuthnReg{
		auths: make(map[string]authenticator.Authenticator),
		err:   unexpectedErr,
	}

	eng := New(&fakeFlowStore{}, &fakePolicyGetter{pol: pol}, &fakeCredReader{}, reg)

	_, err := eng.InitFlow(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when authn.Get returns a non-ErrNotFound error")
	}
	if !errors.Is(err, unexpectedErr) {
		t.Errorf("expected wrapped unexpectedErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Branch 2: advanceToSecondFactor — a.StartFlow() returns an error
// ---------------------------------------------------------------------------

// TestAdvanceToSecondFactor_StartFlowError covers the branch at
// engine.go line 271-273 where the second-factor authenticator's StartFlow
// returns an error.  We trigger it by completing the first factor successfully
// under an MFA policy, while the second-factor authenticator is rigged to fail
// StartFlow.
func TestAdvanceToSecondFactor_StartFlowError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := mfaPolicy() // MFARequired=true, AllowedSecondFactors=["totp"]

	f := testFlow(tenantID, flow.StatePending, "first_factor")

	// First-factor credential lookup succeeds.
	cred := testCredential(identityID, []byte(`{}`))

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}

	startErr := errors.New("second-factor service unreachable")
	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)
	totpAuthn.startFlowErr = startErr // StartFlow will fail

	reg := newFakeAuthnReg()
	reg.register(pwAuthn)
	reg.register(totpAuthn)

	store := &fakeFlowStore{getFlow: f}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correct",
	})
	if err == nil {
		t.Fatal("expected error when second-factor StartFlow fails")
	}
	if !errors.Is(err, startErr) {
		t.Errorf("expected wrapped startErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Branch 3 / Branch 5: advanceToSecondFactor — e.flows.Update() fails
// (also covers submitFirstFactor's MFA advancement Update failure path)
// ---------------------------------------------------------------------------

// TestAdvanceToSecondFactor_UpdateError covers engine.go line 289-291 where
// flows.Update returns an error during the phase transition from first factor
// to second factor.
func TestAdvanceToSecondFactor_UpdateError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := mfaPolicy() // MFARequired=true, AllowedSecondFactors=["totp"]

	f := testFlow(tenantID, flow.StatePending, "first_factor")

	cred := testCredential(identityID, []byte(`{}`))

	pwAuthn := newFakeAuthenticator("password", authenticator.FirstFactor)
	pwAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
	}

	// totpAuthn's StartFlow succeeds (returns default nodes).
	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)

	reg := newFakeAuthnReg()
	reg.register(pwAuthn)
	reg.register(totpAuthn)

	updateErr := errors.New("db write failed during MFA advance")
	store := &fakeFlowStore{getFlow: f, updateErr: updateErr}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentifierCred: cred}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "password", map[string]string{
		"identifier": "user@example.com",
		"password":   "correct",
	})
	if err == nil {
		t.Fatal("expected error when flows.Update fails during MFA phase advance")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("expected wrapped updateErr, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Branch 4: submitSecondFactor — e.flows.Update() fails at completion
// ---------------------------------------------------------------------------

// TestSubmitSecondFactor_UpdateErrorAtCompletion covers engine.go line 353-355
// where flows.Update fails after a successful second-factor CompleteFlow.
// This is distinct from TestSubmitFlow_SecondFactor_FlowUpdateError in
// engine_test.go (which may share the same updateErr field); this test
// explicitly verifies the error is surfaced from the completion Update, not
// from appendFlowError.
func TestSubmitSecondFactor_UpdateErrorAtCompletion(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	pol := mfaPolicy()

	f := testFlow(tenantID, flow.StatePending, "second_factor")
	f.IdentityID = &identityID
	f.UI.Internal.CompletedAAL = "aal1"
	f.UI.Internal.CompletedAMR = []string{"password"}
	f.UI.Internal.AuthnStates = map[string]string{"totp": ""}

	cred := testCredential(identityID, []byte(`{"secret":"JBSWY3DPEHPK3PXP"}`))
	cred.Type = "totp"

	totpAuthn := newFakeAuthenticator("totp", authenticator.SecondFactor)
	// CompleteFlow succeeds — we want to reach the flows.Update call.
	totpAuthn.completeFlowResult = &authenticator.AuthResult{
		IdentityID: identityID,
		AAL:        "aal2",
		AMR:        []string{"totp"},
	}

	reg := newFakeAuthnReg()
	reg.register(totpAuthn)

	updateErr := errors.New("db commit failed at second factor completion")
	store := &fakeFlowStore{getFlow: f, updateErr: updateErr}
	eng := New(store, &fakePolicyGetter{pol: pol}, &fakeCredReader{byIdentityAndTypeCred: cred}, reg)

	_, err := eng.SubmitFlow(context.Background(), tenantID, f.ID, "totp", map[string]string{
		"totp_code": "123456",
	})
	if err == nil {
		t.Fatal("expected error when flows.Update fails at second factor completion")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("expected wrapped updateErr, got: %v", err)
	}
}
