package verification

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Fake implementations of flowStorer and identityActivator
// ---------------------------------------------------------------------------

type fakeFlowStore struct {
	// createFn is called by Create; if nil the store uses createResult/createErr.
	createFn  func(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error)
	getFn     func(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	updateFn  func(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error
	updateStateFn func(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State) error

	// record the last UpdateState call so tests can assert on it
	lastUpdateStateState flow.State
}

func (f *fakeFlowStore) Create(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error) {
	if f.createFn != nil {
		return f.createFn(ctx, tenantID, flowType, ui, expiresAt)
	}
	// Default: echo back a synthetic flow with the given arguments.
	fl := &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flowType,
		State:    flow.StatePending,
		UI:       ui,
	}
	return fl, nil
}

func (f *fakeFlowStore) Get(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	if f.getFn != nil {
		return f.getFn(ctx, tenantID, flowID)
	}
	return nil, flow.ErrNotFound
}

func (f *fakeFlowStore) Update(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error {
	if f.updateFn != nil {
		return f.updateFn(ctx, tenantID, flowID, state, identityID, ui)
	}
	return nil
}

func (f *fakeFlowStore) UpdateState(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State) error {
	f.lastUpdateStateState = state
	if f.updateStateFn != nil {
		return f.updateStateFn(ctx, tenantID, flowID, state)
	}
	return nil
}

// ---------------------------------------------------------------------------

type fakeIdentityActivator struct {
	updateStateFn func(ctx context.Context, tenantID, identityID uuid.UUID, state string) error

	// recorded arguments for assertion
	calledTenantID   uuid.UUID
	calledIdentityID uuid.UUID
	calledState      string
	called           bool
}

func (a *fakeIdentityActivator) UpdateIdentityState(ctx context.Context, tenantID, identityID uuid.UUID, state string) error {
	a.called = true
	a.calledTenantID = tenantID
	a.calledIdentityID = identityID
	a.calledState = state
	if a.updateStateFn != nil {
		return a.updateStateFn(ctx, tenantID, identityID, state)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helper: build a ready-to-submit flow with a VerificationToken already set
// ---------------------------------------------------------------------------

func buildPendingVerificationFlow(tenantID, identityID uuid.UUID, token string) *flow.Flow {
	id := uuid.New()
	return &flow.Flow{
		ID:         id,
		TenantID:   tenantID,
		Type:       flow.TypeVerification,
		State:      flow.StatePending,
		IdentityID: &identityID,
		UI: flow.UI{
			Method: "POST",
			Internal: &flow.UIInternal{
				Phase:             "verify",
				VerificationToken: token,
			},
		},
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

// ---------------------------------------------------------------------------
// InitFlow tests
// ---------------------------------------------------------------------------

func TestInitFlow_Success(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	store := &fakeFlowStore{}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	f, plainToken, err := engine.InitFlow(context.Background(), tenantID, identityID)

	if err != nil {
		t.Fatalf("InitFlow returned unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("InitFlow returned nil flow")
	}
	if plainToken == "" {
		t.Fatal("InitFlow returned empty plaintext token")
	}
	if f.IdentityID == nil {
		t.Fatal("InitFlow: flow.IdentityID is nil")
	}
	if *f.IdentityID != identityID {
		t.Errorf("InitFlow: flow.IdentityID = %s, want %s", *f.IdentityID, identityID)
	}
}

func TestInitFlow_TokenStoredInUIInternal(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	var capturedUI flow.UI
	store := &fakeFlowStore{
		createFn: func(ctx context.Context, tid uuid.UUID, ft flow.Type, ui flow.UI, exp time.Time) (*flow.Flow, error) {
			capturedUI = ui
			return &flow.Flow{
				ID:       uuid.New(),
				TenantID: tid,
				Type:     ft,
				State:    flow.StatePending,
				UI:       ui,
			}, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	_, plainToken, err := engine.InitFlow(context.Background(), tenantID, identityID)
	if err != nil {
		t.Fatalf("InitFlow returned unexpected error: %v", err)
	}

	if capturedUI.Internal == nil {
		t.Fatal("InitFlow: UI.Internal is nil in the Create call")
	}
	storedToken := capturedUI.Internal.VerificationToken
	if storedToken == "" {
		t.Fatal("InitFlow: UI.Internal.VerificationToken is empty")
	}
	if storedToken != plainToken {
		t.Errorf("InitFlow: stored token %q does not match returned plaintext token %q", storedToken, plainToken)
	}
}

func TestInitFlow_ReturnedTokenIsNonEmpty(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	store := &fakeFlowStore{}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	_, token, err := engine.InitFlow(context.Background(), tenantID, identityID)
	if err != nil {
		t.Fatalf("InitFlow returned unexpected error: %v", err)
	}
	if len(token) == 0 {
		t.Error("InitFlow: returned token is empty")
	}
}

func TestInitFlow_CreateError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()
	createErr := errors.New("db: connection refused")

	store := &fakeFlowStore{
		createFn: func(_ context.Context, _ uuid.UUID, _ flow.Type, _ flow.UI, _ time.Time) (*flow.Flow, error) {
			return nil, createErr
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	f, tok, err := engine.InitFlow(context.Background(), tenantID, identityID)
	if err == nil {
		t.Fatal("InitFlow: expected error, got nil")
	}
	if f != nil {
		t.Error("InitFlow: expected nil flow on error")
	}
	if tok != "" {
		t.Error("InitFlow: expected empty token on error")
	}
	if !errors.Is(err, createErr) {
		t.Errorf("InitFlow: error chain should wrap createErr; got %v", err)
	}
}

func TestInitFlow_UpdateError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()
	updateErr := errors.New("db: update failed")

	store := &fakeFlowStore{
		updateFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ flow.State, _ *uuid.UUID, _ flow.UI) error {
			return updateErr
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	f, tok, err := engine.InitFlow(context.Background(), tenantID, identityID)
	if err == nil {
		t.Fatal("InitFlow: expected error from Update, got nil")
	}
	if f != nil {
		t.Error("InitFlow: expected nil flow when Update fails")
	}
	if tok != "" {
		t.Error("InitFlow: expected empty token when Update fails")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("InitFlow: error chain should wrap updateErr; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetFlow tests
// ---------------------------------------------------------------------------

func TestGetFlow_DelegatesToFlowStore(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()

	want := &flow.Flow{
		ID:         flowID,
		TenantID:   tenantID,
		Type:       flow.TypeVerification,
		State:      flow.StatePending,
		IdentityID: &identityID,
	}

	store := &fakeFlowStore{
		getFn: func(_ context.Context, tid, fid uuid.UUID) (*flow.Flow, error) {
			if tid != tenantID || fid != flowID {
				t.Errorf("Get called with wrong IDs: tenantID=%s flowID=%s", tid, fid)
			}
			return want, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	got, err := engine.GetFlow(context.Background(), tenantID, flowID)
	if err != nil {
		t.Fatalf("GetFlow unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("GetFlow: returned %v, want %v", got, want)
	}
}

func TestGetFlow_PropagatesNotFound(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	flowID := uuid.New()

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, flow.ErrNotFound
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	_, err := engine.GetFlow(context.Background(), tenantID, flowID)
	if !errors.Is(err, flow.ErrNotFound) {
		t.Errorf("GetFlow: expected ErrNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow tests
// ---------------------------------------------------------------------------

func TestSubmitFlow_Success(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()
	token := "valid-token-abc123"

	f := buildPendingVerificationFlow(tenantID, identityID, token)

	var updateCalledWith flow.State
	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
		updateFn: func(_ context.Context, _, _ uuid.UUID, state flow.State, _ *uuid.UUID, _ flow.UI) error {
			updateCalledWith = state
			return nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, token)
	if err != nil {
		t.Fatalf("SubmitFlow returned unexpected error: %v", err)
	}
	if !activator.called {
		t.Error("SubmitFlow: UpdateIdentityState was not called")
	}
	if activator.calledIdentityID != identityID {
		t.Errorf("SubmitFlow: UpdateIdentityState called with identityID=%s, want %s", activator.calledIdentityID, identityID)
	}
	if activator.calledState != identity.StateActive {
		t.Errorf("SubmitFlow: UpdateIdentityState called with state=%q, want %q", activator.calledState, identity.StateActive)
	}
	if updateCalledWith != flow.StateSuccess {
		t.Errorf("SubmitFlow: flow.Update called with state=%q, want %q", updateCalledWith, flow.StateSuccess)
	}
}

func TestSubmitFlow_WrongToken_FlowMarkedFailed(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	f := buildPendingVerificationFlow(tenantID, identityID, "correct-token")

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, "wrong-token")
	if err == nil {
		t.Fatal("SubmitFlow: expected error for wrong token, got nil")
	}
	if activator.called {
		t.Error("SubmitFlow: UpdateIdentityState should NOT be called on wrong token")
	}
	if store.lastUpdateStateState != flow.StateFailed {
		t.Errorf("SubmitFlow: UpdateState called with %q, want %q", store.lastUpdateStateState, flow.StateFailed)
	}
}

func TestSubmitFlow_FlowNotFound_WrapsErrNotFound(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	flowID := uuid.New()

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, flow.ErrNotFound
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, flowID, "any-token")
	if err == nil {
		t.Fatal("SubmitFlow: expected error for missing flow")
	}
	if !errors.Is(err, flow.ErrNotFound) {
		t.Errorf("SubmitFlow: error should wrap flow.ErrNotFound; got %v", err)
	}
}

func TestSubmitFlow_NonPendingFlow_ReturnsError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	f := buildPendingVerificationFlow(tenantID, identityID, "some-token")
	f.State = flow.StateSuccess // already completed

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, "some-token")
	if err == nil {
		t.Fatal("SubmitFlow: expected error for non-pending flow")
	}
}

func TestSubmitFlow_WrongFlowType_ReturnsError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	f := buildPendingVerificationFlow(tenantID, identityID, "some-token")
	f.Type = flow.TypeLogin // wrong type

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, "some-token")
	if err == nil {
		t.Fatal("SubmitFlow: expected error for wrong flow type")
	}
}

func TestSubmitFlow_NoIdentityID_ReturnsError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()

	f := &flow.Flow{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Type:       flow.TypeVerification,
		State:      flow.StatePending,
		IdentityID: nil, // intentionally absent
		UI: flow.UI{
			Method: "POST",
			Internal: &flow.UIInternal{
				Phase:             "verify",
				VerificationToken: "some-token",
			},
		},
	}

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, "some-token")
	if err == nil {
		t.Fatal("SubmitFlow: expected error when flow has no identity_id")
	}
}

func TestSubmitFlow_NoTokenInFlowInternal_ReturnsError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	f := buildPendingVerificationFlow(tenantID, identityID, "" /* empty token */)

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, "any-token")
	if err == nil {
		t.Fatal("SubmitFlow: expected error when flow has no stored token")
	}
}

func TestSubmitFlow_NilUIInternal_ReturnsError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	f := buildPendingVerificationFlow(tenantID, identityID, "some-token")
	f.UI.Internal = nil // strip Internal entirely

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, "some-token")
	if err == nil {
		t.Fatal("SubmitFlow: expected error when UI.Internal is nil")
	}
}

func TestSubmitFlow_IdentityUpdateError_ReturnsError(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()
	token := "correct-token"
	activateErr := errors.New("identity: update state failed")

	f := buildPendingVerificationFlow(tenantID, identityID, token)

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{
		updateStateFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return activateErr
		},
	}
	engine := New(store, activator)

	err := engine.SubmitFlow(context.Background(), tenantID, f.ID, token)
	if err == nil {
		t.Fatal("SubmitFlow: expected error when identity activation fails")
	}
	if !errors.Is(err, activateErr) {
		t.Errorf("SubmitFlow: error chain should wrap activateErr; got %v", err)
	}
}

// ---------------------------------------------------------------------------
// generateToken tests
// ---------------------------------------------------------------------------

func TestGenerateToken_NonEmpty(t *testing.T) {
	t.Parallel()
	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}
	if tok == "" {
		t.Error("generateToken returned empty string")
	}
}

func TestGenerateToken_ValidBase64URL(t *testing.T) {
	t.Parallel()
	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}
	// RawURLEncoding produces ceil(n*4/3) chars for n bytes; 32 bytes → 43 chars.
	const wantLen = 43
	if len(tok) != wantLen {
		t.Errorf("generateToken: len=%d, want %d", len(tok), wantLen)
	}
	// Verify it can be decoded back to 32 bytes.
	decoded, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Errorf("generateToken: returned non-base64url string: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("generateToken: decoded len=%d, want 32", len(decoded))
	}
}

func TestGenerateToken_UniqueEachCall(t *testing.T) {
	t.Parallel()
	const n = 100
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		tok, err := generateToken()
		if err != nil {
			t.Fatalf("generateToken[%d] returned error: %v", i, err)
		}
		if seen[tok] {
			t.Fatalf("generateToken returned duplicate token after %d calls", i)
		}
		seen[tok] = true
	}
}

// ---------------------------------------------------------------------------
// Edge-case / regression tests
// ---------------------------------------------------------------------------

func TestSubmitFlow_SuccessIdentityActivatedWithCorrectTenantID(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()
	token := "exact-token-xyz"

	f := buildPendingVerificationFlow(tenantID, identityID, token)

	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	if err := engine.SubmitFlow(context.Background(), tenantID, f.ID, token); err != nil {
		t.Fatalf("SubmitFlow unexpected error: %v", err)
	}
	if activator.calledTenantID != tenantID {
		t.Errorf("UpdateIdentityState tenantID=%s, want %s", activator.calledTenantID, tenantID)
	}
}

func TestInitFlow_UIInternalPhaseIsVerify(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	var capturedUI flow.UI
	store := &fakeFlowStore{
		createFn: func(_ context.Context, _ uuid.UUID, _ flow.Type, ui flow.UI, _ time.Time) (*flow.Flow, error) {
			capturedUI = ui
			return &flow.Flow{
				ID:       uuid.New(),
				TenantID: tenantID,
				Type:     flow.TypeVerification,
				State:    flow.StatePending,
				UI:       ui,
			}, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	if _, _, err := engine.InitFlow(context.Background(), tenantID, identityID); err != nil {
		t.Fatalf("InitFlow error: %v", err)
	}
	if capturedUI.Internal == nil {
		t.Fatal("UI.Internal is nil")
	}
	if capturedUI.Internal.Phase != "verify" {
		t.Errorf("UI.Internal.Phase = %q, want %q", capturedUI.Internal.Phase, "verify")
	}
}

func TestInitFlow_FlowTypeIsVerification(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()

	var capturedType flow.Type
	store := &fakeFlowStore{
		createFn: func(_ context.Context, _ uuid.UUID, ft flow.Type, ui flow.UI, _ time.Time) (*flow.Flow, error) {
			capturedType = ft
			return &flow.Flow{
				ID:       uuid.New(),
				TenantID: tenantID,
				Type:     ft,
				State:    flow.StatePending,
				UI:       ui,
			}, nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	if _, _, err := engine.InitFlow(context.Background(), tenantID, identityID); err != nil {
		t.Fatalf("InitFlow error: %v", err)
	}
	if capturedType != flow.TypeVerification {
		t.Errorf("Create called with flowType=%q, want %q", capturedType, flow.TypeVerification)
	}
}

func TestSubmitFlow_SuccessTokenClearedInFinalUpdate(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	identityID := uuid.New()
	token := "clear-me-token"

	f := buildPendingVerificationFlow(tenantID, identityID, token)

	var capturedUI flow.UI
	store := &fakeFlowStore{
		getFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
		updateFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ flow.State, _ *uuid.UUID, ui flow.UI) error {
			capturedUI = ui
			return nil
		},
	}
	activator := &fakeIdentityActivator{}
	engine := New(store, activator)

	if err := engine.SubmitFlow(context.Background(), tenantID, f.ID, token); err != nil {
		t.Fatalf("SubmitFlow unexpected error: %v", err)
	}
	// After a successful verification the token must NOT appear in the stored UI.
	if capturedUI.Internal != nil && capturedUI.Internal.VerificationToken != "" {
		t.Error("SubmitFlow: VerificationToken was not cleared from flow UI on success")
	}
}
