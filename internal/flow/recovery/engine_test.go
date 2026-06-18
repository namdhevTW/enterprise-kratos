package recovery

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/enterprise-idp/idpd/internal/session"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Fake implementations of the four dependency interfaces
// ---------------------------------------------------------------------------

// fakeFlowStore records calls and returns controlled responses.
type fakeFlowStore struct {
	// createFn is called by Create; if nil, returns a minimal pending flow.
	createFn func(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error)
	// getFn is called by Get; if nil, returns errFlowGetNil.
	getFn func(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	// updateFn is called by Update.
	updateFn func(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error
	// updateStateFn is called by UpdateState.
	updateStateFn func(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State) error

	// recorded calls (for assertion)
	updateCalls      []fakeUpdateCall
	updateStateCalls []fakeUpdateStateCall
}

type fakeUpdateCall struct {
	tenantID   uuid.UUID
	flowID     uuid.UUID
	state      flow.State
	identityID *uuid.UUID
	ui         flow.UI
}

type fakeUpdateStateCall struct {
	tenantID uuid.UUID
	flowID   uuid.UUID
	state    flow.State
}

func (s *fakeFlowStore) Create(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error) {
	if s.createFn != nil {
		return s.createFn(ctx, tenantID, flowType, ui, expiresAt)
	}
	return &flow.Flow{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Type:      flowType,
		State:     flow.StatePending,
		UI:        ui,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *fakeFlowStore) Get(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	if s.getFn != nil {
		return s.getFn(ctx, tenantID, flowID)
	}
	return nil, fmt.Errorf("fakeFlowStore.Get: no getFn configured")
}

func (s *fakeFlowStore) Update(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error {
	s.updateCalls = append(s.updateCalls, fakeUpdateCall{
		tenantID:   tenantID,
		flowID:     flowID,
		state:      state,
		identityID: identityID,
		ui:         ui,
	})
	if s.updateFn != nil {
		return s.updateFn(ctx, tenantID, flowID, state, identityID, ui)
	}
	return nil
}

func (s *fakeFlowStore) UpdateState(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State) error {
	s.updateStateCalls = append(s.updateStateCalls, fakeUpdateStateCall{
		tenantID: tenantID,
		flowID:   flowID,
		state:    state,
	})
	if s.updateStateFn != nil {
		return s.updateStateFn(ctx, tenantID, flowID, state)
	}
	return nil
}

// fakePolicyGetter returns a controlled policy or error.
type fakePolicyGetter struct {
	pol *policy.FlowPolicy
	err error
}

func (g *fakePolicyGetter) Get(_ context.Context, _ uuid.UUID) (*policy.FlowPolicy, error) {
	return g.pol, g.err
}

// fakeIdentityFinder records calls and returns controlled responses.
type fakeIdentityFinder struct {
	getIdentityIDFn      func(ctx context.Context, tenantID uuid.UUID, identifier string) (uuid.UUID, error)
	updateIdentityStateFn func(ctx context.Context, tenantID, identityID uuid.UUID, state string) error

	updateStateCalls []fakeIdentityStateCall
}

type fakeIdentityStateCall struct {
	tenantID   uuid.UUID
	identityID uuid.UUID
	state      string
}

func (f *fakeIdentityFinder) GetIdentityIDByIdentifier(ctx context.Context, tenantID uuid.UUID, identifier string) (uuid.UUID, error) {
	if f.getIdentityIDFn != nil {
		return f.getIdentityIDFn(ctx, tenantID, identifier)
	}
	return uuid.Nil, fmt.Errorf("fakeIdentityFinder: no getIdentityIDFn configured")
}

func (f *fakeIdentityFinder) UpdateIdentityState(ctx context.Context, tenantID, identityID uuid.UUID, state string) error {
	f.updateStateCalls = append(f.updateStateCalls, fakeIdentityStateCall{
		tenantID:   tenantID,
		identityID: identityID,
		state:      state,
	})
	if f.updateIdentityStateFn != nil {
		return f.updateIdentityStateFn(ctx, tenantID, identityID, state)
	}
	return nil
}

// fakeSessionCreator returns a controlled session or error.
type fakeSessionCreator struct {
	createFn func(ctx context.Context, tenantID, identityID uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error)
}

func (c *fakeSessionCreator) Create(ctx context.Context, tenantID, identityID uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error) {
	if c.createFn != nil {
		return c.createFn(ctx, tenantID, identityID, aal, amr, ttl)
	}
	return &session.Session{
		ID:         uuid.New(),
		TenantID:   tenantID,
		IdentityID: identityID,
		Token:      "tok",
		AAL:        aal,
		AMR:        amr,
		Active:     true,
		ExpiresAt:  time.Now().Add(ttl),
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func enabledPolicy() *policy.FlowPolicy {
	return &policy.FlowPolicy{
		Recovery: policy.RecoveryPolicy{
			Enabled:        true,
			AllowedMethods: []string{"link"},
		},
	}
}

func disabledPolicy() *policy.FlowPolicy {
	return &policy.FlowPolicy{
		Recovery: policy.RecoveryPolicy{
			Enabled: false,
		},
	}
}

// pendingRecoveryFlow returns a minimal flow in the pending/request phase.
func pendingRecoveryFlow(tenantID, flowID uuid.UUID) *flow.Flow {
	return &flow.Flow{
		ID:       flowID,
		TenantID: tenantID,
		Type:     flow.TypeRecovery,
		State:    flow.StatePending,
		UI: flow.UI{
			Method:   "POST",
			Internal: &flow.UIInternal{Phase: "request"},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
}

// pendingLinkFlow returns a flow in the pending_link phase with a known token and identity.
func pendingLinkFlow(tenantID, flowID, identityID uuid.UUID, token string) *flow.Flow {
	return &flow.Flow{
		ID:       flowID,
		TenantID: tenantID,
		Type:     flow.TypeRecovery,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			Internal: &flow.UIInternal{
				Phase:              "pending_link",
				RecoveryToken:      token,
				RecoveryIdentityID: identityID.String(),
			},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
}

// ---------------------------------------------------------------------------
// InitFlow tests
// ---------------------------------------------------------------------------

func TestInitFlow_Success(t *testing.T) {
	tenantID := uuid.New()
	flows := &fakeFlowStore{}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	f, err := eng.InitFlow(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("InitFlow: unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("InitFlow: returned nil flow")
	}
	if f.Type != flow.TypeRecovery {
		t.Errorf("InitFlow: flow type = %s, want %s", f.Type, flow.TypeRecovery)
	}
	if f.State != flow.StatePending {
		t.Errorf("InitFlow: flow state = %s, want %s", f.State, flow.StatePending)
	}
	if f.TenantID != tenantID {
		t.Errorf("InitFlow: tenantID = %s, want %s", f.TenantID, tenantID)
	}
	if f.UI.Internal == nil || f.UI.Internal.Phase != "request" {
		t.Errorf("InitFlow: UI.Internal.Phase = %q, want %q", f.UI.Internal.Phase, "request")
	}
	if len(f.UI.Nodes) == 0 {
		t.Error("InitFlow: expected at least one UI node")
	}
}

func TestInitFlow_RecoveryDisabled(t *testing.T) {
	tenantID := uuid.New()
	flows := &fakeFlowStore{}
	pols := &fakePolicyGetter{pol: disabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.InitFlow(context.Background(), tenantID)
	if err == nil {
		t.Fatal("InitFlow: expected error when recovery disabled, got nil")
	}
}

func TestInitFlow_PolicyError(t *testing.T) {
	tenantID := uuid.New()
	policyErr := errors.New("db unavailable")
	flows := &fakeFlowStore{}
	pols := &fakePolicyGetter{err: policyErr}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.InitFlow(context.Background(), tenantID)
	if err == nil {
		t.Fatal("InitFlow: expected error from policy, got nil")
	}
	if !errors.Is(err, policyErr) {
		t.Errorf("InitFlow: error = %v, want to wrap %v", err, policyErr)
	}
}

func TestInitFlow_FlowsCreateError(t *testing.T) {
	tenantID := uuid.New()
	createErr := errors.New("insert failed")
	flows := &fakeFlowStore{
		createFn: func(_ context.Context, _ uuid.UUID, _ flow.Type, _ flow.UI, _ time.Time) (*flow.Flow, error) {
			return nil, createErr
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.InitFlow(context.Background(), tenantID)
	if err == nil {
		t.Fatal("InitFlow: expected error from flows.Create, got nil")
	}
	if !errors.Is(err, createErr) {
		t.Errorf("InitFlow: error = %v, want to wrap %v", err, createErr)
	}
}

// ---------------------------------------------------------------------------
// GetFlow tests
// ---------------------------------------------------------------------------

func TestGetFlow_DelegatesToStore(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	expected := pendingRecoveryFlow(tenantID, flowID)

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, tid, fid uuid.UUID) (*flow.Flow, error) {
			if tid != tenantID || fid != flowID {
				t.Errorf("GetFlow: unexpected IDs tid=%s fid=%s", tid, fid)
			}
			return expected, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	got, err := eng.GetFlow(context.Background(), tenantID, flowID)
	if err != nil {
		t.Fatalf("GetFlow: unexpected error: %v", err)
	}
	if got != expected {
		t.Errorf("GetFlow: returned wrong flow")
	}
}

func TestGetFlow_PropagatesError(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	getErr := fmt.Errorf("flow.Get %s: %w", flowID, flow.ErrNotFound)

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return nil, getErr
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.GetFlow(context.Background(), tenantID, flowID)
	if err == nil {
		t.Fatal("GetFlow: expected error, got nil")
	}
	if !errors.Is(err, flow.ErrNotFound) {
		t.Errorf("GetFlow: error = %v, want to wrap flow.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// RequestRecovery tests
// ---------------------------------------------------------------------------

func TestRequestRecovery_Success_IdentityFound(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingRecoveryFlow(tenantID, flowID), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{
		getIdentityIDFn: func(_ context.Context, _ uuid.UUID, _ string) (uuid.UUID, error) {
			return identityID, nil
		},
	}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	token, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "user@example.com")
	if err != nil {
		t.Fatalf("RequestRecovery: unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("RequestRecovery: expected non-empty token")
	}

	// Verify flow was updated with identity and token.
	if len(flows.updateCalls) == 0 {
		t.Fatal("RequestRecovery: expected flows.Update to be called")
	}
	call := flows.updateCalls[0]
	if call.identityID == nil || *call.identityID != identityID {
		t.Errorf("RequestRecovery: Update called with identityID=%v, want %s", call.identityID, identityID)
	}
	if call.state != flow.StatePending {
		t.Errorf("RequestRecovery: Update state = %s, want %s", call.state, flow.StatePending)
	}
	if call.ui.Internal == nil {
		t.Fatal("RequestRecovery: Update called with nil UI.Internal")
	}
	if call.ui.Internal.Phase != "pending_link" {
		t.Errorf("RequestRecovery: UI.Internal.Phase = %q, want %q", call.ui.Internal.Phase, "pending_link")
	}
	if call.ui.Internal.RecoveryToken != token {
		t.Errorf("RequestRecovery: UI.Internal.RecoveryToken = %q, want %q", call.ui.Internal.RecoveryToken, token)
	}
	if call.ui.Internal.RecoveryIdentityID != identityID.String() {
		t.Errorf("RequestRecovery: UI.Internal.RecoveryIdentityID = %q, want %q", call.ui.Internal.RecoveryIdentityID, identityID.String())
	}
}

func TestRequestRecovery_AntiEnumeration_IdentityNotFound(t *testing.T) {
	// When the identity does not exist the engine MUST still return a token
	// (same code path, no error) to prevent user enumeration.
	tenantID := uuid.New()
	flowID := uuid.New()

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingRecoveryFlow(tenantID, flowID), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{
		getIdentityIDFn: func(_ context.Context, _ uuid.UUID, _ string) (uuid.UUID, error) {
			return uuid.Nil, fmt.Errorf("identity.GetIdentityIDByIdentifier %q: %w", "nobody@example.com", identity.ErrNotFound)
		},
	}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	token, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "nobody@example.com")
	if err != nil {
		t.Fatalf("RequestRecovery (anti-enum): unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("RequestRecovery (anti-enum): expected non-empty token even when identity not found")
	}

	// RecoveryIdentityID must be empty (no identity was resolved).
	if len(flows.updateCalls) == 0 {
		t.Fatal("RequestRecovery (anti-enum): expected flows.Update to be called")
	}
	call := flows.updateCalls[0]
	if call.ui.Internal == nil {
		t.Fatal("RequestRecovery (anti-enum): Update called with nil UI.Internal")
	}
	if call.ui.Internal.RecoveryIdentityID != "" {
		t.Errorf("RequestRecovery (anti-enum): RecoveryIdentityID = %q, want empty string", call.ui.Internal.RecoveryIdentityID)
	}
	if call.ui.Internal.RecoveryToken == "" {
		t.Error("RequestRecovery (anti-enum): RecoveryToken should not be empty")
	}
}

func TestRequestRecovery_PolicyError(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	policyErr := errors.New("policy store down")

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingRecoveryFlow(tenantID, flowID), nil
		},
	}
	pols := &fakePolicyGetter{err: policyErr}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "user@example.com")
	if err == nil {
		t.Fatal("RequestRecovery: expected policy error, got nil")
	}
	if !errors.Is(err, policyErr) {
		t.Errorf("RequestRecovery: error = %v, want to wrap %v", err, policyErr)
	}
}

func TestRequestRecovery_PolicyDisabled(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingRecoveryFlow(tenantID, flowID), nil
		},
	}
	pols := &fakePolicyGetter{pol: disabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "user@example.com")
	if err == nil {
		t.Fatal("RequestRecovery: expected error when recovery disabled, got nil")
	}
}

func TestRequestRecovery_FlowNotPending(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			f := pendingRecoveryFlow(tenantID, flowID)
			f.State = flow.StateSuccess
			return f, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "user@example.com")
	if err == nil {
		t.Fatal("RequestRecovery: expected error for non-pending flow, got nil")
	}
}

func TestRequestRecovery_WrongFlowType(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			f := pendingRecoveryFlow(tenantID, flowID)
			f.Type = flow.TypeLogin
			return f, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "user@example.com")
	if err == nil {
		t.Fatal("RequestRecovery: expected error for wrong flow type, got nil")
	}
}

func TestRequestRecovery_FlowsGetError(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	getErr := fmt.Errorf("flow.Get %s: %w", flowID, flow.ErrNotFound)

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return nil, getErr
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "user@example.com")
	if err == nil {
		t.Fatal("RequestRecovery: expected error from flows.Get, got nil")
	}
	if !errors.Is(err, flow.ErrNotFound) {
		t.Errorf("RequestRecovery: error = %v, want to wrap flow.ErrNotFound", err)
	}
}

func TestRequestRecovery_FlowsUpdateError(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	updateErr := errors.New("update failed")

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingRecoveryFlow(tenantID, flowID), nil
		},
		updateFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ flow.State, _ *uuid.UUID, _ flow.UI) error {
			return updateErr
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{
		getIdentityIDFn: func(_ context.Context, _ uuid.UUID, _ string) (uuid.UUID, error) {
			return identityID, nil
		},
	}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, err := eng.RequestRecovery(context.Background(), tenantID, flowID, "user@example.com")
	if err == nil {
		t.Fatal("RequestRecovery: expected error from flows.Update, got nil")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("RequestRecovery: error = %v, want to wrap %v", err, updateErr)
	}
}

// ---------------------------------------------------------------------------
// UseToken tests
// ---------------------------------------------------------------------------

func TestUseToken_Success(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const plainToken = "valid-recovery-token-abc123"

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingLinkFlow(tenantID, flowID, identityID, plainToken), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	gotSess, gotIdentityID, err := eng.UseToken(context.Background(), tenantID, flowID, plainToken)
	if err != nil {
		t.Fatalf("UseToken: unexpected error: %v", err)
	}
	if gotSess == nil {
		t.Fatal("UseToken: expected non-nil session")
	}
	if gotIdentityID != identityID {
		t.Errorf("UseToken: identityID = %s, want %s", gotIdentityID, identityID)
	}

	// Identity must have been activated.
	if len(ids.updateStateCalls) == 0 {
		t.Fatal("UseToken: expected identities.UpdateIdentityState to be called")
	}
	stateCall := ids.updateStateCalls[0]
	if stateCall.identityID != identityID {
		t.Errorf("UseToken: UpdateIdentityState identityID = %s, want %s", stateCall.identityID, identityID)
	}
	if stateCall.state != identity.StateActive {
		t.Errorf("UseToken: UpdateIdentityState state = %q, want %q", stateCall.state, identity.StateActive)
	}

	// Flow must have been marked success.
	if len(flows.updateCalls) == 0 {
		t.Fatal("UseToken: expected flows.Update to be called")
	}
	updateCall := flows.updateCalls[0]
	if updateCall.state != flow.StateSuccess {
		t.Errorf("UseToken: flows.Update state = %s, want %s", updateCall.state, flow.StateSuccess)
	}
}

func TestUseToken_WrongToken(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "stored-token-xyz"
	const submittedToken = "wrong-token-abc"

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingLinkFlow(tenantID, flowID, identityID, storedToken), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, submittedToken)
	if err == nil {
		t.Fatal("UseToken: expected error for wrong token, got nil")
	}

	// Flow must be failed via UpdateState.
	if len(flows.updateStateCalls) == 0 {
		t.Fatal("UseToken: expected flows.UpdateState(failed) to be called")
	}
	if flows.updateStateCalls[0].state != flow.StateFailed {
		t.Errorf("UseToken: UpdateState = %s, want %s", flows.updateStateCalls[0].state, flow.StateFailed)
	}
}

func TestUseToken_EmptyRecoveryIdentityID_AntiEnumeration(t *testing.T) {
	// Flow has a valid token but RecoveryIdentityID is empty (identity was not
	// found during RequestRecovery). UseToken must fail without revealing that
	// no identity exists.
	tenantID := uuid.New()
	flowID := uuid.New()
	const storedToken = "valid-token-no-identity"

	// Build the flow manually with an empty RecoveryIdentityID.
	antiEnumFlow := &flow.Flow{
		ID:       flowID,
		TenantID: tenantID,
		Type:     flow.TypeRecovery,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			Internal: &flow.UIInternal{
				Phase:              "pending_link",
				RecoveryToken:      storedToken,
				RecoveryIdentityID: "", // intentionally empty
			},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return antiEnumFlow, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err == nil {
		t.Fatal("UseToken: expected error for empty RecoveryIdentityID, got nil")
	}

	// Flow must be failed.
	if len(flows.updateStateCalls) == 0 {
		t.Fatal("UseToken: expected flows.UpdateState(failed) to be called")
	}
	if flows.updateStateCalls[0].state != flow.StateFailed {
		t.Errorf("UseToken: UpdateState = %s, want %s", flows.updateStateCalls[0].state, flow.StateFailed)
	}
}

func TestUseToken_InvalidIdentityIDUUID(t *testing.T) {
	// RecoveryIdentityID is non-empty but not a valid UUID.
	tenantID := uuid.New()
	flowID := uuid.New()
	const storedToken = "valid-token-bad-uuid"

	badFlow := &flow.Flow{
		ID:       flowID,
		TenantID: tenantID,
		Type:     flow.TypeRecovery,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			Internal: &flow.UIInternal{
				Phase:              "pending_link",
				RecoveryToken:      storedToken,
				RecoveryIdentityID: "not-a-valid-uuid",
			},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return badFlow, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err == nil {
		t.Fatal("UseToken: expected error for invalid identity UUID, got nil")
	}
}

func TestUseToken_IdentityUpdateError(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "valid-token-identity-err"
	updateErr := errors.New("identity update failed")

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingLinkFlow(tenantID, flowID, identityID, storedToken), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{
		updateIdentityStateFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return updateErr
		},
	}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err == nil {
		t.Fatal("UseToken: expected error from identity update, got nil")
	}
	if !errors.Is(err, updateErr) {
		t.Errorf("UseToken: error = %v, want to wrap %v", err, updateErr)
	}
}

func TestUseToken_SessionCreateError(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "valid-token-session-err"
	sessErr := errors.New("session store down")

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingLinkFlow(tenantID, flowID, identityID, storedToken), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{
		createFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ time.Duration) (*session.Session, error) {
			return nil, sessErr
		},
	}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err == nil {
		t.Fatal("UseToken: expected error from session create, got nil")
	}
	if !errors.Is(err, sessErr) {
		t.Errorf("UseToken: error = %v, want to wrap %v", err, sessErr)
	}
}

func TestUseToken_FlowNotPending(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "valid-token"

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			f := pendingLinkFlow(tenantID, flowID, identityID, storedToken)
			f.State = flow.StateSuccess
			return f, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err == nil {
		t.Fatal("UseToken: expected error for non-pending flow, got nil")
	}
}

func TestUseToken_WrongFlowType(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "valid-token"

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			f := pendingLinkFlow(tenantID, flowID, identityID, storedToken)
			f.Type = flow.TypeVerification
			return f, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err == nil {
		t.Fatal("UseToken: expected error for wrong flow type, got nil")
	}
}

func TestUseToken_NoPendingLinkPhase(t *testing.T) {
	// Flow is pending + recovery type but NOT in "pending_link" phase.
	tenantID := uuid.New()
	flowID := uuid.New()

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingRecoveryFlow(tenantID, flowID), nil // phase = "request"
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, "any-token")
	if err == nil {
		t.Fatal("UseToken: expected error when not in pending_link phase, got nil")
	}
}

func TestUseToken_NoTokenStored(t *testing.T) {
	// Flow is in pending_link phase but RecoveryToken is empty.
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()

	noTokenFlow := &flow.Flow{
		ID:       flowID,
		TenantID: tenantID,
		Type:     flow.TypeRecovery,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			Internal: &flow.UIInternal{
				Phase:              "pending_link",
				RecoveryToken:      "", // intentionally empty
				RecoveryIdentityID: identityID.String(),
			},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return noTokenFlow, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, "any-token")
	if err == nil {
		t.Fatal("UseToken: expected error when no token stored in flow, got nil")
	}
}

func TestUseToken_FlowsGetError(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	getErr := fmt.Errorf("flow.Get %s: %w", flowID, flow.ErrNotFound)

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return nil, getErr
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, "any-token")
	if err == nil {
		t.Fatal("UseToken: expected error from flows.Get, got nil")
	}
	if !errors.Is(err, flow.ErrNotFound) {
		t.Errorf("UseToken: error = %v, want to wrap flow.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// UseToken — session property assertions
// ---------------------------------------------------------------------------

func TestUseToken_SessionHasRecoveryAMR(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "amr-check-token"

	var capturedAMR []string

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingLinkFlow(tenantID, flowID, identityID, storedToken), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{
		createFn: func(_ context.Context, tid, iid uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error) {
			capturedAMR = amr
			return &session.Session{
				ID:         uuid.New(),
				TenantID:   tid,
				IdentityID: iid,
				Token:      "tok",
				AAL:        aal,
				AMR:        amr,
				Active:     true,
				ExpiresAt:  time.Now().Add(ttl),
			}, nil
		},
	}

	eng := New(flows, pols, ids, sess)
	gotSess, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err != nil {
		t.Fatalf("UseToken: unexpected error: %v", err)
	}

	// AMR from the create call must include "recovery".
	recoveryInAMR := false
	for _, m := range capturedAMR {
		if m == "recovery" {
			recoveryInAMR = true
			break
		}
	}
	if !recoveryInAMR {
		t.Errorf("UseToken: sessions.Create AMR = %v, want to include %q", capturedAMR, "recovery")
	}

	// The returned session must also carry "recovery" in its AMR slice.
	recoveryInSessAMR := false
	for _, m := range gotSess.AMR {
		if m == "recovery" {
			recoveryInSessAMR = true
			break
		}
	}
	if !recoveryInSessAMR {
		t.Errorf("UseToken: session.AMR = %v, want to include %q", gotSess.AMR, "recovery")
	}
}

func TestUseToken_SessionTTLIs15Minutes(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "ttl-check-token"

	var capturedTTL time.Duration

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingLinkFlow(tenantID, flowID, identityID, storedToken), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{
		createFn: func(_ context.Context, tid, iid uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error) {
			capturedTTL = ttl
			return &session.Session{
				ID:         uuid.New(),
				TenantID:   tid,
				IdentityID: iid,
				Token:      "tok",
				AAL:        aal,
				AMR:        amr,
				Active:     true,
				ExpiresAt:  time.Now().Add(ttl),
			}, nil
		},
	}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err != nil {
		t.Fatalf("UseToken: unexpected error: %v", err)
	}

	if capturedTTL != recoverySessionTTL {
		t.Errorf("UseToken: sessions.Create TTL = %v, want %v (recoverySessionTTL)", capturedTTL, recoverySessionTTL)
	}
	if recoverySessionTTL != 15*time.Minute {
		t.Errorf("recoverySessionTTL constant = %v, want 15m", recoverySessionTTL)
	}
}

func TestUseToken_SessionIdentityMatchesFlow(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	const storedToken = "identity-match-token"

	var capturedIdentityID uuid.UUID

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return pendingLinkFlow(tenantID, flowID, identityID, storedToken), nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{
		createFn: func(_ context.Context, tid, iid uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error) {
			capturedIdentityID = iid
			return &session.Session{
				ID:         uuid.New(),
				TenantID:   tid,
				IdentityID: iid,
				Token:      "tok",
				AAL:        aal,
				AMR:        amr,
				Active:     true,
				ExpiresAt:  time.Now().Add(ttl),
			}, nil
		},
	}

	eng := New(flows, pols, ids, sess)
	gotSess, gotIdentityID, err := eng.UseToken(context.Background(), tenantID, flowID, storedToken)
	if err != nil {
		t.Fatalf("UseToken: unexpected error: %v", err)
	}
	if capturedIdentityID != identityID {
		t.Errorf("UseToken: sessions.Create identityID = %s, want %s", capturedIdentityID, identityID)
	}
	if gotSess.IdentityID != identityID {
		t.Errorf("UseToken: session.IdentityID = %s, want %s", gotSess.IdentityID, identityID)
	}
	if gotIdentityID != identityID {
		t.Errorf("UseToken: returned identityID = %s, want %s", gotIdentityID, identityID)
	}
}

// ---------------------------------------------------------------------------
// UseToken — nil Internal guard
// ---------------------------------------------------------------------------

func TestUseToken_NilInternal(t *testing.T) {
	// If UI.Internal is nil entirely the engine must fail gracefully.
	tenantID := uuid.New()
	flowID := uuid.New()

	nilInternalFlow := &flow.Flow{
		ID:        flowID,
		TenantID:  tenantID,
		Type:      flow.TypeRecovery,
		State:     flow.StatePending,
		UI:        flow.UI{Method: "POST"},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	flows := &fakeFlowStore{
		getFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return nilInternalFlow, nil
		},
	}
	pols := &fakePolicyGetter{pol: enabledPolicy()}
	ids := &fakeIdentityFinder{}
	sess := &fakeSessionCreator{}

	eng := New(flows, pols, ids, sess)
	_, _, err := eng.UseToken(context.Background(), tenantID, flowID, "any-token")
	if err == nil {
		t.Fatal("UseToken: expected error for nil UI.Internal, got nil")
	}
}
