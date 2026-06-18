package settings

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
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// stubFlowStorer is an in-memory flowStorer for tests.
type stubFlowStorer struct {
	flows map[string]*flow.Flow // key: tenantID+":"+flowID

	createErr error
	getErr    error
	updateErr error

	createCalls int
	updateCalls int
}

func newStubFlowStorer() *stubFlowStorer {
	return &stubFlowStorer{flows: make(map[string]*flow.Flow)}
}

func flowKey(tenantID, flowID uuid.UUID) string {
	return tenantID.String() + ":" + flowID.String()
}

func (s *stubFlowStorer) Create(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error) {
	s.createCalls++
	if s.createErr != nil {
		return nil, s.createErr
	}
	f := &flow.Flow{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Type:      flowType,
		State:     flow.StatePending,
		UI:        ui,
		ExpiresAt: expiresAt,
	}
	s.flows[flowKey(tenantID, f.ID)] = f
	return f, nil
}

func (s *stubFlowStorer) Get(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	f, ok := s.flows[flowKey(tenantID, flowID)]
	if !ok {
		return nil, fmt.Errorf("stubFlowStorer.Get %s: %w", flowID, flow.ErrNotFound)
	}
	// Return a copy so mutations in tests do not affect the stored value.
	cp := *f
	return &cp, nil
}

func (s *stubFlowStorer) Update(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error {
	s.updateCalls++
	if s.updateErr != nil {
		return s.updateErr
	}
	key := flowKey(tenantID, flowID)
	f, ok := s.flows[key]
	if !ok {
		return fmt.Errorf("stubFlowStorer.Update %s: %w", flowID, flow.ErrNotFound)
	}
	f.State = state
	f.IdentityID = identityID
	f.UI = ui
	return nil
}

// stubIdentityManager is an in-memory identityManager for tests.
type stubIdentityManager struct {
	identities  map[string]*identity.Identity  // key: tenantID+":"+identityID
	credentials map[string]*identity.Credential // key: tenantID+":"+identityID+":"+credType

	getIdentityErr       error
	updateTraitsErr      error
	getByTypeErr         error
	upsertCredentialErr  error

	upsertCalls         int
	lastUpsertIdentifiers []string
	lastUpsertConfig    json.RawMessage
}

func newStubIdentityManager() *stubIdentityManager {
	return &stubIdentityManager{
		identities:  make(map[string]*identity.Identity),
		credentials: make(map[string]*identity.Credential),
	}
}

func identityKey(tenantID, identityID uuid.UUID) string {
	return tenantID.String() + ":" + identityID.String()
}

func credKey(tenantID, identityID uuid.UUID, credType string) string {
	return tenantID.String() + ":" + identityID.String() + ":" + credType
}

func (m *stubIdentityManager) setIdentity(tenantID, identityID uuid.UUID, traits json.RawMessage) {
	m.identities[identityKey(tenantID, identityID)] = &identity.Identity{
		ID:       identityID,
		TenantID: tenantID,
		Traits:   traits,
		State:    identity.StateActive,
	}
}

func (m *stubIdentityManager) setCredential(tenantID, identityID uuid.UUID, credType string, identifiers []string) {
	m.credentials[credKey(tenantID, identityID, credType)] = &identity.Credential{
		ID:          uuid.New(),
		TenantID:    tenantID,
		IdentityID:  identityID,
		Type:        credType,
		Identifiers: identifiers,
		Config:      json.RawMessage(`{}`),
	}
}

func (m *stubIdentityManager) GetIdentity(ctx context.Context, tenantID, identityID uuid.UUID) (*identity.Identity, error) {
	if m.getIdentityErr != nil {
		return nil, m.getIdentityErr
	}
	ident, ok := m.identities[identityKey(tenantID, identityID)]
	if !ok {
		return nil, fmt.Errorf("stubIdentityManager.GetIdentity %s: %w", identityID, identity.ErrNotFound)
	}
	cp := *ident
	return &cp, nil
}

func (m *stubIdentityManager) UpdateTraits(ctx context.Context, tenantID, identityID uuid.UUID, traits json.RawMessage) error {
	if m.updateTraitsErr != nil {
		return m.updateTraitsErr
	}
	key := identityKey(tenantID, identityID)
	ident, ok := m.identities[key]
	if !ok {
		return fmt.Errorf("stubIdentityManager.UpdateTraits %s: %w", identityID, identity.ErrNotFound)
	}
	ident.Traits = traits
	return nil
}

func (m *stubIdentityManager) GetByIdentityAndType(ctx context.Context, tenantID, identityID uuid.UUID, credType string) (*identity.Credential, error) {
	if m.getByTypeErr != nil {
		return nil, m.getByTypeErr
	}
	cred, ok := m.credentials[credKey(tenantID, identityID, credType)]
	if !ok {
		return nil, fmt.Errorf("stubIdentityManager.GetByIdentityAndType %s/%s: %w", identityID, credType, identity.ErrNotFound)
	}
	cp := *cred
	return &cp, nil
}

func (m *stubIdentityManager) UpsertCredential(ctx context.Context, tenantID, identityID uuid.UUID, credType string, identifiers []string, config json.RawMessage) error {
	m.upsertCalls++
	m.lastUpsertIdentifiers = identifiers
	m.lastUpsertConfig = config
	if m.upsertCredentialErr != nil {
		return m.upsertCredentialErr
	}
	return nil
}

// stubAuthnReg is a test authnReg that returns a pre-configured authenticator.
type stubAuthnReg struct {
	authn    authenticator.Authenticator
	getErr   error
}

func (r *stubAuthnReg) Get(id string) (authenticator.Authenticator, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	if r.authn != nil && r.authn.ID() == id {
		return r.authn, nil
	}
	return nil, fmt.Errorf("registry.Get %q: %w", id, authnregistry.ErrNotFound)
}

// stubPasswordAuthenticator implements authenticator.Authenticator for tests.
type stubPasswordAuthenticator struct {
	enrollResult *authenticator.EnrollResult
	enrollErr    error
}

func (a *stubPasswordAuthenticator) ID() string                      { return "password" }
func (a *stubPasswordAuthenticator) Type() authenticator.Type        { return authenticator.FirstFactor }
func (a *stubPasswordAuthenticator) StartFlow(_ context.Context, _ *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
	return &authenticator.FlowState{}, nil
}
func (a *stubPasswordAuthenticator) CompleteFlow(_ context.Context, _ *authenticator.CompleteFlowRequest) (*authenticator.AuthResult, error) {
	return &authenticator.AuthResult{}, nil
}
func (a *stubPasswordAuthenticator) Enroll(_ context.Context, _ *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
	if a.enrollErr != nil {
		return nil, a.enrollErr
	}
	return a.enrollResult, nil
}
func (a *stubPasswordAuthenticator) Unenroll(_ context.Context, _ *authenticator.UnenrollRequest) error {
	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newEngine wires up an Engine with the three provided stubs.
func newEngine(fs *stubFlowStorer, im *stubIdentityManager, ar *stubAuthnReg) *Engine {
	return New(fs, im, ar)
}

// defaultTraits returns traits JSON with a single email field.
func defaultTraits(email string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"email": email})
	return b
}

// defaultEnrollResult is the password enroll result used across password tests.
func defaultEnrollResult() *authenticator.EnrollResult {
	return &authenticator.EnrollResult{
		CredentialType:   "password",
		CredentialConfig: json.RawMessage(`{"hashed_password":"$2a$12$x"}`),
	}
}

// pendingSettingsFlow inserts a flow that is already associated with identityID.
func pendingSettingsFlow(fs *stubFlowStorer, tenantID, identityID uuid.UUID) *flow.Flow {
	f := &flow.Flow{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Type:       flow.TypeSettings,
		State:      flow.StatePending,
		IdentityID: &identityID,
		UI:         flow.UI{Method: "POST", Internal: &flow.UIInternal{Phase: "settings"}},
		ExpiresAt:  time.Now().Add(flowTTL),
	}
	fs.flows[flowKey(tenantID, f.ID)] = f
	return f
}

// ---------------------------------------------------------------------------
// InitFlow tests
// ---------------------------------------------------------------------------

func TestInitFlow_Success(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))

	ar := &stubAuthnReg{}
	eng := newEngine(fs, im, ar)

	f, err := eng.InitFlow(context.Background(), tenantID, identityID)
	if err != nil {
		t.Fatalf("InitFlow: unexpected error: %v", err)
	}
	if f == nil {
		t.Fatal("InitFlow: returned nil flow")
	}
	if f.Type != flow.TypeSettings {
		t.Errorf("InitFlow: Type = %q, want %q", f.Type, flow.TypeSettings)
	}
	if f.State != flow.StatePending {
		t.Errorf("InitFlow: State = %q, want %q", f.State, flow.StatePending)
	}
	if f.IdentityID == nil || *f.IdentityID != identityID {
		t.Errorf("InitFlow: IdentityID = %v, want %s", f.IdentityID, identityID)
	}
	// Create + Update must both be called.
	if fs.createCalls != 1 {
		t.Errorf("InitFlow: flows.Create called %d times, want 1", fs.createCalls)
	}
	if fs.updateCalls != 1 {
		t.Errorf("InitFlow: flows.Update called %d times, want 1", fs.updateCalls)
	}
}

func TestInitFlow_PreFillsEmailFromTraits(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("prefill@example.com"))

	eng := newEngine(fs, im, &stubAuthnReg{})

	f, err := eng.InitFlow(context.Background(), tenantID, identityID)
	if err != nil {
		t.Fatalf("InitFlow: unexpected error: %v", err)
	}

	// Find the traits.email node and verify its pre-filled value.
	found := false
	for _, node := range f.UI.Nodes {
		if node.Attributes.Name == "traits.email" {
			if node.Attributes.Value != "prefill@example.com" {
				t.Errorf("InitFlow: traits.email node value = %q, want %q",
					node.Attributes.Value, "prefill@example.com")
			}
			found = true
		}
	}
	if !found {
		t.Error("InitFlow: traits.email node not found in UI")
	}
}

func TestInitFlow_GetIdentityError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.getIdentityErr = errors.New("db unavailable")

	eng := newEngine(fs, im, &stubAuthnReg{})

	_, err := eng.InitFlow(context.Background(), tenantID, identityID)
	if err == nil {
		t.Fatal("InitFlow: expected error when GetIdentity fails, got nil")
	}
	if fs.createCalls != 0 {
		t.Errorf("InitFlow: flows.Create should not be called after GetIdentity error, called %d time(s)", fs.createCalls)
	}
}

func TestInitFlow_FlowsCreateError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	fs.createErr = errors.New("db write failed")

	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))

	eng := newEngine(fs, im, &stubAuthnReg{})

	_, err := eng.InitFlow(context.Background(), tenantID, identityID)
	if err == nil {
		t.Fatal("InitFlow: expected error when flows.Create fails, got nil")
	}
	// Update must not be called if Create failed.
	if fs.updateCalls != 0 {
		t.Errorf("InitFlow: flows.Update should not be called after Create error, called %d time(s)", fs.updateCalls)
	}
}

// ---------------------------------------------------------------------------
// GetFlow tests
// ---------------------------------------------------------------------------

func TestGetFlow_Delegates(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, newStubIdentityManager(), &stubAuthnReg{})

	got, err := eng.GetFlow(context.Background(), tenantID, f.ID)
	if err != nil {
		t.Fatalf("GetFlow: unexpected error: %v", err)
	}
	if got.ID != f.ID {
		t.Errorf("GetFlow: ID = %s, want %s", got.ID, f.ID)
	}
	if got.TenantID != tenantID {
		t.Errorf("GetFlow: TenantID = %s, want %s", got.TenantID, tenantID)
	}
}

func TestGetFlow_NotFound(t *testing.T) {
	fs := newStubFlowStorer()
	eng := newEngine(fs, newStubIdentityManager(), &stubAuthnReg{})

	_, err := eng.GetFlow(context.Background(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatal("GetFlow: expected error for unknown flow, got nil")
	}
	if !errors.Is(err, flow.ErrNotFound) {
		t.Errorf("GetFlow: error = %v, want wrapping flow.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// SubmitFlow guard-rail tests
// ---------------------------------------------------------------------------

func TestSubmitFlow_NonPendingFlow(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	f := pendingSettingsFlow(fs, tenantID, identityID)
	// Mark the flow as already succeeded.
	f.State = flow.StateSuccess
	fs.flows[flowKey(tenantID, f.ID)] = f

	eng := newEngine(fs, newStubIdentityManager(), &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{})
	if err == nil {
		t.Fatal("SubmitFlow: expected error for non-pending flow, got nil")
	}
}

func TestSubmitFlow_WrongFlowType(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	// Insert a login flow (wrong type).
	loginFlow := &flow.Flow{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Type:       flow.TypeLogin,
		State:      flow.StatePending,
		IdentityID: &identityID,
		UI:         flow.UI{},
		ExpiresAt:  time.Now().Add(flowTTL),
	}
	fs.flows[flowKey(tenantID, loginFlow.ID)] = loginFlow

	eng := newEngine(fs, newStubIdentityManager(), &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, loginFlow.ID, identityID, "profile", map[string]string{})
	if err == nil {
		t.Fatal("SubmitFlow: expected error for wrong flow type, got nil")
	}
}

func TestSubmitFlow_WrongIdentity(t *testing.T) {
	tenantID := uuid.New()
	ownerID := uuid.New()
	callerID := uuid.New() // different identity trying to submit someone else's flow

	fs := newStubFlowStorer()
	f := pendingSettingsFlow(fs, tenantID, ownerID)

	eng := newEngine(fs, newStubIdentityManager(), &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, callerID, "profile", map[string]string{})
	if err == nil {
		t.Fatal("SubmitFlow: expected error when identity does not own flow, got nil")
	}
}

func TestSubmitFlow_NilIdentityID(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	f := &flow.Flow{
		ID:         uuid.New(),
		TenantID:   tenantID,
		Type:       flow.TypeSettings,
		State:      flow.StatePending,
		IdentityID: nil, // not yet associated with any identity
		UI:         flow.UI{},
		ExpiresAt:  time.Now().Add(flowTTL),
	}
	fs.flows[flowKey(tenantID, f.ID)] = f

	eng := newEngine(fs, newStubIdentityManager(), &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{})
	if err == nil {
		t.Fatal("SubmitFlow: expected error when flow has nil IdentityID, got nil")
	}
}

func TestSubmitFlow_UnknownMethod(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, im, &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "totp", map[string]string{})
	if err == nil {
		t.Fatal("SubmitFlow: expected error for unknown method, got nil")
	}
}

// ---------------------------------------------------------------------------
// submitProfile tests
// ---------------------------------------------------------------------------

func TestSubmitFlow_Profile_Success(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, im, &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{
		"traits.email": "alice-new@example.com",
		"method":       "profile",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/profile: unexpected error: %v", err)
	}

	// The flow should be marked success.
	stored := fs.flows[flowKey(tenantID, f.ID)]
	if stored.State != flow.StateSuccess {
		t.Errorf("SubmitFlow/profile: flow state = %q, want %q", stored.State, flow.StateSuccess)
	}
}

func TestSubmitFlow_Profile_TraitsEmailUpdated(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("old@example.com"))
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, im, &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{
		"traits.email": "new@example.com",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/profile: unexpected error: %v", err)
	}

	// Read back the traits from the stub.
	updated := im.identities[identityKey(tenantID, identityID)]
	var traits map[string]any
	if err := json.Unmarshal(updated.Traits, &traits); err != nil {
		t.Fatalf("SubmitFlow/profile: unmarshal traits: %v", err)
	}
	if traits["email"] != "new@example.com" {
		t.Errorf("SubmitFlow/profile: traits.email = %q, want %q", traits["email"], "new@example.com")
	}
}

func TestSubmitFlow_Profile_NonTraitsFieldsIgnored(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, im, &stubAuthnReg{})

	// "method" key must NOT be written into traits.
	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{
		"method":       "profile",
		"traits.email": "alice@example.com",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/profile: unexpected error: %v", err)
	}

	updated := im.identities[identityKey(tenantID, identityID)]
	var traits map[string]any
	if err := json.Unmarshal(updated.Traits, &traits); err != nil {
		t.Fatalf("unmarshal traits: %v", err)
	}
	if _, ok := traits["method"]; ok {
		t.Error("SubmitFlow/profile: 'method' key must not appear in traits")
	}
}

func TestSubmitFlow_Profile_GetIdentityError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	// Do not add the identity — GetIdentity inside submitProfile will fail.
	im.getIdentityErr = fmt.Errorf("identity.GetIdentity: %w", identity.ErrNotFound)
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, im, &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{
		"traits.email": "x@example.com",
	})
	if err == nil {
		t.Fatal("SubmitFlow/profile: expected error when GetIdentity fails, got nil")
	}
}

func TestSubmitFlow_Profile_UpdateTraitsError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	im.updateTraitsErr = errors.New("db write error")
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, im, &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{
		"traits.email": "new@example.com",
	})
	if err == nil {
		t.Fatal("SubmitFlow/profile: expected error when UpdateTraits fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// submitPassword tests
// ---------------------------------------------------------------------------

// passwordAuthnReg returns a stubAuthnReg pre-loaded with the stub password authenticator.
func passwordAuthnReg(enrollResult *authenticator.EnrollResult, enrollErr error) *stubAuthnReg {
	return &stubAuthnReg{
		authn: &stubPasswordAuthenticator{
			enrollResult: enrollResult,
			enrollErr:    enrollErr,
		},
	}
}

func TestSubmitFlow_Password_Success_WithExistingCredential(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	// Pre-existing password credential with its own identifiers.
	im.setCredential(tenantID, identityID, "password", []string{"alice@example.com"})
	f := pendingSettingsFlow(fs, tenantID, identityID)

	ar := passwordAuthnReg(defaultEnrollResult(), nil)
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "NewSecureP@ss1",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/password: unexpected error: %v", err)
	}

	// Identifiers must be those from the existing credential (preserved).
	if len(im.lastUpsertIdentifiers) != 1 || im.lastUpsertIdentifiers[0] != "alice@example.com" {
		t.Errorf("SubmitFlow/password: upsert identifiers = %v, want [alice@example.com]", im.lastUpsertIdentifiers)
	}
	// Config must be the new hash returned by Enroll.
	if string(im.lastUpsertConfig) != `{"hashed_password":"$2a$12$x"}` {
		t.Errorf("SubmitFlow/password: upsert config = %s, want {\"hashed_password\":\"$2a$12$x\"}", im.lastUpsertConfig)
	}
	// Flow must be marked success.
	stored := fs.flows[flowKey(tenantID, f.ID)]
	if stored.State != flow.StateSuccess {
		t.Errorf("SubmitFlow/password: flow state = %q, want %q", stored.State, flow.StateSuccess)
	}
}

func TestSubmitFlow_Password_Success_FallbackToTraitsEmail(t *testing.T) {
	// When there is no existing credential AND the enroll result provides no
	// identifiers, the engine should fall back to the email in traits.
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("fallback@example.com"))
	// No existing password credential — GetByIdentityAndType returns ErrNotFound.
	// im.getByTypeErr is nil; absence in the map triggers ErrNotFound from stub.
	f := pendingSettingsFlow(fs, tenantID, identityID)

	// EnrollResult has no identifiers — engine must use traits email.
	enrollResult := &authenticator.EnrollResult{
		CredentialType:   "password",
		Identifiers:      nil,
		CredentialConfig: json.RawMessage(`{"hashed_password":"$2a$12$x"}`),
	}
	ar := passwordAuthnReg(enrollResult, nil)
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "AnotherP@ss1",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/password: unexpected error: %v", err)
	}

	if len(im.lastUpsertIdentifiers) != 1 || im.lastUpsertIdentifiers[0] != "fallback@example.com" {
		t.Errorf("SubmitFlow/password: upsert identifiers = %v, want [fallback@example.com]", im.lastUpsertIdentifiers)
	}
}

func TestSubmitFlow_Password_GetByIdentityAndType_ErrNotFound_FallbackToEmail(t *testing.T) {
	// Explicit ErrNotFound from GetByIdentityAndType should trigger email fallback.
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("errnotfound@example.com"))
	// Force ErrNotFound from GetByIdentityAndType.
	im.getByTypeErr = fmt.Errorf("wrapped: %w", identity.ErrNotFound)
	f := pendingSettingsFlow(fs, tenantID, identityID)

	enrollResult := &authenticator.EnrollResult{
		CredentialType:   "password",
		Identifiers:      nil,
		CredentialConfig: json.RawMessage(`{"hashed_password":"$2a$12$x"}`),
	}
	ar := passwordAuthnReg(enrollResult, nil)
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "P@ss",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/password: unexpected error: %v", err)
	}

	if len(im.lastUpsertIdentifiers) != 1 || im.lastUpsertIdentifiers[0] != "errnotfound@example.com" {
		t.Errorf("SubmitFlow/password: upsert identifiers = %v, want [errnotfound@example.com]", im.lastUpsertIdentifiers)
	}
}

func TestSubmitFlow_Password_AuthnGetNotFound(t *testing.T) {
	// authnReg.Get returns ErrNotFound for "password" — should surface as an error.
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	f := pendingSettingsFlow(fs, tenantID, identityID)

	// Registry has no authenticators registered.
	ar := &stubAuthnReg{}
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "irrelevant",
	})
	if err == nil {
		t.Fatal("SubmitFlow/password: expected error when password authenticator not registered, got nil")
	}
}

func TestSubmitFlow_Password_AuthnGetOtherError(t *testing.T) {
	// authnReg.Get returns a non-ErrNotFound error.
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	f := pendingSettingsFlow(fs, tenantID, identityID)

	ar := &stubAuthnReg{getErr: errors.New("registry unavailable")}
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "irrelevant",
	})
	if err == nil {
		t.Fatal("SubmitFlow/password: expected error when authn.Get returns error, got nil")
	}
}

func TestSubmitFlow_Password_EnrollError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	f := pendingSettingsFlow(fs, tenantID, identityID)

	ar := passwordAuthnReg(nil, errors.New("bcrypt error"))
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "bad-password",
	})
	if err == nil {
		t.Fatal("SubmitFlow/password: expected error when Enroll fails, got nil")
	}
	// UpsertCredential must not be called.
	if im.upsertCalls != 0 {
		t.Errorf("SubmitFlow/password: UpsertCredential should not be called after Enroll error, called %d time(s)", im.upsertCalls)
	}
}

func TestSubmitFlow_Password_UpsertCredentialError(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	im.setCredential(tenantID, identityID, "password", []string{"alice@example.com"})
	im.upsertCredentialErr = errors.New("db constraint violation")
	f := pendingSettingsFlow(fs, tenantID, identityID)

	ar := passwordAuthnReg(defaultEnrollResult(), nil)
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "GoodP@ss1",
	})
	if err == nil {
		t.Fatal("SubmitFlow/password: expected error when UpsertCredential fails, got nil")
	}
}

func TestSubmitFlow_Password_UpsertCalledOnce(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))
	im.setCredential(tenantID, identityID, "password", []string{"alice@example.com"})
	f := pendingSettingsFlow(fs, tenantID, identityID)

	ar := passwordAuthnReg(defaultEnrollResult(), nil)
	eng := newEngine(fs, im, ar)

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "password", map[string]string{
		"password": "GoodP@ss1",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/password: unexpected error: %v", err)
	}
	if im.upsertCalls != 1 {
		t.Errorf("SubmitFlow/password: UpsertCredential called %d time(s), want 1", im.upsertCalls)
	}
}

// ---------------------------------------------------------------------------
// Multi-field profile update
// ---------------------------------------------------------------------------

func TestSubmitFlow_Profile_MultipleTraitFields(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	initialTraits, _ := json.Marshal(map[string]any{
		"email":      "alice@example.com",
		"first_name": "Alice",
	})

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, initialTraits)
	f := pendingSettingsFlow(fs, tenantID, identityID)

	eng := newEngine(fs, im, &stubAuthnReg{})

	err := eng.SubmitFlow(context.Background(), tenantID, f.ID, identityID, "profile", map[string]string{
		"traits.email":      "alice-updated@example.com",
		"traits.first_name": "Alicia",
	})
	if err != nil {
		t.Fatalf("SubmitFlow/profile: unexpected error: %v", err)
	}

	updated := im.identities[identityKey(tenantID, identityID)]
	var traits map[string]any
	if err := json.Unmarshal(updated.Traits, &traits); err != nil {
		t.Fatalf("unmarshal updated traits: %v", err)
	}
	if traits["email"] != "alice-updated@example.com" {
		t.Errorf("traits.email = %q, want %q", traits["email"], "alice-updated@example.com")
	}
	if traits["first_name"] != "Alicia" {
		t.Errorf("traits.first_name = %q, want %q", traits["first_name"], "Alicia")
	}
}

// ---------------------------------------------------------------------------
// ExpiresAt boundary
// ---------------------------------------------------------------------------

func TestInitFlow_ExpiresAtIsInFuture(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()

	fs := newStubFlowStorer()
	im := newStubIdentityManager()
	im.setIdentity(tenantID, identityID, defaultTraits("alice@example.com"))

	eng := newEngine(fs, im, &stubAuthnReg{})

	before := time.Now()
	f, err := eng.InitFlow(context.Background(), tenantID, identityID)
	if err != nil {
		t.Fatalf("InitFlow: unexpected error: %v", err)
	}
	after := time.Now()

	lower := before.Add(flowTTL - time.Second)
	upper := after.Add(flowTTL + time.Second)

	if f.ExpiresAt.Before(lower) || f.ExpiresAt.After(upper) {
		t.Errorf("InitFlow: ExpiresAt = %v, expected between %v and %v", f.ExpiresAt, lower, upper)
	}
}
