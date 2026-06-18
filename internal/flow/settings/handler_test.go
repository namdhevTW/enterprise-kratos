package settings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Handler test doubles
// ---------------------------------------------------------------------------

// fakeSettingsEngine is an in-memory settingsEngine for handler tests.
type fakeSettingsEngine struct {
	// InitFlow controls
	initFlowResult *flow.Flow
	initFlowErr    error

	// GetFlow controls
	getFlowResult *flow.Flow
	getFlowErr    error

	// SubmitFlow controls
	submitFlowErr error

	// Call capture
	lastInitTenantID    uuid.UUID
	lastInitIdentityID  uuid.UUID
	lastGetTenantID     uuid.UUID
	lastGetFlowID       uuid.UUID
	lastSubmitTenantID  uuid.UUID
	lastSubmitFlowID    uuid.UUID
	lastSubmitIdentity  uuid.UUID
	lastSubmitMethod    string
	lastSubmitValues    map[string]string
}

func (e *fakeSettingsEngine) InitFlow(_ context.Context, tenantID, identityID uuid.UUID) (*flow.Flow, error) {
	e.lastInitTenantID = tenantID
	e.lastInitIdentityID = identityID
	if e.initFlowErr != nil {
		return nil, e.initFlowErr
	}
	if e.initFlowResult != nil {
		return e.initFlowResult, nil
	}
	// Default: return a minimal pending settings flow.
	fID := uuid.New()
	return &flow.Flow{
		ID:       fID,
		TenantID: tenantID,
		Type:     flow.TypeSettings,
		State:    flow.StatePending,
		UI:       flow.UI{Method: "POST"},
	}, nil
}

func (e *fakeSettingsEngine) GetFlow(_ context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	e.lastGetTenantID = tenantID
	e.lastGetFlowID = flowID
	if e.getFlowErr != nil {
		return nil, e.getFlowErr
	}
	if e.getFlowResult != nil {
		return e.getFlowResult, nil
	}
	return &flow.Flow{
		ID:       flowID,
		TenantID: tenantID,
		Type:     flow.TypeSettings,
		State:    flow.StatePending,
		UI:       flow.UI{Method: "POST"},
	}, nil
}

func (e *fakeSettingsEngine) SubmitFlow(_ context.Context, tenantID, flowID, identityID uuid.UUID, method string, values map[string]string) error {
	e.lastSubmitTenantID = tenantID
	e.lastSubmitFlowID = flowID
	e.lastSubmitIdentity = identityID
	e.lastSubmitMethod = method
	e.lastSubmitValues = values
	return e.submitFlowErr
}

// fakeSessionReader is an in-memory sessionReader for handler tests.
type fakeSessionReader struct {
	sess *session.Session
	err  error
}

func (r *fakeSessionReader) GetByToken(_ context.Context, _ uuid.UUID, _ string) (*session.Session, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.sess, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// validSession returns a session that is active and not expired.
func validSession(identityID uuid.UUID) *session.Session {
	return &session.Session{
		ID:         uuid.New(),
		IdentityID: identityID,
		Token:      "valid-token",
		Active:     true,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
}

// testTenant returns a *tenant.Tenant with a stable slug and a new ID.
func testTenant() *internaltenant.Tenant {
	return &internaltenant.Tenant{
		ID:    uuid.New(),
		Slug:  "acme",
		Name:  "Acme Corp",
		State: internaltenant.StateActive,
	}
}

// newRouter builds a chi Router that mirrors how the handler is mounted in
// production — the tenant is injected into the request context, and the
// flowId URL param is handled by chi's pattern matching.
func newRouter(h *Handler, t *internaltenant.Tenant) chi.Router {
	r := chi.NewRouter()

	// Inject tenant into the request context, mimicking the tenant middleware.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := internaltenant.WithTenant(req.Context(), t)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})

	h.Mount(r)
	return r
}

// newRouterNoTenant builds a chi Router with NO tenant in the context — used
// to verify that handlers reject requests when the tenant middleware is absent.
func newRouterNoTenant(h *Handler) chi.Router {
	r := chi.NewRouter()
	h.Mount(r)
	return r
}

// jsonBody serialises v and returns a *bytes.Buffer suitable for http.Request.
func jsonBody(v any) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

// decodeJSON parses the response body of rr into dst.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(dst); err != nil {
		t.Fatalf("decodeJSON: %v", err)
	}
}

// assertStatus fails the test if rr.Code != want.
func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Errorf("status = %d, want %d (body: %s)", rr.Code, want, rr.Body.String())
	}
}

// assertErrorBody fails the test unless the JSON response contains an "error" key.
func assertErrorBody(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]string
	decodeJSON(t, rr, &body)
	if _, ok := body["error"]; !ok {
		t.Errorf("expected JSON body with 'error' key, got: %s", rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// initFlow  POST /self-service/settings/flows
// ---------------------------------------------------------------------------

func TestHandler_InitFlow_Success(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	sess := validSession(identityID)

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	// Verify engine received the correct tenant and identity IDs.
	if eng.lastInitTenantID != tenant.ID {
		t.Errorf("InitFlow: tenantID = %s, want %s", eng.lastInitTenantID, tenant.ID)
	}
	if eng.lastInitIdentityID != identityID {
		t.Errorf("InitFlow: identityID = %s, want %s", eng.lastInitIdentityID, identityID)
	}

	// Verify response shape.
	var resp flowResponse
	decodeJSON(t, rr, &resp)
	if resp.Type != string(flow.TypeSettings) {
		t.Errorf("InitFlow: type = %q, want %q", resp.Type, flow.TypeSettings)
	}
}

func TestHandler_InitFlow_AuthorizationBearerToken(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)
}

func TestHandler_InitFlow_NoTenant(t *testing.T) {
	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: validSession(uuid.New())}

	h := NewHandler(eng, sessions)
	router := newRouterNoTenant(h)

	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertErrorBody(t, rr)
}

func TestHandler_InitFlow_NoSessionToken(t *testing.T) {
	tenant := testTenant()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: validSession(uuid.New())}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	// Neither X-Session-Token nor Authorization header is set.
	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertErrorBody(t, rr)
}

func TestHandler_InitFlow_SessionRevoked(t *testing.T) {
	tenant := testTenant()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{err: session.ErrRevoked}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	req.Header.Set("X-Session-Token", "revoked-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertErrorBody(t, rr)
}

func TestHandler_InitFlow_EngineError(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())

	eng := &fakeSettingsEngine{initFlowErr: fmt.Errorf("db unavailable")}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusInternalServerError)
	assertErrorBody(t, rr)
}

// ---------------------------------------------------------------------------
// getFlow  GET /self-service/settings/flows/{flowId}
// ---------------------------------------------------------------------------

func TestHandler_GetFlow_Success(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeSettingsEngine{
		getFlowResult: &flow.Flow{
			ID:       flowID,
			TenantID: tenant.ID,
			Type:     flow.TypeSettings,
			State:    flow.StatePending,
			UI:       flow.UI{Method: "POST"},
		},
	}
	sessions := &fakeSessionReader{}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	var resp flowResponse
	decodeJSON(t, rr, &resp)
	if resp.ID != flowID.String() {
		t.Errorf("GetFlow: id = %q, want %q", resp.ID, flowID.String())
	}
	if resp.Type != string(flow.TypeSettings) {
		t.Errorf("GetFlow: type = %q, want %q", resp.Type, flow.TypeSettings)
	}
	if resp.State != string(flow.StatePending) {
		t.Errorf("GetFlow: state = %q, want %q", resp.State, flow.StatePending)
	}
}

func TestHandler_GetFlow_ActionURLSet(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeSettingsEngine{
		getFlowResult: &flow.Flow{
			ID:       flowID,
			TenantID: tenant.ID,
			Type:     flow.TypeSettings,
			State:    flow.StatePending,
			UI:       flow.UI{Method: "POST"},
		},
	}
	h := NewHandler(eng, &fakeSessionReader{})
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	var resp flowResponse
	decodeJSON(t, rr, &resp)

	wantAction := fmt.Sprintf("/t/%s/self-service/settings/flows/%s", tenant.Slug, flowID)
	if resp.UI.Action != wantAction {
		t.Errorf("GetFlow: action = %q, want %q", resp.UI.Action, wantAction)
	}
}

func TestHandler_GetFlow_InvalidFlowID(t *testing.T) {
	tenant := testTenant()

	eng := &fakeSettingsEngine{}
	h := NewHandler(eng, &fakeSessionReader{})
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodGet,
		"/self-service/settings/flows/not-a-uuid", nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr)
}

func TestHandler_GetFlow_NotFound(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeSettingsEngine{
		getFlowErr: fmt.Errorf("wrapped: %w", flow.ErrNotFound),
	}
	h := NewHandler(eng, &fakeSessionReader{})
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusNotFound)
	assertErrorBody(t, rr)
}

func TestHandler_GetFlow_Expired(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeSettingsEngine{
		getFlowErr: fmt.Errorf("wrapped: %w", flow.ErrExpired),
	}
	h := NewHandler(eng, &fakeSessionReader{})
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusGone)
	assertErrorBody(t, rr)
}

// ---------------------------------------------------------------------------
// submitFlow  POST /self-service/settings/flows/{flowId}
// ---------------------------------------------------------------------------

func TestHandler_SubmitFlow_Success_Profile(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	sess := validSession(identityID)
	flowID := uuid.New()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{
		"method":       "profile",
		"traits.email": "alice@example.com",
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	var resp map[string]string
	decodeJSON(t, rr, &resp)
	if resp["state"] != "success" {
		t.Errorf("SubmitFlow/profile: state = %q, want \"success\"", resp["state"])
	}

	if eng.lastSubmitMethod != "profile" {
		t.Errorf("SubmitFlow/profile: method forwarded = %q, want \"profile\"", eng.lastSubmitMethod)
	}
}

func TestHandler_SubmitFlow_Success_Password(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	sess := validSession(identityID)
	flowID := uuid.New()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{
		"method":   "password",
		"password": "NewS3cur3P@ss",
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	var resp map[string]string
	decodeJSON(t, rr, &resp)
	if resp["state"] != "success" {
		t.Errorf("SubmitFlow/password: state = %q, want \"success\"", resp["state"])
	}

	if eng.lastSubmitMethod != "password" {
		t.Errorf("SubmitFlow/password: method forwarded = %q, want \"password\"", eng.lastSubmitMethod)
	}
}

func TestHandler_SubmitFlow_ForwardsValuesToEngine(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())
	flowID := uuid.New()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{
		"method":       "profile",
		"traits.email": "forwarded@example.com",
	})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	if eng.lastSubmitValues["traits.email"] != "forwarded@example.com" {
		t.Errorf("SubmitFlow: values[traits.email] = %q, want \"forwarded@example.com\"",
			eng.lastSubmitValues["traits.email"])
	}
}

func TestHandler_SubmitFlow_NoSessionToken(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{err: session.ErrNotFound}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{"method": "profile"})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	// Deliberately omit any session header.
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertErrorBody(t, rr)
}

func TestHandler_SubmitFlow_InvalidFlowID(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{"method": "profile"})
	req := httptest.NewRequest(http.MethodPost,
		"/self-service/settings/flows/not-a-valid-uuid", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr)
}

func TestHandler_SubmitFlow_MissingMethod(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())
	flowID := uuid.New()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	// Body has no "method" key.
	body := jsonBody(map[string]string{"traits.email": "alice@example.com"})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr)
}

func TestHandler_SubmitFlow_FlowNotFound(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())
	flowID := uuid.New()

	eng := &fakeSettingsEngine{
		submitFlowErr: fmt.Errorf("wrapped: %w", flow.ErrNotFound),
	}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{"method": "profile"})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusNotFound)
	assertErrorBody(t, rr)
}

func TestHandler_SubmitFlow_FlowExpired(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())
	flowID := uuid.New()

	eng := &fakeSettingsEngine{
		submitFlowErr: fmt.Errorf("wrapped: %w", flow.ErrExpired),
	}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{"method": "profile"})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusGone)
	assertErrorBody(t, rr)
}

func TestHandler_SubmitFlow_EngineError(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())
	flowID := uuid.New()

	eng := &fakeSettingsEngine{
		submitFlowErr: fmt.Errorf("password too short"),
	}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{"method": "password", "password": "x"})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Generic engine errors on SubmitFlow surface as 400 Bad Request.
	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorBody(t, rr)
}

// ---------------------------------------------------------------------------
// Identity propagation
// ---------------------------------------------------------------------------

// TestHandler_SubmitFlow_IdentityIDPropagated verifies that the identity from
// the session is forwarded to the engine, not a different one.
func TestHandler_SubmitFlow_IdentityIDPropagated(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	sess := validSession(identityID)
	flowID := uuid.New()

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	body := jsonBody(map[string]string{"method": "profile"})
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/self-service/settings/flows/%s", flowID), body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	if eng.lastSubmitIdentity != identityID {
		t.Errorf("SubmitFlow: identityID = %s, want %s", eng.lastSubmitIdentity, identityID)
	}
}

// TestHandler_InitFlow_IdentityIDFromSession verifies that the session's
// IdentityID is passed to engine.InitFlow.
func TestHandler_InitFlow_IdentityIDFromSession(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	sess := validSession(identityID)

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assertStatus(t, rr, http.StatusOK)

	if eng.lastInitIdentityID != identityID {
		t.Errorf("InitFlow: identityID = %s, want %s", eng.lastInitIdentityID, identityID)
	}
}

// ---------------------------------------------------------------------------
// Content-Type header
// ---------------------------------------------------------------------------

func TestHandler_ResponseContentType(t *testing.T) {
	tenant := testTenant()
	sess := validSession(uuid.New())

	eng := &fakeSettingsEngine{}
	sessions := &fakeSessionReader{sess: sess}

	h := NewHandler(eng, sessions)
	router := newRouter(h, tenant)

	req := httptest.NewRequest(http.MethodPost, "/self-service/settings/flows", nil)
	req.Header.Set("X-Session-Token", "valid-token")
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want \"application/json\"", ct)
	}
}
