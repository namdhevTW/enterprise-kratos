package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Fake recoveryEngine implementation
// ---------------------------------------------------------------------------

type fakeRecoveryEngine struct {
	initFlowFn        func(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error)
	getFlowFn         func(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	requestRecoveryFn func(ctx context.Context, tenantID, flowID uuid.UUID, email string) (string, error)
	useTokenFn        func(ctx context.Context, tenantID, flowID uuid.UUID, token string) (*session.Session, uuid.UUID, error)
}

func (e *fakeRecoveryEngine) InitFlow(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error) {
	if e.initFlowFn != nil {
		return e.initFlowFn(ctx, tenantID)
	}
	return nil, fmt.Errorf("fakeRecoveryEngine: initFlowFn not configured")
}

func (e *fakeRecoveryEngine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	if e.getFlowFn != nil {
		return e.getFlowFn(ctx, tenantID, flowID)
	}
	return nil, fmt.Errorf("fakeRecoveryEngine: getFlowFn not configured")
}

func (e *fakeRecoveryEngine) RequestRecovery(ctx context.Context, tenantID, flowID uuid.UUID, email string) (string, error) {
	if e.requestRecoveryFn != nil {
		return e.requestRecoveryFn(ctx, tenantID, flowID, email)
	}
	return "", fmt.Errorf("fakeRecoveryEngine: requestRecoveryFn not configured")
}

func (e *fakeRecoveryEngine) UseToken(ctx context.Context, tenantID, flowID uuid.UUID, token string) (*session.Session, uuid.UUID, error) {
	if e.useTokenFn != nil {
		return e.useTokenFn(ctx, tenantID, flowID, token)
	}
	return nil, uuid.Nil, fmt.Errorf("fakeRecoveryEngine: useTokenFn not configured")
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testTenant returns a deterministic tenant for use in tests.
func testTenant() *internaltenant.Tenant {
	return &internaltenant.Tenant{
		ID:    uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		Slug:  "acme",
		Name:  "Acme Corp",
		State: internaltenant.StateActive,
	}
}

// minimalPendingFlow returns a flow in the pending/request phase with two UI nodes.
func minimalPendingFlow(tenantID uuid.UUID) *flow.Flow {
	return &flow.Flow{
		ID:       uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
		TenantID: tenantID,
		Type:     flow.TypeRecovery,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			Nodes: []authenticator.UINode{
				{
					Type:  "input",
					Group: "default",
					Attributes: authenticator.UINodeAttrs{
						Name:     "email",
						Type:     "email",
						Required: true,
					},
				},
			},
			Internal: &flow.UIInternal{Phase: "request"},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
}

// newRouter builds a chi router with the handler mounted under /t/{slug}.
// If t is not nil the tenant middleware injects it into every request context.
func newRouter(eng recoveryEngine, t *internaltenant.Tenant) *chi.Mux {
	r := chi.NewRouter()
	r.Route("/t/{slug}", func(r chi.Router) {
		if t != nil {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					ctx := internaltenant.WithTenant(req.Context(), t)
					next.ServeHTTP(w, req.WithContext(ctx))
				})
			})
		}
		h := NewHandler(eng)
		h.Mount(r)
	})
	return r
}

// doRequest fires a request against router and returns the recorder.
func doRequest(router http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// decodeJSON decodes the recorder body into dst; fails the test on error.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(dst); err != nil {
		t.Fatalf("decodeJSON: %v (body: %s)", err, rr.Body.String())
	}
}

// assertStatus fails the test if the recorded status code differs from want.
func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Errorf("status = %d, want %d (body: %s)", rr.Code, want, rr.Body.String())
	}
}

// assertErrorField fails if the JSON body does not contain an "error" key.
func assertErrorField(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	var m map[string]any
	decodeJSON(t, rr, &m)
	if _, ok := m["error"]; !ok {
		t.Errorf("expected JSON body to contain 'error' key, got: %s", rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// initFlow — POST /t/{slug}/self-service/recovery/flows
// ---------------------------------------------------------------------------

func TestHandler_InitFlow_Success(t *testing.T) {
	tenant := testTenant()
	f := minimalPendingFlow(tenant.ID)

	eng := &fakeRecoveryEngine{
		initFlowFn: func(_ context.Context, tenantID uuid.UUID) (*flow.Flow, error) {
			if tenantID != tenant.ID {
				t.Errorf("InitFlow: tenantID = %s, want %s", tenantID, tenant.ID)
			}
			return f, nil
		},
	}

	router := newRouter(eng, tenant)
	rr := doRequest(router, http.MethodPost, "/t/acme/self-service/recovery/flows", nil)

	assertStatus(t, rr, http.StatusOK)

	var resp flowResponse
	decodeJSON(t, rr, &resp)

	if resp.ID != f.ID.String() {
		t.Errorf("resp.ID = %s, want %s", resp.ID, f.ID.String())
	}
	if resp.Type != string(flow.TypeRecovery) {
		t.Errorf("resp.Type = %s, want %s", resp.Type, flow.TypeRecovery)
	}
	if resp.State != string(flow.StatePending) {
		t.Errorf("resp.State = %s, want %s", resp.State, flow.StatePending)
	}
	// Action URL must be set by the handler.
	wantAction := fmt.Sprintf("/t/%s/self-service/recovery/flows/%s", tenant.Slug, f.ID)
	if resp.UI.Action != wantAction {
		t.Errorf("resp.UI.Action = %q, want %q", resp.UI.Action, wantAction)
	}
	// Nodes must be present and non-nil.
	if resp.UI.Nodes == nil {
		t.Error("resp.UI.Nodes is nil, want non-nil slice")
	}
}

func TestHandler_InitFlow_NoTenant_Returns401(t *testing.T) {
	eng := &fakeRecoveryEngine{}
	// No tenant injected — pass nil so the middleware is skipped.
	router := newRouter(eng, nil)

	rr := doRequest(router, http.MethodPost, "/t/acme/self-service/recovery/flows", nil)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertErrorField(t, rr)
}

func TestHandler_InitFlow_EngineError_Returns500(t *testing.T) {
	tenant := testTenant()

	eng := &fakeRecoveryEngine{
		initFlowFn: func(_ context.Context, _ uuid.UUID) (*flow.Flow, error) {
			return nil, fmt.Errorf("database connection lost")
		},
	}

	router := newRouter(eng, tenant)
	rr := doRequest(router, http.MethodPost, "/t/acme/self-service/recovery/flows", nil)

	assertStatus(t, rr, http.StatusInternalServerError)
	assertErrorField(t, rr)
}

// ---------------------------------------------------------------------------
// getFlow (no token) — GET /t/{slug}/self-service/recovery/flows/{flowId}
// ---------------------------------------------------------------------------

func TestHandler_GetFlow_Success(t *testing.T) {
	tenant := testTenant()
	f := minimalPendingFlow(tenant.ID)

	eng := &fakeRecoveryEngine{
		getFlowFn: func(_ context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
			if tenantID != tenant.ID {
				t.Errorf("GetFlow: tenantID = %s, want %s", tenantID, tenant.ID)
			}
			if flowID != f.ID {
				t.Errorf("GetFlow: flowID = %s, want %s", flowID, f.ID)
			}
			return f, nil
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", f.ID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusOK)

	var resp flowResponse
	decodeJSON(t, rr, &resp)

	if resp.ID != f.ID.String() {
		t.Errorf("resp.ID = %s, want %s", resp.ID, f.ID.String())
	}
	wantAction := fmt.Sprintf("/t/%s/self-service/recovery/flows/%s", tenant.Slug, f.ID)
	if resp.UI.Action != wantAction {
		t.Errorf("resp.UI.Action = %q, want %q", resp.UI.Action, wantAction)
	}
}

func TestHandler_GetFlow_NoTenant_Returns401(t *testing.T) {
	eng := &fakeRecoveryEngine{}
	router := newRouter(eng, nil)

	flowID := uuid.New()
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertErrorField(t, rr)
}

func TestHandler_GetFlow_InvalidFlowID_Returns400(t *testing.T) {
	tenant := testTenant()
	eng := &fakeRecoveryEngine{}
	router := newRouter(eng, tenant)

	rr := doRequest(router, http.MethodGet, "/t/acme/self-service/recovery/flows/not-a-uuid", nil)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorField(t, rr)
}

func TestHandler_GetFlow_NotFound_Returns404(t *testing.T) {
	tenant := testTenant()

	eng := &fakeRecoveryEngine{
		getFlowFn: func(_ context.Context, _ uuid.UUID, fid uuid.UUID) (*flow.Flow, error) {
			return nil, fmt.Errorf("flow.Get %s: %w", fid, flow.ErrNotFound)
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", uuid.New())
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusNotFound)
	assertErrorField(t, rr)
}

func TestHandler_GetFlow_Expired_Returns410(t *testing.T) {
	tenant := testTenant()

	eng := &fakeRecoveryEngine{
		getFlowFn: func(_ context.Context, _ uuid.UUID, fid uuid.UUID) (*flow.Flow, error) {
			return nil, fmt.Errorf("flow.Get %s: %w", fid, flow.ErrExpired)
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", uuid.New())
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusGone)
	assertErrorField(t, rr)
}

// ---------------------------------------------------------------------------
// getFlow (with ?token=) — UseToken path
// ---------------------------------------------------------------------------

func TestHandler_GetFlow_WithToken_Success(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	identityID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	const plainToken = "valid-recovery-token-xyz"

	returnedSession := &session.Session{
		ID:         uuid.New(),
		TenantID:   tenant.ID,
		IdentityID: identityID,
		Token:      "sess-tok-abc",
		AAL:        "aal1",
		AMR:        []string{"recovery"},
		Active:     true,
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}

	eng := &fakeRecoveryEngine{
		useTokenFn: func(_ context.Context, tenantID, fid uuid.UUID, tok string) (*session.Session, uuid.UUID, error) {
			if tenantID != tenant.ID {
				t.Errorf("UseToken: tenantID = %s, want %s", tenantID, tenant.ID)
			}
			if fid != flowID {
				t.Errorf("UseToken: flowID = %s, want %s", fid, flowID)
			}
			if tok != plainToken {
				t.Errorf("UseToken: token = %q, want %q", tok, plainToken)
			}
			return returnedSession, identityID, nil
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s?token=%s", flowID, plainToken)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	decodeJSON(t, rr, &resp)

	if resp["session_token"] != returnedSession.Token {
		t.Errorf("session_token = %v, want %q", resp["session_token"], returnedSession.Token)
	}
	if resp["next"] != "set_password" {
		t.Errorf("next = %v, want %q", resp["next"], "set_password")
	}
	if resp["identity_id"] != identityID.String() {
		t.Errorf("identity_id = %v, want %s", resp["identity_id"], identityID.String())
	}
}

func TestHandler_GetFlow_WithToken_InvalidToken_Returns400(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{
		useTokenFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ string) (*session.Session, uuid.UUID, error) {
			return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: invalid token")
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s?token=wrong-token", flowID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorField(t, rr)
}

func TestHandler_GetFlow_WithToken_NotFound_Returns404(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{
		useTokenFn: func(_ context.Context, _ uuid.UUID, fid uuid.UUID, _ string) (*session.Session, uuid.UUID, error) {
			return nil, uuid.Nil, fmt.Errorf("flow.Get %s: %w", fid, flow.ErrNotFound)
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s?token=tok", flowID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusNotFound)
	assertErrorField(t, rr)
}

func TestHandler_GetFlow_WithToken_Expired_Returns410(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{
		useTokenFn: func(_ context.Context, _ uuid.UUID, fid uuid.UUID, _ string) (*session.Session, uuid.UUID, error) {
			return nil, uuid.Nil, fmt.Errorf("flow.Get %s: %w", fid, flow.ErrExpired)
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s?token=tok", flowID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusGone)
	assertErrorField(t, rr)
}

// ---------------------------------------------------------------------------
// submitFlow — POST /t/{slug}/self-service/recovery/flows/{flowId}
// ---------------------------------------------------------------------------

func jsonBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("jsonBody: %v", err)
	}
	return b
}

func TestHandler_SubmitFlow_Success(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")
	const wantToken = "recovery-link-token-abc"

	eng := &fakeRecoveryEngine{
		requestRecoveryFn: func(_ context.Context, tenantID, fid uuid.UUID, email string) (string, error) {
			if tenantID != tenant.ID {
				t.Errorf("RequestRecovery: tenantID = %s, want %s", tenantID, tenant.ID)
			}
			if fid != flowID {
				t.Errorf("RequestRecovery: flowID = %s, want %s", fid, flowID)
			}
			if email != "user@example.com" {
				t.Errorf("RequestRecovery: email = %q, want %q", email, "user@example.com")
			}
			return wantToken, nil
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	body := jsonBody(t, map[string]string{"email": "user@example.com", "method": "link"})
	rr := doRequest(router, http.MethodPost, path, body)

	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	decodeJSON(t, rr, &resp)

	if resp["state"] != "pending_link" {
		t.Errorf("state = %v, want %q", resp["state"], "pending_link")
	}
	if resp["recovery_token"] != wantToken {
		t.Errorf("recovery_token = %v, want %q", resp["recovery_token"], wantToken)
	}
}

func TestHandler_SubmitFlow_NoTenant_Returns401(t *testing.T) {
	eng := &fakeRecoveryEngine{}
	router := newRouter(eng, nil)

	flowID := uuid.New()
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	body := jsonBody(t, map[string]string{"email": "user@example.com"})
	rr := doRequest(router, http.MethodPost, path, body)

	assertStatus(t, rr, http.StatusUnauthorized)
	assertErrorField(t, rr)
}

func TestHandler_SubmitFlow_InvalidFlowID_Returns400(t *testing.T) {
	tenant := testTenant()
	eng := &fakeRecoveryEngine{}
	router := newRouter(eng, tenant)

	body := jsonBody(t, map[string]string{"email": "user@example.com"})
	rr := doRequest(router, http.MethodPost, "/t/acme/self-service/recovery/flows/not-a-uuid", body)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorField(t, rr)
}

func TestHandler_SubmitFlow_MissingEmail_Returns400(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{}
	router := newRouter(eng, tenant)

	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	body := jsonBody(t, map[string]string{"method": "link"}) // no "email"
	rr := doRequest(router, http.MethodPost, path, body)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorField(t, rr)
}

func TestHandler_SubmitFlow_EmptyEmail_Returns400(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{}
	router := newRouter(eng, tenant)

	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	body := jsonBody(t, map[string]string{"email": "", "method": "link"})
	rr := doRequest(router, http.MethodPost, path, body)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorField(t, rr)
}

func TestHandler_SubmitFlow_FlowNotFound_Returns404(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{
		requestRecoveryFn: func(_ context.Context, _ uuid.UUID, fid uuid.UUID, _ string) (string, error) {
			return "", fmt.Errorf("flow.Get %s: %w", fid, flow.ErrNotFound)
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	body := jsonBody(t, map[string]string{"email": "user@example.com"})
	rr := doRequest(router, http.MethodPost, path, body)

	assertStatus(t, rr, http.StatusNotFound)
	assertErrorField(t, rr)
}

func TestHandler_SubmitFlow_FlowExpired_Returns410(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{
		requestRecoveryFn: func(_ context.Context, _ uuid.UUID, fid uuid.UUID, _ string) (string, error) {
			return "", fmt.Errorf("flow.Get %s: %w", fid, flow.ErrExpired)
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	body := jsonBody(t, map[string]string{"email": "user@example.com"})
	rr := doRequest(router, http.MethodPost, path, body)

	assertStatus(t, rr, http.StatusGone)
	assertErrorField(t, rr)
}

func TestHandler_SubmitFlow_EngineError_Returns400(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{
		requestRecoveryFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ string) (string, error) {
			return "", fmt.Errorf("recovery is disabled for this tenant")
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	body := jsonBody(t, map[string]string{"email": "user@example.com"})
	rr := doRequest(router, http.MethodPost, path, body)

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorField(t, rr)
}

// ---------------------------------------------------------------------------
// Additional coverage: Content-Type and response shape
// ---------------------------------------------------------------------------

func TestHandler_InitFlow_ResponseContentType(t *testing.T) {
	tenant := testTenant()
	f := minimalPendingFlow(tenant.ID)

	eng := &fakeRecoveryEngine{
		initFlowFn: func(_ context.Context, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}

	router := newRouter(eng, tenant)
	rr := doRequest(router, http.MethodPost, "/t/acme/self-service/recovery/flows", nil)

	assertStatus(t, rr, http.StatusOK)
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestHandler_SubmitFlow_InvalidJSONBody_Returns400(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()

	eng := &fakeRecoveryEngine{}
	router := newRouter(eng, tenant)

	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", flowID)
	rr := doRequest(router, http.MethodPost, path, []byte("not json {{{"))

	assertStatus(t, rr, http.StatusBadRequest)
	assertErrorField(t, rr)
}

func TestHandler_GetFlow_WithToken_ResponseContainsSessionID(t *testing.T) {
	tenant := testTenant()
	flowID := uuid.New()
	identityID := uuid.New()
	sessID := uuid.New()

	returnedSession := &session.Session{
		ID:         sessID,
		TenantID:   tenant.ID,
		IdentityID: identityID,
		Token:      "session-token-xyz",
		AAL:        "aal1",
		AMR:        []string{"recovery"},
		Active:     true,
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}

	eng := &fakeRecoveryEngine{
		useTokenFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ string) (*session.Session, uuid.UUID, error) {
			return returnedSession, identityID, nil
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s?token=good-token", flowID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusOK)

	var resp map[string]any
	decodeJSON(t, rr, &resp)

	if resp["session_id"] != sessID.String() {
		t.Errorf("session_id = %v, want %s", resp["session_id"], sessID.String())
	}
	if resp["expires_at"] == nil {
		t.Error("expires_at must be present in UseToken response")
	}
}

func TestHandler_InitFlow_ActionURLIncludesTenantSlug(t *testing.T) {
	tenant := &internaltenant.Tenant{
		ID:    uuid.New(),
		Slug:  "my-team",
		Name:  "My Team",
		State: internaltenant.StateActive,
	}
	f := minimalPendingFlow(tenant.ID)

	eng := &fakeRecoveryEngine{
		initFlowFn: func(_ context.Context, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}

	router := newRouter(eng, tenant)
	rr := doRequest(router, http.MethodPost, "/t/my-team/self-service/recovery/flows", nil)

	assertStatus(t, rr, http.StatusOK)

	var resp flowResponse
	decodeJSON(t, rr, &resp)

	wantAction := fmt.Sprintf("/t/my-team/self-service/recovery/flows/%s", f.ID)
	if resp.UI.Action != wantAction {
		t.Errorf("UI.Action = %q, want %q", resp.UI.Action, wantAction)
	}
}

func TestHandler_GetFlow_NoTokenPath_ActionURLSet(t *testing.T) {
	tenant := testTenant()
	f := minimalPendingFlow(tenant.ID)

	eng := &fakeRecoveryEngine{
		getFlowFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", f.ID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusOK)

	var resp flowResponse
	decodeJSON(t, rr, &resp)

	wantAction := fmt.Sprintf("/t/%s/self-service/recovery/flows/%s", tenant.Slug, f.ID)
	if resp.UI.Action != wantAction {
		t.Errorf("UI.Action = %q, want %q", resp.UI.Action, wantAction)
	}
}

func TestHandler_GetFlow_NodesNeverNil(t *testing.T) {
	// Even when the engine returns a flow with nil Nodes, the handler must
	// serialize them as an empty array (not JSON null).
	tenant := testTenant()
	f := minimalPendingFlow(tenant.ID)
	f.UI.Nodes = nil // explicitly nil

	eng := &fakeRecoveryEngine{
		getFlowFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}

	router := newRouter(eng, tenant)
	path := fmt.Sprintf("/t/acme/self-service/recovery/flows/%s", f.ID)
	rr := doRequest(router, http.MethodGet, path, nil)

	assertStatus(t, rr, http.StatusOK)

	var resp flowResponse
	decodeJSON(t, rr, &resp)

	if resp.UI.Nodes == nil {
		t.Error("UI.Nodes must not be nil in the response even when the flow has nil nodes")
	}
}
