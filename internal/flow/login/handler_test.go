package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/hydra"
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Fake implementations for handler-level interfaces
// ---------------------------------------------------------------------------

// fakeLoginEngine implements loginEngine.
type fakeLoginEngine struct {
	initFlowResult   *flow.Flow
	initFlowErr      error
	getFlowResult    *flow.Flow
	getFlowErr       error
	submitFlowResult *SubmitResult
	submitFlowErr    error
}

func (f *fakeLoginEngine) InitFlow(_ context.Context, _ uuid.UUID) (*flow.Flow, error) {
	return f.initFlowResult, f.initFlowErr
}

func (f *fakeLoginEngine) GetFlow(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
	return f.getFlowResult, f.getFlowErr
}

func (f *fakeLoginEngine) SubmitFlow(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
	return f.submitFlowResult, f.submitFlowErr
}

// fakeSessionIssuer implements sessionIssuer.
type fakeSessionIssuer struct {
	createResult *session.Session
	createErr    error
}

func (f *fakeSessionIssuer) Create(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ time.Duration) (*session.Session, error) {
	return f.createResult, f.createErr
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// withTenant injects a *Tenant into the request context.
func withTenant(r *http.Request, t *internaltenant.Tenant) *http.Request {
	ctx := internaltenant.WithTenant(r.Context(), t)
	return r.WithContext(ctx)
}

// chiParam adds a chi URL parameter to the request context.
func chiParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// testTenant returns a minimal tenant for use in tests.
func testTenant() *internaltenant.Tenant {
	return &internaltenant.Tenant{
		ID:   uuid.New(),
		Slug: "test-tenant",
		Name: "Test Tenant",
	}
}

// minimalFlow returns a minimal *flow.Flow suitable for handler tests.
func minimalFlow(tenantID uuid.UUID) *flow.Flow {
	return &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeLogin,
		State:    flow.StatePending,
		UI: flow.UI{
			Action: "/t/test-tenant/self-service/login/flows/...",
			Method: "POST",
			Nodes:  []authenticator.UINode{},
		},
	}
}

// minimalSession returns a minimal *session.Session.
func minimalSession(tenantID, identityID uuid.UUID) *session.Session {
	return &session.Session{
		ID:         uuid.New(),
		TenantID:   tenantID,
		IdentityID: identityID,
		Token:      "sess_token_abc123",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		AAL:        "aal1",
		AMR:        []string{"password"},
		Active:     true,
	}
}

// newTestServer builds a chi router with an injected tenant middleware wrapper
// and mounts the given handler. The testTenantFn, when non-nil, will be called
// to inject a tenant into each request context before the handler sees it.
func newTestServer(h *Handler, t *internaltenant.Tenant) *httptest.Server {
	r := chi.NewRouter()
	if t != nil {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				req = withTenant(req, t)
				next.ServeHTTP(w, req)
			})
		})
	}
	h.Mount(r)
	return httptest.NewServer(r)
}

// decodeJSON is a small helper that asserts clean JSON decoding.
func decodeJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("failed to decode JSON response: %v\nbody: %s", err, body)
	}
}

// ---------------------------------------------------------------------------
// initFlow — POST /self-service/login/flows
// ---------------------------------------------------------------------------

func TestHandler_InitFlow_Success(t *testing.T) {
	tenant := testTenant()
	f := minimalFlow(tenant.ID)

	eng := &fakeLoginEngine{initFlowResult: f}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/self-service/login/flows", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["id"] == nil {
		t.Error("expected 'id' field in response")
	}
	if body["type"] == nil {
		t.Error("expected 'type' field in response")
	}
	if body["state"] == nil {
		t.Error("expected 'state' field in response")
	}
	if body["ui"] == nil {
		t.Error("expected 'ui' field in response")
	}
	// Action URL should have been rewritten to include tenant slug and flow ID.
	ui, _ := body["ui"].(map[string]any)
	action, _ := ui["action"].(string)
	expectedAction := fmt.Sprintf("/t/%s/self-service/login/flows/%s", tenant.Slug, f.ID)
	if action != expectedAction {
		t.Errorf("expected action %q, got %q", expectedAction, action)
	}
}

func TestHandler_InitFlow_NoTenant_Returns401(t *testing.T) {
	eng := &fakeLoginEngine{}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	// No tenant middleware injected.
	srv := newTestServer(h, nil)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/self-service/login/flows", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty 'error' field in response")
	}
}

func TestHandler_InitFlow_EngineError_Returns500(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{initFlowErr: errors.New("db down")}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/self-service/login/flows", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty 'error' field in response")
	}
}

// ---------------------------------------------------------------------------
// getFlow — GET /self-service/login/flows/{flowId}
// ---------------------------------------------------------------------------

func TestHandler_GetFlow_Success(t *testing.T) {
	tenant := testTenant()
	f := minimalFlow(tenant.ID)

	eng := &fakeLoginEngine{getFlowResult: f}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/self-service/login/flows/" + f.ID.String())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if gotID, _ := body["id"].(string); gotID != f.ID.String() {
		t.Errorf("expected id %s, got %s", f.ID, gotID)
	}
	// Action URL must be rewritten.
	ui, _ := body["ui"].(map[string]any)
	action, _ := ui["action"].(string)
	expectedAction := fmt.Sprintf("/t/%s/self-service/login/flows/%s", tenant.Slug, f.ID)
	if action != expectedAction {
		t.Errorf("expected action %q, got %q", expectedAction, action)
	}
}

func TestHandler_GetFlow_NoTenant_Returns401(t *testing.T) {
	eng := &fakeLoginEngine{}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/self-service/login/flows/" + uuid.New().String())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestHandler_GetFlow_InvalidFlowID_Returns400(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/self-service/login/flows/not-a-uuid")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty 'error' field in response")
	}
}

func TestHandler_GetFlow_EngineNotFound_Returns404(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{getFlowErr: fmt.Errorf("wrapped: %w", flow.ErrNotFound)}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/self-service/login/flows/" + uuid.New().String())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandler_GetFlow_EngineExpired_Returns410(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{getFlowErr: fmt.Errorf("wrapped: %w", flow.ErrExpired)}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/self-service/login/flows/" + uuid.New().String())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGone {
		t.Errorf("expected 410, got %d", resp.StatusCode)
	}
}

func TestHandler_GetFlow_EngineOtherError_Returns500(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{getFlowErr: errors.New("db offline")}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/self-service/login/flows/" + uuid.New().String())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// submitFlow — POST /self-service/login/flows/{flowId}
// ---------------------------------------------------------------------------

// postFlow is a small helper that submits a POST to /self-service/login/flows/{id}
// with the given JSON body map. It returns the *http.Response.
func postFlow(t *testing.T, srvURL, flowID string, body map[string]string) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal body: %v", err)
	}
	resp, err := http.Post(srvURL+"/self-service/login/flows/"+flowID, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func TestHandler_SubmitFlow_Success_Completed_NoHydra(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	f := minimalFlow(tenant.ID)

	submitResult := &SubmitResult{
		Flow:       f,
		Completed:  true,
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
		SessionTTL: 24 * time.Hour,
	}
	sess := minimalSession(tenant.ID, identityID)

	eng := &fakeLoginEngine{submitFlowResult: submitResult}
	issuer := &fakeSessionIssuer{createResult: sess}
	h := NewHandler(eng, issuer, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp := postFlow(t, srv.URL, f.ID.String(), map[string]string{
		"method":     "password",
		"identifier": "user@example.com",
		"password":   "secret",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["session_token"] == nil {
		t.Error("expected 'session_token' in response")
	}
	if gotToken, _ := body["session_token"].(string); gotToken != sess.Token {
		t.Errorf("expected session_token %q, got %q", sess.Token, gotToken)
	}
	if body["session_id"] == nil {
		t.Error("expected 'session_id' in response")
	}
	if body["identity_id"] == nil {
		t.Error("expected 'identity_id' in response")
	}
	if body["aal"] == nil {
		t.Error("expected 'aal' in response")
	}
	if gotAAL, _ := body["aal"].(string); gotAAL != "aal1" {
		t.Errorf("expected aal 'aal1', got %q", gotAAL)
	}
	if body["expires_at"] == nil {
		t.Error("expected 'expires_at' in response")
	}
}

func TestHandler_SubmitFlow_Success_NotCompleted_SecondFactor(t *testing.T) {
	tenant := testTenant()
	f := minimalFlow(tenant.ID)

	// Second factor pending: flow advanced but not yet complete.
	submitResult := &SubmitResult{
		Flow:      f,
		Completed: false,
	}

	eng := &fakeLoginEngine{submitFlowResult: submitResult}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp := postFlow(t, srv.URL, f.ID.String(), map[string]string{
		"method":     "password",
		"identifier": "user@example.com",
		"password":   "secret",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	// When not completed the handler returns the flow response, not a session_token.
	if body["session_token"] != nil {
		t.Error("expected no 'session_token' when flow is not completed")
	}
	if body["id"] == nil {
		t.Error("expected 'id' in flow response when not completed")
	}
	if body["ui"] == nil {
		t.Error("expected 'ui' in flow response when not completed")
	}
}

func TestHandler_SubmitFlow_NoTenant_Returns401(t *testing.T) {
	eng := &fakeLoginEngine{}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, nil)
	defer srv.Close()

	resp := postFlow(t, srv.URL, uuid.New().String(), map[string]string{
		"method": "password",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestHandler_SubmitFlow_InvalidFlowID_Returns400(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp := postFlow(t, srv.URL, "not-a-valid-uuid", map[string]string{
		"method": "password",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty 'error' field")
	}
}

func TestHandler_SubmitFlow_MissingMethod_Returns400(t *testing.T) {
	tenant := testTenant()
	f := minimalFlow(tenant.ID)

	eng := &fakeLoginEngine{}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	// No "method" key in the body.
	resp := postFlow(t, srv.URL, f.ID.String(), map[string]string{
		"identifier": "user@example.com",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty 'error' field")
	}
}

func TestHandler_SubmitFlow_InvalidJSON_Returns400(t *testing.T) {
	tenant := testTenant()
	f := minimalFlow(tenant.ID)

	eng := &fakeLoginEngine{}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	// Send raw non-JSON bytes.
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/self-service/login/flows/"+f.ID.String(),
		bytes.NewBufferString("THIS IS NOT JSON }{"))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_SubmitFlow_EngineNotFound_Returns404(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{submitFlowErr: fmt.Errorf("wrapped: %w", flow.ErrNotFound)}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp := postFlow(t, srv.URL, uuid.New().String(), map[string]string{
		"method": "password",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestHandler_SubmitFlow_EngineExpired_Returns410(t *testing.T) {
	tenant := testTenant()
	eng := &fakeLoginEngine{submitFlowErr: fmt.Errorf("wrapped: %w", flow.ErrExpired)}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp := postFlow(t, srv.URL, uuid.New().String(), map[string]string{
		"method": "password",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGone {
		t.Errorf("expected 410, got %d", resp.StatusCode)
	}
}

func TestHandler_SubmitFlow_EngineCredentialError_Returns400(t *testing.T) {
	tenant := testTenant()
	// Any error that is neither ErrNotFound nor ErrExpired is treated as a
	// credential/validation error and surfaced as 400.
	credErr := errors.New("invalid credentials")
	eng := &fakeLoginEngine{submitFlowErr: credErr}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp := postFlow(t, srv.URL, uuid.New().String(), map[string]string{
		"method":     "password",
		"identifier": "user@example.com",
		"password":   "wrong",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty 'error' field")
	}
}

func TestHandler_SubmitFlow_SessionCreateError_Returns500(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	f := minimalFlow(tenant.ID)

	submitResult := &SubmitResult{
		Flow:       f,
		Completed:  true,
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
		SessionTTL: 24 * time.Hour,
	}

	eng := &fakeLoginEngine{submitFlowResult: submitResult}
	issuer := &fakeSessionIssuer{createErr: errors.New("session store unavailable")}
	h := NewHandler(eng, issuer, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	resp := postFlow(t, srv.URL, f.ID.String(), map[string]string{
		"method":     "password",
		"identifier": "user@example.com",
		"password":   "correct",
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty 'error' field")
	}
}

// ---------------------------------------------------------------------------
// submitFlow — Hydra login challenge redirect
// ---------------------------------------------------------------------------

func TestHandler_SubmitFlow_HydraChallenge_Redirects(t *testing.T) {
	tenant := testTenant()
	identityID := uuid.New()
	f := minimalFlow(tenant.ID)

	submitResult := &SubmitResult{
		Flow:       f,
		Completed:  true,
		IdentityID: identityID,
		AAL:        "aal1",
		AMR:        []string{"password"},
		SessionTTL: 24 * time.Hour,
	}
	sess := minimalSession(tenant.ID, identityID)

	eng := &fakeLoginEngine{submitFlowResult: submitResult}
	issuer := &fakeSessionIssuer{createResult: sess}

	// Spin up a fake Hydra admin endpoint that returns a redirect_to URL.
	const hydraRedirect = "https://hydra.example.com/oauth2/auth?code=xyz"
	hydraServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"redirect_to": hydraRedirect,
		})
	}))
	defer hydraServer.Close()

	hydraClient := hydra.NewClient(hydraServer.URL, nil)
	h := NewHandler(eng, issuer, hydraClient)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	raw, _ := json.Marshal(map[string]string{
		"method":     "password",
		"identifier": "user@example.com",
		"password":   "secret",
	})
	req, err := http.NewRequest(http.MethodPost,
		srv.URL+"/self-service/login/flows/"+f.ID.String()+"?login_challenge=test-challenge",
		bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use a client that does NOT follow redirects so we can inspect the 302.
	noRedirectClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != hydraRedirect {
		t.Errorf("expected Location %q, got %q", hydraRedirect, loc)
	}
	if tok := resp.Header.Get("X-Session-Token"); tok != sess.Token {
		t.Errorf("expected X-Session-Token %q, got %q", sess.Token, tok)
	}
}

// ---------------------------------------------------------------------------
// Handler — Mount registers all expected routes
// ---------------------------------------------------------------------------

func TestHandler_Mount_RegistersRoutes(t *testing.T) {
	tenant := testTenant()
	f := minimalFlow(tenant.ID)

	eng := &fakeLoginEngine{
		initFlowResult:   f,
		getFlowResult:    f,
		submitFlowResult: &SubmitResult{Flow: f, Completed: false},
	}
	h := NewHandler(eng, &fakeSessionIssuer{}, nil)
	srv := newTestServer(h, tenant)
	defer srv.Close()

	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"init flow POST", http.MethodPost, "/self-service/login/flows", http.StatusOK},
		{"get flow GET", http.MethodGet, "/self-service/login/flows/" + f.ID.String(), http.StatusOK},
		{"submit flow POST", http.MethodPost, "/self-service/login/flows/" + f.ID.String(), http.StatusOK},
	}

	client := &http.Client{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, srv.URL+tc.path, bytes.NewBufferString(`{"method":"password"}`))
			if err != nil {
				t.Fatalf("failed to build request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != tc.want {
				t.Errorf("expected %d, got %d", tc.want, resp.StatusCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// toResponse — helper unit tests
// ---------------------------------------------------------------------------

func TestToResponse_NilNodes_BecomesEmptySlice(t *testing.T) {
	f := &flow.Flow{
		ID:    uuid.New(),
		Type:  flow.TypeLogin,
		State: flow.StatePending,
		UI: flow.UI{
			Action: "/action",
			Method: "POST",
			Nodes:  nil, // intentionally nil
		},
	}
	r := toResponse(f)
	if r.UI.Nodes == nil {
		t.Error("expected non-nil nodes slice in response")
	}
	if len(r.UI.Nodes) != 0 {
		t.Errorf("expected empty nodes slice, got %d nodes", len(r.UI.Nodes))
	}
}

func TestToResponse_MapsFlowFields(t *testing.T) {
	id := uuid.New()
	f := &flow.Flow{
		ID:    id,
		Type:  flow.TypeLogin,
		State: flow.StatePending,
		UI: flow.UI{
			Action: "/t/slug/self-service/login/flows/" + id.String(),
			Method: "POST",
			Nodes:  []authenticator.UINode{{Type: "input", Group: "default"}},
			Messages: []authenticator.UIMessage{
				{ID: 4000006, Type: "error", Text: "bad credentials"},
			},
		},
	}
	r := toResponse(f)

	if r.ID != id.String() {
		t.Errorf("expected ID %s, got %s", id, r.ID)
	}
	if r.Type != string(flow.TypeLogin) {
		t.Errorf("expected type 'login', got %q", r.Type)
	}
	if r.State != string(flow.StatePending) {
		t.Errorf("expected state 'pending', got %q", r.State)
	}
	if r.UI.Action != f.UI.Action {
		t.Errorf("expected action %q, got %q", f.UI.Action, r.UI.Action)
	}
	if len(r.UI.Nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(r.UI.Nodes))
	}
	if len(r.UI.Messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(r.UI.Messages))
	}
}

func TestToResponse_InternalNotExposed(t *testing.T) {
	// toResponse must never expose UI.Internal to clients.
	// Verify by marshalling and checking there is no "_internal" key.
	id := uuid.New()
	f := &flow.Flow{
		ID:    id,
		Type:  flow.TypeLogin,
		State: flow.StatePending,
		UI: flow.UI{
			Action: "/action",
			Method: "POST",
			Nodes:  []authenticator.UINode{},
			Internal: &flow.UIInternal{
				Phase: "first_factor",
			},
		},
	}
	r := toResponse(f)

	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	ui, _ := decoded["ui"].(map[string]any)
	if _, found := ui["_internal"]; found {
		t.Error("UI._internal must not be present in the client-facing response")
	}
}

// ---------------------------------------------------------------------------
// actionURL helper
// ---------------------------------------------------------------------------

func TestActionURL_Format(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	got := actionURL("my-tenant", id)
	want := "/t/my-tenant/self-service/login/flows/11111111-1111-1111-1111-111111111111"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

// ---------------------------------------------------------------------------
// errBody helper
// ---------------------------------------------------------------------------

func TestErrBody_Shape(t *testing.T) {
	body := errBody("something went wrong")
	if v, ok := body["error"]; !ok || v != "something went wrong" {
		t.Errorf("expected error key with message, got %v", body)
	}
	if len(body) != 1 {
		t.Errorf("expected exactly one key, got %d", len(body))
	}
}

