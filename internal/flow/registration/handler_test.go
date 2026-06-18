package registration

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
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Stub implementations of handler interfaces
// ---------------------------------------------------------------------------

// stubRegistrationEngine is a controllable in-memory implementation of
// registrationEngine used exclusively by handler tests.
type stubRegistrationEngine struct {
	initFlowFn   func(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error)
	getFlowFn    func(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	submitFlowFn func(ctx context.Context, tenantID, flowID uuid.UUID, method string, values map[string]string) (*SubmitResult, error)
}

func (s *stubRegistrationEngine) InitFlow(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error) {
	if s.initFlowFn != nil {
		return s.initFlowFn(ctx, tenantID)
	}
	return &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeRegistration,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			Nodes:  []authenticator.UINode{},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}, nil
}

func (s *stubRegistrationEngine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	if s.getFlowFn != nil {
		return s.getFlowFn(ctx, tenantID, flowID)
	}
	return nil, fmt.Errorf("stubRegistrationEngine.GetFlow: no stub configured")
}

func (s *stubRegistrationEngine) SubmitFlow(ctx context.Context, tenantID, flowID uuid.UUID, method string, values map[string]string) (*SubmitResult, error) {
	if s.submitFlowFn != nil {
		return s.submitFlowFn(ctx, tenantID, flowID, method, values)
	}
	return nil, fmt.Errorf("stubRegistrationEngine.SubmitFlow: no stub configured")
}

// stubSessionIssuer is a controllable implementation of sessionIssuer used
// exclusively by handler tests.
type stubSessionIssuer struct {
	createFn func(ctx context.Context, tenantID, identityID uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error)
}

func (s *stubSessionIssuer) Create(ctx context.Context, tenantID, identityID uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error) {
	if s.createFn != nil {
		return s.createFn(ctx, tenantID, identityID, aal, amr, ttl)
	}
	return &session.Session{
		ID:         uuid.New(),
		TenantID:   tenantID,
		IdentityID: identityID,
		Token:      "test-session-token-" + uuid.New().String(),
		ExpiresAt:  time.Now().Add(ttl),
		AAL:        aal,
		Active:     true,
	}, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestTenant constructs a minimal *tenant.Tenant suitable for handler tests.
func newTestTenant() *internaltenant.Tenant {
	return &internaltenant.Tenant{
		ID:    uuid.New(),
		Slug:  "acme",
		Name:  "Acme Corp",
		State: internaltenant.StateActive,
	}
}

// newTestFlow constructs a minimal *flow.Flow in the pending state.
func newTestFlow(tenantID uuid.UUID) *flow.Flow {
	return &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeRegistration,
		State:    flow.StatePending,
		UI: flow.UI{
			Method: "POST",
			Nodes:  []authenticator.UINode{},
		},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
}

// newTestSession constructs a minimal *session.Session.
func newTestSession(tenantID, identityID uuid.UUID) *session.Session {
	return &session.Session{
		ID:         uuid.New(),
		TenantID:   tenantID,
		IdentityID: identityID,
		Token:      "ses-tok-abc123",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		AAL:        "aal1",
		Active:     true,
	}
}

// newCompletedSubmitResult builds a SubmitResult representing a fully completed
// registration (no verification required).
func newCompletedSubmitResult(tenantID uuid.UUID) *SubmitResult {
	identityID := uuid.New()
	return &SubmitResult{
		Flow: &flow.Flow{
			ID:         uuid.New(),
			TenantID:   tenantID,
			Type:       flow.TypeRegistration,
			State:      flow.StateSuccess,
			IdentityID: &identityID,
			UI:         flow.UI{Method: "POST", Nodes: []authenticator.UINode{}},
		},
		Completed:  true,
		IdentityID: identityID,
		SessionTTL: 24 * time.Hour,
	}
}

// newVerificationPendingSubmitResult builds a SubmitResult representing a
// registration that requires email verification.
func newVerificationPendingSubmitResult(tenantID uuid.UUID) *SubmitResult {
	identityID := uuid.New()
	verifFlowID := uuid.New()
	return &SubmitResult{
		Flow: &flow.Flow{
			ID:         uuid.New(),
			TenantID:   tenantID,
			Type:       flow.TypeRegistration,
			State:      flow.StateSuccess,
			IdentityID: &identityID,
			UI:         flow.UI{Method: "POST", Nodes: []authenticator.UINode{}},
		},
		NeedsVerification:  true,
		IdentityID:         identityID,
		VerificationFlowID: verifFlowID,
		VerificationToken:  "tok123",
	}
}

// newHandler wires up a Handler with the provided stubs and mounts routes
// onto a chi router that injects tenant into context when t != nil.
func newHandler(eng registrationEngine, sess sessionIssuer) *Handler {
	return NewHandler(eng, sess)
}

// doRequest fires req through a chi router that optionally injects t into
// the request context, then returns the recorded response.
//
// When t is non-nil the tenant middleware is simulated by decorating the
// chi router with a simple context-injecting middleware.  When t is nil the
// middleware is omitted so the tenant is absent from context (401 path).
//
// flowIDParam is the URL param value for "{flowId}"; set to "" when the route
// does not carry a flowId segment.
func doRequest(h *Handler, req *http.Request, t *internaltenant.Tenant, flowIDParam string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()

	r := chi.NewRouter()

	if t != nil {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				ctx := internaltenant.WithTenant(req.Context(), t)
				next.ServeHTTP(w, req.WithContext(ctx))
			})
		})
	}

	h.Mount(r)

	r.ServeHTTP(rr, req)
	return rr
}

// decodeJSON is a small helper that unmarshals the response body into a
// map[string]any so tests can inspect individual fields.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("failed to decode response JSON: %v — body: %s", err, rr.Body.String())
	}
	return m
}

// jsonBody marshals v and returns a bytes.Buffer suitable for http.NewRequest.
func jsonBody(t *testing.T, v any) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("jsonBody: marshal failed: %v", err)
	}
	return bytes.NewBuffer(b)
}

// ---------------------------------------------------------------------------
// initFlow  POST /self-service/registration/flows
// ---------------------------------------------------------------------------

func TestHandler_InitFlow_Success(t *testing.T) {
	tenant := newTestTenant()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows", nil)
	rr := doRequest(h, req, tenant, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if _, ok := body["id"]; !ok {
		t.Error("expected 'id' field in response")
	}
	if body["type"] != string(flow.TypeRegistration) {
		t.Errorf("expected type %q, got %v", flow.TypeRegistration, body["type"])
	}
	if body["state"] != string(flow.StatePending) {
		t.Errorf("expected state %q, got %v", flow.StatePending, body["state"])
	}
	// action URL must embed the tenant slug
	ui, _ := body["ui"].(map[string]any)
	action, _ := ui["action"].(string)
	if action == "" {
		t.Error("expected ui.action to be non-empty")
	}
}

func TestHandler_InitFlow_NoTenant_Returns401(t *testing.T) {
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows", nil)
	// no tenant injected
	rr := doRequest(h, req, nil, "")

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 401 response")
	}
}

func TestHandler_InitFlow_EngineError_Returns500(t *testing.T) {
	tenant := newTestTenant()
	eng := &stubRegistrationEngine{
		initFlowFn: func(_ context.Context, _ uuid.UUID) (*flow.Flow, error) {
			return nil, errors.New("db write failed")
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows", nil)
	rr := doRequest(h, req, tenant, "")

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 500 response")
	}
}

// ---------------------------------------------------------------------------
// getFlow  GET /self-service/registration/flows/{flowId}
// ---------------------------------------------------------------------------

func TestHandler_GetFlow_Success(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	eng := &stubRegistrationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodGet, "/self-service/registration/flows/"+f.ID.String(), nil)
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if body["id"] != f.ID.String() {
		t.Errorf("expected id %q, got %v", f.ID.String(), body["id"])
	}
	if body["type"] != string(flow.TypeRegistration) {
		t.Errorf("expected type %q, got %v", flow.TypeRegistration, body["type"])
	}
}

func TestHandler_GetFlow_NoTenant_Returns401(t *testing.T) {
	flowID := uuid.New()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodGet, "/self-service/registration/flows/"+flowID.String(), nil)
	rr := doRequest(h, req, nil, flowID.String())

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestHandler_GetFlow_InvalidFlowID_Returns400(t *testing.T) {
	tenant := newTestTenant()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodGet, "/self-service/registration/flows/not-a-uuid", nil)
	rr := doRequest(h, req, tenant, "not-a-uuid")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 400 response")
	}
}

func TestHandler_GetFlow_ErrNotFound_Returns404(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, fmt.Errorf("flow.Get: %w", flow.ErrNotFound)
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodGet, "/self-service/registration/flows/"+flowID.String(), nil)
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 404 response")
	}
}

func TestHandler_GetFlow_ErrExpired_Returns410(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, fmt.Errorf("flow.Get: %w", flow.ErrExpired)
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodGet, "/self-service/registration/flows/"+flowID.String(), nil)
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusGone {
		t.Fatalf("expected 410 Gone, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 410 response")
	}
}

// ---------------------------------------------------------------------------
// submitFlow  POST /self-service/registration/flows/{flowId}
// ---------------------------------------------------------------------------

func TestHandler_SubmitFlow_SuccessCompleted_Returns200WithSessionToken(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newCompletedSubmitResult(tenant.ID)
	sess := newTestSession(tenant.ID, result.IdentityID)

	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return result, nil
		},
	}
	issuer := &stubSessionIssuer{
		createFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ time.Duration) (*session.Session, error) {
			return sess, nil
		},
	}
	h := newHandler(eng, issuer)

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if body["session_token"] != sess.Token {
		t.Errorf("expected session_token %q, got %v", sess.Token, body["session_token"])
	}
	if body["session_id"] == nil {
		t.Error("expected 'session_id' in response")
	}
	if body["identity_id"] == nil {
		t.Error("expected 'identity_id' in response")
	}
	if body["aal"] != "aal1" {
		t.Errorf("expected aal 'aal1', got %v", body["aal"])
	}
	if body["expires_at"] == nil {
		t.Error("expected 'expires_at' in response")
	}
}

func TestHandler_SubmitFlow_SuccessVerificationPending_Returns200WithVerificationToken(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newVerificationPendingSubmitResult(tenant.ID)

	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return result, nil
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d — body: %s", rr.Code, rr.Body.String())
	}
	body := decodeJSON(t, rr)
	if body["verification_pending"] != true {
		t.Errorf("expected verification_pending = true, got %v", body["verification_pending"])
	}
	if body["verification_token"] != result.VerificationToken {
		t.Errorf("expected verification_token %q, got %v", result.VerificationToken, body["verification_token"])
	}
	if body["verification_flow_id"] != result.VerificationFlowID.String() {
		t.Errorf("expected verification_flow_id %q, got %v", result.VerificationFlowID.String(), body["verification_flow_id"])
	}
	if body["identity_id"] == nil {
		t.Error("expected 'identity_id' in response")
	}
	// session_token must NOT be present when verification is pending
	if _, ok := body["session_token"]; ok {
		t.Error("expected no 'session_token' when verification is pending")
	}
}

func TestHandler_SubmitFlow_NoTenant_Returns401(t *testing.T) {
	flowID := uuid.New()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{"method": "password"})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+flowID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, nil, flowID.String())

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", rr.Code)
	}
}

func TestHandler_SubmitFlow_InvalidFlowID_Returns400(t *testing.T) {
	tenant := newTestTenant()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{"method": "password"})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/bad-uuid", reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, "bad-uuid")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 400 response")
	}
}

func TestHandler_SubmitFlow_MissingMethod_Returns400(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	// Omit "method" field entirely.
	reqBody := jsonBody(t, map[string]string{
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+flowID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field when method is missing")
	}
}

func TestHandler_SubmitFlow_EmptyMethod_Returns400(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	// Explicitly send empty string for "method".
	reqBody := jsonBody(t, map[string]string{
		"method":       "",
		"traits.email": "user@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+flowID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for empty method, got %d", rr.Code)
	}
}

func TestHandler_SubmitFlow_ErrNotFound_Returns404(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return nil, fmt.Errorf("flow.Get: %w", flow.ErrNotFound)
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+flowID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rr.Code)
	}
}

func TestHandler_SubmitFlow_ErrExpired_Returns410(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return nil, fmt.Errorf("flow.Get: %w", flow.ErrExpired)
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+flowID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusGone {
		t.Fatalf("expected 410 Gone, got %d", rr.Code)
	}
}

func TestHandler_SubmitFlow_RegistrationError_Duplicate_Returns400(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return nil, errors.New("registration: an account with this identifier already exists")
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "existing@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+flowID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for duplicate, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 400 response")
	}
}

func TestHandler_SubmitFlow_SessionCreateError_Returns500(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newCompletedSubmitResult(tenant.ID)

	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return result, nil
		},
	}
	issuer := &stubSessionIssuer{
		createFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ time.Duration) (*session.Session, error) {
			return nil, errors.New("session store unavailable")
		},
	}
	h := newHandler(eng, issuer)

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error when session create fails, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 500 response")
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case / contract tests
// ---------------------------------------------------------------------------

// TestHandler_InitFlow_ActionURL verifies that the ui.action is populated with
// the expected path pattern for the tenant slug and new flow ID.
func TestHandler_InitFlow_ActionURL(t *testing.T) {
	tenant := newTestTenant()
	fixedFlowID := uuid.New()
	eng := &stubRegistrationEngine{
		initFlowFn: func(_ context.Context, tenantID uuid.UUID) (*flow.Flow, error) {
			return &flow.Flow{
				ID:       fixedFlowID,
				TenantID: tenantID,
				Type:     flow.TypeRegistration,
				State:    flow.StatePending,
				UI:       flow.UI{Method: "POST", Nodes: []authenticator.UINode{}},
			}, nil
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows", nil)
	rr := doRequest(h, req, tenant, "")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	ui, _ := body["ui"].(map[string]any)
	action, _ := ui["action"].(string)

	expectedAction := fmt.Sprintf("/t/%s/self-service/registration/flows/%s", tenant.Slug, fixedFlowID.String())
	if action != expectedAction {
		t.Errorf("expected action %q, got %q", expectedAction, action)
	}
}

// TestHandler_GetFlow_ActionURL verifies that getFlow populates ui.action with
// the correct path.
func TestHandler_GetFlow_ActionURL(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)

	eng := &stubRegistrationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodGet, "/self-service/registration/flows/"+f.ID.String(), nil)
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	ui, _ := body["ui"].(map[string]any)
	action, _ := ui["action"].(string)

	expectedAction := fmt.Sprintf("/t/%s/self-service/registration/flows/%s", tenant.Slug, f.ID.String())
	if action != expectedAction {
		t.Errorf("expected action %q, got %q", expectedAction, action)
	}
}

// TestHandler_SubmitFlow_ContentTypeJSON verifies that the response
// Content-Type header is set to application/json.
func TestHandler_SubmitFlow_ContentTypeJSON(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newCompletedSubmitResult(tenant.ID)

	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return result, nil
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, f.ID.String())

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
}

// TestHandler_SubmitFlow_InvalidJSONBody_Returns400 verifies that a malformed
// request body results in a 400 response.
func TestHandler_SubmitFlow_InvalidJSONBody_Returns400(t *testing.T) {
	tenant := newTestTenant()
	flowID := uuid.New()
	eng := &stubRegistrationEngine{}
	h := newHandler(eng, &stubSessionIssuer{})

	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+flowID.String(), bytes.NewBufferString("not json {{{"))
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, flowID.String())

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for malformed JSON, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	if body["error"] == nil {
		t.Error("expected 'error' field in 400 response")
	}
}

// TestHandler_SubmitFlow_VerificationPending_SessionNotIssued ensures that
// the session issuer is NOT called when the flow needs verification.
func TestHandler_SubmitFlow_VerificationPending_SessionNotIssued(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newVerificationPendingSubmitResult(tenant.ID)

	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return result, nil
		},
	}

	sessionCreateCalled := false
	issuer := &stubSessionIssuer{
		createFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ []string, _ time.Duration) (*session.Session, error) {
			sessionCreateCalled = true
			return nil, errors.New("should not be called")
		},
	}
	h := newHandler(eng, issuer)

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	if sessionCreateCalled {
		t.Error("session issuer Create must NOT be called when NeedsVerification is true")
	}
}

// TestHandler_SubmitFlow_Completed_EngineReceivesCorrectTenantAndFlowID ensures
// the handler passes the correct tenant ID and flow ID from the request context
// and URL parameter down to the engine.
func TestHandler_SubmitFlow_Completed_EngineReceivesCorrectTenantAndFlowID(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newCompletedSubmitResult(tenant.ID)

	var capturedTenantID, capturedFlowID uuid.UUID
	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, tid, fid uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			capturedTenantID = tid
			capturedFlowID = fid
			return result, nil
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	doRequest(h, req, tenant, f.ID.String())

	if capturedTenantID != tenant.ID {
		t.Errorf("engine received tenantID %s, want %s", capturedTenantID, tenant.ID)
	}
	if capturedFlowID != f.ID {
		t.Errorf("engine received flowID %s, want %s", capturedFlowID, f.ID)
	}
}

// TestHandler_SubmitFlow_Completed_SessionIssuedWithAAL1 ensures the session is
// created with aal1 on the completed (no-verification) path.
func TestHandler_SubmitFlow_Completed_SessionIssuedWithAAL1(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newCompletedSubmitResult(tenant.ID)

	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return result, nil
		},
	}

	var capturedAAL string
	issuer := &stubSessionIssuer{
		createFn: func(_ context.Context, _, _ uuid.UUID, aal string, _ []string, _ time.Duration) (*session.Session, error) {
			capturedAAL = aal
			return newTestSession(tenant.ID, result.IdentityID), nil
		},
	}
	h := newHandler(eng, issuer)

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if capturedAAL != "aal1" {
		t.Errorf("expected aal 'aal1' passed to session issuer, got %q", capturedAAL)
	}
}

// TestHandler_SubmitFlow_VerificationPending_VerificationFlowIDIsUUID verifies
// that the verification_flow_id in the response is a valid UUID string.
func TestHandler_SubmitFlow_VerificationPending_VerificationFlowIDIsUUID(t *testing.T) {
	tenant := newTestTenant()
	f := newTestFlow(tenant.ID)
	result := newVerificationPendingSubmitResult(tenant.ID)

	eng := &stubRegistrationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string, _ map[string]string) (*SubmitResult, error) {
			return result, nil
		},
	}
	h := newHandler(eng, &stubSessionIssuer{})

	reqBody := jsonBody(t, map[string]string{
		"method":       "password",
		"traits.email": "user@example.com",
		"password":     "S3cret!",
	})
	req := httptest.NewRequest(http.MethodPost, "/self-service/registration/flows/"+f.ID.String(), reqBody)
	req.Header.Set("Content-Type", "application/json")
	rr := doRequest(h, req, tenant, f.ID.String())

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := decodeJSON(t, rr)
	verifFlowIDStr, _ := body["verification_flow_id"].(string)
	if _, err := uuid.Parse(verifFlowIDStr); err != nil {
		t.Errorf("verification_flow_id %q is not a valid UUID: %v", verifFlowIDStr, err)
	}
}
