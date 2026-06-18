package verification

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/enterprise-idp/idpd/internal/flow"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Fake verificationEngine
// ---------------------------------------------------------------------------

type fakeVerificationEngine struct {
	getFlowFn    func(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	submitFlowFn func(ctx context.Context, tenantID, flowID uuid.UUID, token string) error
}

func (f *fakeVerificationEngine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	if f.getFlowFn != nil {
		return f.getFlowFn(ctx, tenantID, flowID)
	}
	return nil, flow.ErrNotFound
}

func (f *fakeVerificationEngine) SubmitFlow(ctx context.Context, tenantID, flowID uuid.UUID, token string) error {
	if f.submitFlowFn != nil {
		return f.submitFlowFn(ctx, tenantID, flowID, token)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// buildTenant creates a *tenant.Tenant with a fixed UUID and slug for use in
// tests that need a resolved tenant context.
func buildTenant() *internaltenant.Tenant {
	return &internaltenant.Tenant{
		ID:    uuid.New(),
		Slug:  "acme",
		Name:  "Acme Corp",
		State: internaltenant.StateActive,
	}
}

// buildFlow constructs a minimal *flow.Flow suitable for handler tests.
func buildFlow(tenantID uuid.UUID) *flow.Flow {
	return &flow.Flow{
		ID:       uuid.New(),
		TenantID: tenantID,
		Type:     flow.TypeVerification,
		State:    flow.StatePending,
	}
}

// newChiContext returns a context enriched with a chi URL parameter for flowId.
func newChiContext(ctx context.Context, flowID string) context.Context {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("flowId", flowID)
	return context.WithValue(ctx, chi.RouteCtxKey, rctx)
}

// executeGetFlow sends a GET request through the handler's getFlow method
// without going through a real chi router (which avoids wiring chi middleware
// in tests while still letting chi.URLParam work via newChiContext).
func executeGetFlow(h *Handler, ctx context.Context, flowIDParam, token string) *httptest.ResponseRecorder {
	target := "/self-service/verification/flows/" + flowIDParam
	if token != "" {
		target += "?token=" + token
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	h.getFlow(rr, req)
	return rr
}

// executeSubmitFlow sends a POST request through the handler's submitFlow
// method.  body is JSON-encoded before sending.
func executeSubmitFlow(h *Handler, ctx context.Context, flowIDParam string, body map[string]string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(http.MethodPost, "/self-service/verification/flows/"+flowIDParam, &buf)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	h.submitFlow(rr, req)
	return rr
}

// decodeBody is a convenience that decodes the response recorder body into a
// map[string]string and fails the test if decoding fails.
func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&m); err != nil {
		t.Fatalf("failed to decode response body: %v (body: %s)", err, rr.Body.String())
	}
	return m
}

// ---------------------------------------------------------------------------
// getFlow — no ?token query param (plain flow fetch)
// ---------------------------------------------------------------------------

func TestGetFlow_NoToken_Success(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	f := buildFlow(ten.ID)

	engine := &fakeVerificationEngine{
		getFlowFn: func(_ context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
			if tenantID != ten.ID {
				t.Errorf("GetFlow tenantID=%s, want %s", tenantID, ten.ID)
			}
			if flowID != f.ID {
				t.Errorf("GetFlow flowID=%s, want %s", flowID, f.ID)
			}
			return f, nil
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, f.ID.String())

	rr := executeGetFlow(h, ctx, f.ID.String(), "")

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	// Response must include at least the flow ID.
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got, ok := resp["id"].(string); !ok || got != f.ID.String() {
		t.Errorf("response id=%q, want %q", got, f.ID.String())
	}
}

func TestGetFlow_NoToken_NoTenant_Returns401(t *testing.T) {
	t.Parallel()
	flowID := uuid.New()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	// Context has NO tenant injected.
	ctx := newChiContext(context.Background(), flowID.String())
	rr := executeGetFlow(h, ctx, flowID.String(), "")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestGetFlow_NoToken_InvalidFlowID_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, "not-a-uuid")

	rr := executeGetFlow(h, ctx, "not-a-uuid", "")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestGetFlow_NoToken_ErrNotFound_Returns404(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, flow.ErrNotFound
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeGetFlow(h, ctx, flowID.String(), "")

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestGetFlow_NoToken_ErrExpired_Returns410(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return nil, flow.ErrExpired
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeGetFlow(h, ctx, flowID.String(), "")

	if rr.Code != http.StatusGone {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusGone)
	}
}

// ---------------------------------------------------------------------------
// getFlow — with ?token= query param (email link click / inline verification)
// ---------------------------------------------------------------------------

func TestGetFlow_WithToken_Success_Returns200WithSuccessState(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()
	tok := "valid-tok"

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, tenantID, fid uuid.UUID, token string) error {
			if tenantID != ten.ID {
				t.Errorf("SubmitFlow tenantID=%s, want %s", tenantID, ten.ID)
			}
			if fid != flowID {
				t.Errorf("SubmitFlow flowID=%s, want %s", fid, flowID)
			}
			if token != tok {
				t.Errorf("SubmitFlow token=%q, want %q", token, tok)
			}
			return nil
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeGetFlow(h, ctx, flowID.String(), tok)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if body["state"] != "success" {
		t.Errorf("body[state] = %q, want %q", body["state"], "success")
	}
}

func TestGetFlow_WithToken_InvalidToken_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return &invalidTokenError{"bad token"}
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeGetFlow(h, ctx, flowID.String(), "wrong-token")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestGetFlow_WithToken_ErrNotFound_Returns404(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return flow.ErrNotFound
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeGetFlow(h, ctx, flowID.String(), "some-token")

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestGetFlow_WithToken_ErrExpired_Returns410(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return flow.ErrExpired
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeGetFlow(h, ctx, flowID.String(), "expired-token")

	if rr.Code != http.StatusGone {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusGone)
	}
}

// ---------------------------------------------------------------------------
// submitFlow — POST /self-service/verification/flows/{flowId}
// ---------------------------------------------------------------------------

func TestSubmitFlow_Success_Returns200WithSuccessState(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()
	tok := "good-token"

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, tenantID, fid uuid.UUID, token string) error {
			if tenantID != ten.ID {
				t.Errorf("SubmitFlow tenantID=%s, want %s", tenantID, ten.ID)
			}
			if fid != flowID {
				t.Errorf("SubmitFlow flowID=%s, want %s", fid, flowID)
			}
			if token != tok {
				t.Errorf("SubmitFlow token=%q, want %q", token, tok)
			}
			return nil
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": tok})

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if body["state"] != "success" {
		t.Errorf("body[state] = %q, want %q", body["state"], "success")
	}
}

func TestSubmitFlow_NoTenant_Returns401(t *testing.T) {
	t.Parallel()
	flowID := uuid.New()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	// No tenant in context.
	ctx := newChiContext(context.Background(), flowID.String())
	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": "tok"})

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestSubmitFlow_InvalidFlowID_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, "bad-uuid")

	rr := executeSubmitFlow(h, ctx, "bad-uuid", map[string]string{"token": "tok"})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestSubmitFlow_MissingToken_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	// Token key absent from body.
	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	body := decodeBody(t, rr)
	if body["error"] == "" {
		t.Error("expected a non-empty error message in body")
	}
}

func TestSubmitFlow_InvalidToken_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return &invalidTokenError{"invalid token"}
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": "wrong"})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestSubmitFlow_ErrNotFound_Returns404(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return flow.ErrNotFound
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": "any"})

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestSubmitFlow_ErrExpired_Returns410(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string) error {
			return flow.ErrExpired
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": "any"})

	if rr.Code != http.StatusGone {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusGone)
	}
}

// ---------------------------------------------------------------------------
// Response shape assertions
// ---------------------------------------------------------------------------

func TestGetFlow_NoToken_Success_ResponseShape(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	f := buildFlow(ten.ID)
	f.Type = flow.TypeVerification
	f.State = flow.StatePending

	engine := &fakeVerificationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, f.ID.String())
	rr := executeGetFlow(h, ctx, f.ID.String(), "")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	for _, field := range []string{"id", "type", "state", "ui"} {
		if _, ok := resp[field]; !ok {
			t.Errorf("response missing field %q", field)
		}
	}
	if resp["id"] != f.ID.String() {
		t.Errorf("id=%v, want %v", resp["id"], f.ID.String())
	}
	if resp["type"] != string(flow.TypeVerification) {
		t.Errorf("type=%v, want %v", resp["type"], flow.TypeVerification)
	}
	if resp["state"] != string(flow.StatePending) {
		t.Errorf("state=%v, want %v", resp["state"], flow.StatePending)
	}

	// UI action must contain the tenant slug and flow id.
	ui, ok := resp["ui"].(map[string]any)
	if !ok {
		t.Fatal("ui field is not an object")
	}
	action, _ := ui["action"].(string)
	if action == "" {
		t.Error("ui.action is empty")
	}
}

func TestGetFlow_NoToken_Success_ContentTypeIsJSON(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	f := buildFlow(ten.ID)

	engine := &fakeVerificationEngine{
		getFlowFn: func(_ context.Context, _, _ uuid.UUID) (*flow.Flow, error) {
			return f, nil
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, f.ID.String())
	rr := executeGetFlow(h, ctx, f.ID.String(), "")

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestSubmitFlow_Success_ContentTypeIsJSON(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, _, _ uuid.UUID, _ string) error { return nil },
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())
	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": "good"})

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

// TestGetFlow_WithToken_NoTenant_Returns401 ensures that even when a ?token=
// query param is present the handler still enforces tenant resolution first.
func TestGetFlow_WithToken_NoTenant_Returns401(t *testing.T) {
	t.Parallel()
	flowID := uuid.New()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	// No tenant injected — bare context.
	ctx := newChiContext(context.Background(), flowID.String())
	rr := executeGetFlow(h, ctx, flowID.String(), "some-token")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestGetFlow_WithToken_InvalidFlowID_Returns400 ensures that an unparseable
// flowId causes a 400 even when a token is present.
func TestGetFlow_WithToken_InvalidFlowID_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, "not-a-valid-uuid")
	rr := executeGetFlow(h, ctx, "not-a-valid-uuid", "tok")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestSubmitFlow_MalformedJSON_Returns400 sends a non-JSON body and expects 400.
func TestSubmitFlow_MalformedJSON_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	req := httptest.NewRequest(http.MethodPost, "/self-service/verification/flows/"+flowID.String(),
		bytes.NewBufferString("this is { not json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	h.submitFlow(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestSubmitFlow_EmptyStringToken_Returns400 ensures that an explicit empty
// token value is treated the same as a missing token.
func TestSubmitFlow_EmptyStringToken_Returns400(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()
	engine := &fakeVerificationEngine{}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())

	// Token key is present but value is "".
	rr := executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": ""})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// TestGetFlow_WithToken_TenantIDPassedToEngine verifies that the handler
// forwards the resolved tenant's ID (not a zero UUID) to the engine.
func TestGetFlow_WithToken_TenantIDPassedToEngine(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	var capturedTenantID uuid.UUID
	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, tenantID, _ uuid.UUID, _ string) error {
			capturedTenantID = tenantID
			return nil
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())
	executeGetFlow(h, ctx, flowID.String(), "tok")

	if capturedTenantID != ten.ID {
		t.Errorf("engine received tenantID=%s, want %s", capturedTenantID, ten.ID)
	}
}

// TestSubmitFlow_TenantIDPassedToEngine mirrors the above for POST.
func TestSubmitFlow_TenantIDPassedToEngine(t *testing.T) {
	t.Parallel()
	ten := buildTenant()
	flowID := uuid.New()

	var capturedTenantID uuid.UUID
	engine := &fakeVerificationEngine{
		submitFlowFn: func(_ context.Context, tenantID, _ uuid.UUID, _ string) error {
			capturedTenantID = tenantID
			return nil
		},
	}
	h := NewHandler(engine)

	ctx := internaltenant.WithTenant(context.Background(), ten)
	ctx = newChiContext(ctx, flowID.String())
	executeSubmitFlow(h, ctx, flowID.String(), map[string]string{"token": "tok"})

	if capturedTenantID != ten.ID {
		t.Errorf("engine received tenantID=%s, want %s", capturedTenantID, ten.ID)
	}
}

// ---------------------------------------------------------------------------
// invalidTokenError — a plain error type used to simulate token validation
// failures that are neither ErrNotFound nor ErrExpired.
// ---------------------------------------------------------------------------

type invalidTokenError struct{ msg string }

func (e *invalidTokenError) Error() string { return e.msg }
