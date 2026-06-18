package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---- fake engine ------------------------------------------------------------

type fakeOIDCEngine struct {
	initiateURL string
	initiateErr error
	callback    *CallbackResult
	callbackErr error
}

func (f *fakeOIDCEngine) InitiateLogin(_ context.Context, _, _, _ uuid.UUID) (string, error) {
	return f.initiateURL, f.initiateErr
}
func (f *fakeOIDCEngine) HandleCallback(_ context.Context, _ uuid.UUID, _, _ string) (*CallbackResult, error) {
	return f.callback, f.callbackErr
}

// ---- helpers ----------------------------------------------------------------

func handlerRouter(engine oidcEngine, tenantID uuid.UUID) *chi.Mux {
	h := NewHandler(engine)
	r := chi.NewRouter()
	r.Route("/t/{tenant-slug}", func(r chi.Router) {
		// Inject a fake tenant so the handler can read it from context.
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				t := &internaltenant.Tenant{ID: tenantID, Slug: "test"}
				ctx := internaltenant.WithTenant(req.Context(), t)
				next.ServeHTTP(w, req.WithContext(ctx))
			})
		})
		h.Mount(r)
	})
	return r
}

func makeRequest(method, path string, body any) *http.Request {
	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func testCallbackResult(tenantID, identityID uuid.UUID) *CallbackResult {
	return &CallbackResult{
		Session: &session.Session{
			ID:         uuid.New(),
			TenantID:   tenantID,
			IdentityID: identityID,
			Token:      "sess-token",
			AAL:        "aal1",
			AMR:        []string{"oidc"},
		},
		IdentityID: identityID,
		IsNew:      false,
	}
}

// ---- initiate tests ---------------------------------------------------------

func TestHandler_Initiate_Success(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	providerID := uuid.New()

	engine := &fakeOIDCEngine{initiateURL: "https://accounts.google.com/o/oauth2/auth?..."}
	r := handlerRouter(engine, tenantID)

	body := map[string]string{"provider_id": providerID.String()}
	path := "/t/test/self-service/login/flows/" + flowID.String() + "/methods/oidc"
	req := makeRequest(http.MethodPost, path, body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["redirect_to"] == "" {
		t.Error("redirect_to is empty")
	}
}

func TestHandler_Initiate_NoTenant(t *testing.T) {
	engine := &fakeOIDCEngine{initiateURL: "https://example.com/auth"}
	h := NewHandler(engine)
	r := chi.NewRouter()
	h.Mount(r)

	flowID := uuid.New()
	body := map[string]string{"provider_id": uuid.New().String()}
	req := makeRequest(http.MethodPost, "/self-service/login/flows/"+flowID.String()+"/methods/oidc", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandler_Initiate_InvalidFlowID(t *testing.T) {
	tenantID := uuid.New()
	engine := &fakeOIDCEngine{}
	r := handlerRouter(engine, tenantID)

	body := map[string]string{"provider_id": uuid.New().String()}
	req := makeRequest(http.MethodPost, "/t/test/self-service/login/flows/not-a-uuid/methods/oidc", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandler_Initiate_InvalidBody(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	engine := &fakeOIDCEngine{}
	r := handlerRouter(engine, tenantID)

	req := makeRequest(http.MethodPost, "/t/test/self-service/login/flows/"+flowID.String()+"/methods/oidc", nil)
	req.Body = http.NoBody
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Empty body decodes as empty map, so provider_id is "" → parse error
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandler_Initiate_InvalidProviderID(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	engine := &fakeOIDCEngine{}
	r := handlerRouter(engine, tenantID)

	body := map[string]string{"provider_id": "not-a-uuid"}
	req := makeRequest(http.MethodPost, "/t/test/self-service/login/flows/"+flowID.String()+"/methods/oidc", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandler_Initiate_EngineError_NotFound(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	engine := &fakeOIDCEngine{initiateErr: flow.ErrNotFound}
	r := handlerRouter(engine, tenantID)

	body := map[string]string{"provider_id": uuid.New().String()}
	req := makeRequest(http.MethodPost, "/t/test/self-service/login/flows/"+flowID.String()+"/methods/oidc", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandler_Initiate_EngineError_Expired(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	engine := &fakeOIDCEngine{initiateErr: flow.ErrExpired}
	r := handlerRouter(engine, tenantID)

	body := map[string]string{"provider_id": uuid.New().String()}
	req := makeRequest(http.MethodPost, "/t/test/self-service/login/flows/"+flowID.String()+"/methods/oidc", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want 410", w.Code)
	}
}

func TestHandler_Initiate_EngineError_Other(t *testing.T) {
	tenantID := uuid.New()
	flowID := uuid.New()
	engine := &fakeOIDCEngine{initiateErr: errors.New("provider disabled")}
	r := handlerRouter(engine, tenantID)

	body := map[string]string{"provider_id": uuid.New().String()}
	req := makeRequest(http.MethodPost, "/t/test/self-service/login/flows/"+flowID.String()+"/methods/oidc", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---- callback tests ---------------------------------------------------------

func TestHandler_Callback_Success(t *testing.T) {
	tenantID := uuid.New()
	identityID := uuid.New()
	flowID := uuid.New()
	engine := &fakeOIDCEngine{callback: testCallbackResult(tenantID, identityID)}
	r := handlerRouter(engine, tenantID)

	path := "/t/test/self-service/login/flows/oidc/callback?state=" + flowID.String() + "&code=authcode123"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["session_token"] == nil {
		t.Error("session_token missing from response")
	}
}

func TestHandler_Callback_NoTenant(t *testing.T) {
	engine := &fakeOIDCEngine{}
	h := NewHandler(engine)
	r := chi.NewRouter()
	h.Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/self-service/login/flows/oidc/callback?state="+uuid.New().String()+"&code=x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandler_Callback_OIDCProviderError(t *testing.T) {
	tenantID := uuid.New()
	engine := &fakeOIDCEngine{}
	r := handlerRouter(engine, tenantID)

	path := "/t/test/self-service/login/flows/oidc/callback?error=access_denied&error_description=user+denied"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "access_denied" {
		t.Errorf("error field = %q", resp["error"])
	}
}

func TestHandler_Callback_MissingParams(t *testing.T) {
	tenantID := uuid.New()
	engine := &fakeOIDCEngine{}
	r := handlerRouter(engine, tenantID)

	req := httptest.NewRequest(http.MethodGet, "/t/test/self-service/login/flows/oidc/callback", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandler_Callback_EngineError_NotFound(t *testing.T) {
	tenantID := uuid.New()
	engine := &fakeOIDCEngine{callbackErr: flow.ErrNotFound}
	r := handlerRouter(engine, tenantID)

	path := "/t/test/self-service/login/flows/oidc/callback?state=" + uuid.New().String() + "&code=x"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandler_Callback_EngineError_Expired(t *testing.T) {
	tenantID := uuid.New()
	engine := &fakeOIDCEngine{callbackErr: flow.ErrExpired}
	r := handlerRouter(engine, tenantID)

	path := "/t/test/self-service/login/flows/oidc/callback?state=" + uuid.New().String() + "&code=x"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want 410", w.Code)
	}
}

func TestHandler_Callback_EngineError_Other(t *testing.T) {
	tenantID := uuid.New()
	engine := &fakeOIDCEngine{callbackErr: errors.New("nonce mismatch")}
	r := handlerRouter(engine, tenantID)

	path := "/t/test/self-service/login/flows/oidc/callback?state=" + uuid.New().String() + "&code=x"
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
