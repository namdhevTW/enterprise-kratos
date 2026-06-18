package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Fake store
// ---------------------------------------------------------------------------

type fakeSSOStore struct {
	createFn     func(tenantID uuid.UUID, typ, provider string, config json.RawMessage) (*Provider, error)
	getFn        func(tenantID, providerID uuid.UUID) (*Provider, error)
	listFn       func(tenantID uuid.UUID) ([]*Provider, error)
	deleteFn     func(tenantID, providerID uuid.UUID) error
	setEnabledFn func(tenantID, providerID uuid.UUID, enabled bool) error
}

func (f *fakeSSOStore) Create(ctx context.Context, tenantID uuid.UUID, typ, provider string, config json.RawMessage) (*Provider, error) {
	return f.createFn(tenantID, typ, provider, config)
}

func (f *fakeSSOStore) Get(ctx context.Context, tenantID, providerID uuid.UUID) (*Provider, error) {
	return f.getFn(tenantID, providerID)
}

func (f *fakeSSOStore) List(ctx context.Context, tenantID uuid.UUID) ([]*Provider, error) {
	return f.listFn(tenantID)
}

func (f *fakeSSOStore) Delete(ctx context.Context, tenantID, providerID uuid.UUID) error {
	return f.deleteFn(tenantID, providerID)
}

func (f *fakeSSOStore) SetEnabled(ctx context.Context, tenantID, providerID uuid.UUID, enabled bool) error {
	return f.setEnabledFn(tenantID, providerID, enabled)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var (
	testTenantID   = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	testProviderID = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

func testTenant() *internaltenant.Tenant {
	return &internaltenant.Tenant{
		ID:    testTenantID,
		Slug:  "acme",
		Name:  "Acme Corp",
		State: internaltenant.StateActive,
	}
}

func sampleProvider() *Provider {
	return &Provider{
		ID:       testProviderID,
		TenantID: testTenantID,
		Type:     "oidc",
		Provider: "google",
		Config:   json.RawMessage(`{"client_id":"cid","client_secret":"csec","issuer_url":"https://accounts.google.com","redirect_uri":"https://idp.example.com/callback"}`),
		Enabled:  true,
	}
}

// newRouter builds a chi router with the handler mounted.
func newRouter(store ssoStore) *chi.Mux {
	r := chi.NewRouter()
	h := NewHandler(store)
	h.Mount(r)
	return r
}

// withTenantCtx injects a tenant into the request context.
func withTenantCtx(req *http.Request, t *internaltenant.Tenant) *http.Request {
	return req.WithContext(internaltenant.WithTenant(req.Context(), t))
}

// withProviderIDParam injects a chi URL parameter for {providerId}.
func withProviderIDParam(req *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("providerId", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// withTenantAndProviderID injects both the tenant context and the chi route param.
func withTenantAndProviderID(req *http.Request, t *internaltenant.Tenant, providerID string) *http.Request {
	req = withTenantCtx(req, t)
	return withProviderIDParam(req, providerID)
}

// decodeJSON is a small helper to unmarshal a response body into v.
func decodeJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("decodeJSON: %v (body: %s)", err, body)
	}
}

// assertStatus fails the test if the recorded status does not match want.
func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("status: got %d, want %d (body: %s)", rec.Code, want, rec.Body.String())
	}
}

// panicStore returns a store whose every method panics — useful for tests that
// expect the handler to return before ever calling the store.
func panicStore() *fakeSSOStore {
	return &fakeSSOStore{
		createFn: func(_ uuid.UUID, _, _ string, _ json.RawMessage) (*Provider, error) {
			panic("create called unexpectedly")
		},
		getFn: func(_, _ uuid.UUID) (*Provider, error) {
			panic("get called unexpectedly")
		},
		listFn: func(_ uuid.UUID) ([]*Provider, error) {
			panic("list called unexpectedly")
		},
		deleteFn: func(_, _ uuid.UUID) error {
			panic("delete called unexpectedly")
		},
		setEnabledFn: func(_, _ uuid.UUID, _ bool) error {
			panic("setEnabled called unexpectedly")
		},
	}
}

// ---------------------------------------------------------------------------
// POST /admin/sso/providers — create
// ---------------------------------------------------------------------------

func TestCreate_Success(t *testing.T) {
	store := &fakeSSOStore{
		createFn: func(tenantID uuid.UUID, typ, provider string, config json.RawMessage) (*Provider, error) {
			if tenantID != testTenantID {
				t.Errorf("createFn: tenantID got %s, want %s", tenantID, testTenantID)
			}
			if typ != "oidc" {
				t.Errorf("createFn: type got %s, want oidc", typ)
			}
			if provider != "google" {
				t.Errorf("createFn: provider got %s, want google", provider)
			}
			return sampleProvider(), nil
		},
	}
	body := `{"type":"oidc","provider":"google","config":{"client_id":"cid","client_secret":"csec","issuer_url":"https://accounts.google.com","redirect_uri":"https://idp.example.com/callback"}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers", bytes.NewBufferString(body))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusCreated)

	var resp providerResponse
	decodeJSON(t, rec.Body.Bytes(), &resp)
	if resp.ID != testProviderID.String() {
		t.Errorf("id: got %s, want %s", resp.ID, testProviderID.String())
	}
	if resp.Type != "oidc" {
		t.Errorf("type: got %s, want oidc", resp.Type)
	}
	if resp.Provider != "google" {
		t.Errorf("provider: got %s, want google", resp.Provider)
	}
	if !resp.Enabled {
		t.Error("enabled: got false, want true")
	}
}

func TestCreate_NoTenant(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers",
		bytes.NewBufferString(`{"type":"oidc","provider":"google","config":{}}`))
	// no tenant injected into context

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestCreate_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers",
		bytes.NewBufferString(`not-json`))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)
}

func TestCreate_InvalidType(t *testing.T) {
	body := `{"type":"oauth1","provider":"twitter","config":{"key":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers", bytes.NewBufferString(body))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)

	var errResp map[string]string
	decodeJSON(t, rec.Body.Bytes(), &errResp)
	if errResp["error"] == "" {
		t.Error("expected non-empty error message in response body")
	}
}

func TestCreate_MissingProvider(t *testing.T) {
	body := `{"type":"oidc","provider":"","config":{"key":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers", bytes.NewBufferString(body))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)
}

func TestCreate_EmptyConfig(t *testing.T) {
	body := `{"type":"saml","provider":"okta"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers", bytes.NewBufferString(body))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)
}

func TestCreate_StoreError(t *testing.T) {
	store := &fakeSSOStore{
		createFn: func(_ uuid.UUID, _, _ string, _ json.RawMessage) (*Provider, error) {
			return nil, fmt.Errorf("db unavailable")
		},
	}
	body := `{"type":"oidc","provider":"google","config":{"key":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers", bytes.NewBufferString(body))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// GET /admin/sso/providers — list
// ---------------------------------------------------------------------------

func TestList_Success(t *testing.T) {
	p2 := &Provider{
		ID:       uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		TenantID: testTenantID,
		Type:     "saml",
		Provider: "okta",
		Config:   json.RawMessage(`{"metadata_url":"https://okta.example.com/saml/metadata","sp_id":"urn:idp:acme"}`),
		Enabled:  false,
	}
	store := &fakeSSOStore{
		listFn: func(tenantID uuid.UUID) ([]*Provider, error) {
			if tenantID != testTenantID {
				t.Errorf("listFn: tenantID got %s, want %s", tenantID, testTenantID)
			}
			return []*Provider{sampleProvider(), p2}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers", nil)
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusOK)

	var resp struct {
		Providers []providerResponse `json:"providers"`
	}
	decodeJSON(t, rec.Body.Bytes(), &resp)
	if len(resp.Providers) != 2 {
		t.Fatalf("providers length: got %d, want 2", len(resp.Providers))
	}
	if resp.Providers[0].ID != testProviderID.String() {
		t.Errorf("providers[0].id: got %s, want %s", resp.Providers[0].ID, testProviderID.String())
	}
	if resp.Providers[1].Type != "saml" {
		t.Errorf("providers[1].type: got %s, want saml", resp.Providers[1].Type)
	}
}

func TestList_NoTenant(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers", nil)
	// no tenant in context

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestList_EmptyList(t *testing.T) {
	store := &fakeSSOStore{
		listFn: func(_ uuid.UUID) ([]*Provider, error) {
			return []*Provider{}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers", nil)
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusOK)

	var resp struct {
		Providers []providerResponse `json:"providers"`
	}
	decodeJSON(t, rec.Body.Bytes(), &resp)
	if len(resp.Providers) != 0 {
		t.Errorf("providers length: got %d, want 0", len(resp.Providers))
	}
}

func TestList_EmptyListNilSlice(t *testing.T) {
	// Store returns nil slice (e.g. no rows found) — must still produce {providers: []}.
	store := &fakeSSOStore{
		listFn: func(_ uuid.UUID) ([]*Provider, error) {
			return nil, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers", nil)
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusOK)
}

func TestList_StoreError(t *testing.T) {
	store := &fakeSSOStore{
		listFn: func(_ uuid.UUID) ([]*Provider, error) {
			return nil, fmt.Errorf("connection reset")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers", nil)
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// GET /admin/sso/providers/{providerId} — get
// ---------------------------------------------------------------------------

func TestGet_Success(t *testing.T) {
	store := &fakeSSOStore{
		getFn: func(tenantID, providerID uuid.UUID) (*Provider, error) {
			if tenantID != testTenantID {
				t.Errorf("getFn: tenantID got %s, want %s", tenantID, testTenantID)
			}
			if providerID != testProviderID {
				t.Errorf("getFn: providerID got %s, want %s", providerID, testProviderID)
			}
			return sampleProvider(), nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusOK)

	var resp providerResponse
	decodeJSON(t, rec.Body.Bytes(), &resp)
	if resp.ID != testProviderID.String() {
		t.Errorf("id: got %s, want %s", resp.ID, testProviderID.String())
	}
	if resp.Type != "oidc" {
		t.Errorf("type: got %s, want oidc", resp.Type)
	}
	if resp.Provider != "google" {
		t.Errorf("provider: got %s, want google", resp.Provider)
	}
}

func TestGet_NoTenant(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withProviderIDParam(req, testProviderID.String())
	// no tenant in context

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestGet_InvalidUUID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers/not-a-uuid", nil)
	req = withTenantAndProviderID(req, testTenant(), "not-a-uuid")

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)
}

func TestGet_NotFound(t *testing.T) {
	store := &fakeSSOStore{
		getFn: func(_, _ uuid.UUID) (*Provider, error) {
			return nil, fmt.Errorf("sso.Get %s: %w", testProviderID, ErrNotFound)
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNotFound)

	var errResp map[string]string
	decodeJSON(t, rec.Body.Bytes(), &errResp)
	if errResp["error"] == "" {
		t.Error("expected non-empty error in response body for 404")
	}
}

func TestGet_StoreError(t *testing.T) {
	store := &fakeSSOStore{
		getFn: func(_, _ uuid.UUID) (*Provider, error) {
			return nil, fmt.Errorf("unexpected db error")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// DELETE /admin/sso/providers/{providerId} — delete
// ---------------------------------------------------------------------------

func TestDelete_Success(t *testing.T) {
	deleteCalled := false
	store := &fakeSSOStore{
		deleteFn: func(tenantID, providerID uuid.UUID) error {
			deleteCalled = true
			if tenantID != testTenantID {
				t.Errorf("deleteFn: tenantID got %s, want %s", tenantID, testTenantID)
			}
			if providerID != testProviderID {
				t.Errorf("deleteFn: providerID got %s, want %s", providerID, testProviderID)
			}
			return nil
		},
	}
	req := httptest.NewRequest(http.MethodDelete, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNoContent)
	if !deleteCalled {
		t.Error("store.Delete was not called")
	}
}

func TestDelete_NoTenant(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withProviderIDParam(req, testProviderID.String())
	// no tenant in context

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestDelete_InvalidUUID(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/admin/sso/providers/garbage", nil)
	req = withTenantAndProviderID(req, testTenant(), "garbage")

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)
}

func TestDelete_NotFound(t *testing.T) {
	store := &fakeSSOStore{
		deleteFn: func(_, _ uuid.UUID) error {
			return fmt.Errorf("sso.Delete %s: %w", testProviderID, ErrNotFound)
		},
	}
	req := httptest.NewRequest(http.MethodDelete, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNotFound)
}

func TestDelete_StoreError(t *testing.T) {
	store := &fakeSSOStore{
		deleteFn: func(_, _ uuid.UUID) error {
			return fmt.Errorf("lock timeout")
		},
	}
	req := httptest.NewRequest(http.MethodDelete, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// PATCH /admin/sso/providers/{providerId}/enabled — setEnabled
// ---------------------------------------------------------------------------

func TestSetEnabled_SuccessTrue(t *testing.T) {
	var capturedEnabled bool
	store := &fakeSSOStore{
		setEnabledFn: func(tenantID, providerID uuid.UUID, enabled bool) error {
			capturedEnabled = enabled
			if tenantID != testTenantID {
				t.Errorf("setEnabledFn: tenantID got %s, want %s", tenantID, testTenantID)
			}
			if providerID != testProviderID {
				t.Errorf("setEnabledFn: providerID got %s, want %s", providerID, testProviderID)
			}
			return nil
		},
	}
	req := httptest.NewRequest(
		http.MethodPatch,
		"/admin/sso/providers/"+testProviderID.String()+"/enabled",
		bytes.NewBufferString(`{"enabled":true}`),
	)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNoContent)
	if !capturedEnabled {
		t.Error("setEnabledFn: enabled was false, want true")
	}
}

func TestSetEnabled_SuccessFalse(t *testing.T) {
	var capturedEnabled = true // start true so we can verify it flips
	store := &fakeSSOStore{
		setEnabledFn: func(_, _ uuid.UUID, enabled bool) error {
			capturedEnabled = enabled
			return nil
		},
	}
	req := httptest.NewRequest(
		http.MethodPatch,
		"/admin/sso/providers/"+testProviderID.String()+"/enabled",
		bytes.NewBufferString(`{"enabled":false}`),
	)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNoContent)
	if capturedEnabled {
		t.Error("setEnabledFn: enabled was true, want false")
	}
}

func TestSetEnabled_NoTenant(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPatch,
		"/admin/sso/providers/"+testProviderID.String()+"/enabled",
		bytes.NewBufferString(`{"enabled":true}`),
	)
	req = withProviderIDParam(req, testProviderID.String())
	// no tenant in context

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusUnauthorized)
}

func TestSetEnabled_InvalidUUID(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPatch,
		"/admin/sso/providers/bad-id/enabled",
		bytes.NewBufferString(`{"enabled":true}`),
	)
	req = withTenantAndProviderID(req, testTenant(), "bad-id")

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)
}

func TestSetEnabled_InvalidJSONBody(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPatch,
		"/admin/sso/providers/"+testProviderID.String()+"/enabled",
		bytes.NewBufferString(`{bad json`),
	)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(panicStore()).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusBadRequest)
}

func TestSetEnabled_NotFound(t *testing.T) {
	store := &fakeSSOStore{
		setEnabledFn: func(_, _ uuid.UUID, _ bool) error {
			return fmt.Errorf("sso.SetEnabled %s: %w", testProviderID, ErrNotFound)
		},
	}
	req := httptest.NewRequest(
		http.MethodPatch,
		"/admin/sso/providers/"+testProviderID.String()+"/enabled",
		bytes.NewBufferString(`{"enabled":true}`),
	)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNotFound)
}

func TestSetEnabled_StoreError(t *testing.T) {
	store := &fakeSSOStore{
		setEnabledFn: func(_, _ uuid.UUID, _ bool) error {
			return fmt.Errorf("write conflict")
		},
	}
	req := httptest.NewRequest(
		http.MethodPatch,
		"/admin/sso/providers/"+testProviderID.String()+"/enabled",
		bytes.NewBufferString(`{"enabled":true}`),
	)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// Content-Type header sanity checks
// ---------------------------------------------------------------------------

func TestCreate_ResponseContentType(t *testing.T) {
	store := &fakeSSOStore{
		createFn: func(_ uuid.UUID, _, _ string, _ json.RawMessage) (*Provider, error) {
			return sampleProvider(), nil
		},
	}
	body := `{"type":"oidc","provider":"google","config":{"key":"val"}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers", bytes.NewBufferString(body))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
}

func TestList_ResponseContentType(t *testing.T) {
	store := &fakeSSOStore{
		listFn: func(_ uuid.UUID) ([]*Provider, error) {
			return []*Provider{sampleProvider()}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers", nil)
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}
}

// ---------------------------------------------------------------------------
// Error body shape
// ---------------------------------------------------------------------------

func TestGet_ErrorBodyShape(t *testing.T) {
	store := &fakeSSOStore{
		getFn: func(_, _ uuid.UUID) (*Provider, error) {
			return nil, fmt.Errorf("wrapped: %w", ErrNotFound)
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNotFound)

	var body map[string]string
	decodeJSON(t, rec.Body.Bytes(), &body)
	if _, ok := body["error"]; !ok {
		t.Errorf("response body missing 'error' key: %s", rec.Body.String())
	}
}

func TestDelete_ErrorBodyShape(t *testing.T) {
	store := &fakeSSOStore{
		deleteFn: func(_, _ uuid.UUID) error {
			return fmt.Errorf("wrapped: %w", ErrNotFound)
		},
	}
	req := httptest.NewRequest(http.MethodDelete, "/admin/sso/providers/"+testProviderID.String(), nil)
	req = withTenantAndProviderID(req, testTenant(), testProviderID.String())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusNotFound)

	var body map[string]string
	decodeJSON(t, rec.Body.Bytes(), &body)
	if _, ok := body["error"]; !ok {
		t.Errorf("response body missing 'error' key: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// SAML provider variant
// ---------------------------------------------------------------------------

func TestCreate_SuccessSAML(t *testing.T) {
	samlProvider := &Provider{
		ID:       uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		TenantID: testTenantID,
		Type:     "saml",
		Provider: "azure",
		Config:   json.RawMessage(`{"metadata_url":"https://login.microsoftonline.com/tid/FederationMetadata","sp_id":"urn:idp:acme"}`),
		Enabled:  true,
	}
	store := &fakeSSOStore{
		createFn: func(_ uuid.UUID, typ, provider string, _ json.RawMessage) (*Provider, error) {
			if typ != "saml" {
				t.Errorf("createFn: type got %s, want saml", typ)
			}
			if provider != "azure" {
				t.Errorf("createFn: provider got %s, want azure", provider)
			}
			return samlProvider, nil
		},
	}
	body := `{"type":"saml","provider":"azure","config":{"metadata_url":"https://login.microsoftonline.com/tid/FederationMetadata","sp_id":"urn:idp:acme"}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/sso/providers", bytes.NewBufferString(body))
	req = withTenantCtx(req, testTenant())

	rec := httptest.NewRecorder()
	newRouter(store).ServeHTTP(rec, req)

	assertStatus(t, rec, http.StatusCreated)

	var resp providerResponse
	decodeJSON(t, rec.Body.Bytes(), &resp)
	if resp.Type != "saml" {
		t.Errorf("type: got %s, want saml", resp.Type)
	}
	if resp.Provider != "azure" {
		t.Errorf("provider: got %s, want azure", resp.Provider)
	}
}
