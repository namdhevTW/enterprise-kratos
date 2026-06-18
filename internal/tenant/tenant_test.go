package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestTenant builds a *Tenant with deterministic values for use in tests.
func newTestTenant() *Tenant {
	return &Tenant{
		ID:    uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Slug:  "acme",
		Name:  "Acme Corp",
		State: StateActive,
	}
}

// ---------------------------------------------------------------------------
// fakeRepo — satisfies the Repository interface without a real database.
// ---------------------------------------------------------------------------

type fakeRepo struct {
	returnTenant *Tenant
	returnErr    error
}

func (f *fakeRepo) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	return f.returnTenant, f.returnErr
}

func (f *fakeRepo) GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	return f.returnTenant, f.returnErr
}

func (f *fakeRepo) Create(ctx context.Context, slug, name string) (*Tenant, error) {
	return f.returnTenant, f.returnErr
}

func (f *fakeRepo) UpdateState(ctx context.Context, id uuid.UUID, state string) error {
	return f.returnErr
}

func (f *fakeRepo) List(ctx context.Context) ([]*Tenant, error) {
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	if f.returnTenant != nil {
		return []*Tenant{f.returnTenant}, nil
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// context.go tests
// ---------------------------------------------------------------------------

func TestWithTenant_ReturnsContextWithTenant(t *testing.T) {
	want := newTestTenant()
	ctx := WithTenant(context.Background(), want)
	if ctx == nil {
		t.Fatal("WithTenant returned nil context")
	}
}

func TestTenantFromContext_ReturnsTenantSetByWithTenant(t *testing.T) {
	want := newTestTenant()
	ctx := WithTenant(context.Background(), want)
	got := TenantFromContext(ctx)
	if got == nil {
		t.Fatal("TenantFromContext returned nil, want *Tenant")
	}
	if got != want {
		t.Errorf("TenantFromContext returned wrong pointer: got %p, want %p", got, want)
	}
}

func TestTenantFromContext_EmptyContext_ReturnsNil(t *testing.T) {
	got := TenantFromContext(context.Background())
	if got != nil {
		t.Errorf("TenantFromContext with empty context returned %v, want nil", got)
	}
}

func TestTenantIDFromContext_ReturnsIDSetByWithTenant(t *testing.T) {
	want := newTestTenant()
	ctx := WithTenant(context.Background(), want)
	gotID := TenantIDFromContext(ctx)
	if gotID != want.ID {
		t.Errorf("TenantIDFromContext = %s, want %s", gotID, want.ID)
	}
}

func TestTenantIDFromContext_EmptyContext_ReturnsUUIDNil(t *testing.T) {
	got := TenantIDFromContext(context.Background())
	if got != uuid.Nil {
		t.Errorf("TenantIDFromContext with empty context = %s, want uuid.Nil", got)
	}
}

func TestWithTenant_RoundTrip(t *testing.T) {
	original := newTestTenant()
	ctx := WithTenant(context.Background(), original)

	gotTenant := TenantFromContext(ctx)
	gotID := TenantIDFromContext(ctx)

	if gotTenant == nil {
		t.Fatal("TenantFromContext returned nil after WithTenant round-trip")
	}
	if gotTenant != original {
		t.Errorf("round-trip TenantFromContext: got different pointer")
	}
	if gotID != original.ID {
		t.Errorf("round-trip TenantIDFromContext: got %s, want %s", gotID, original.ID)
	}
	if gotTenant.Slug != original.Slug {
		t.Errorf("round-trip Slug: got %q, want %q", gotTenant.Slug, original.Slug)
	}
	if gotTenant.Name != original.Name {
		t.Errorf("round-trip Name: got %q, want %q", gotTenant.Name, original.Name)
	}
	if gotTenant.State != original.State {
		t.Errorf("round-trip State: got %q, want %q", gotTenant.State, original.State)
	}
}

func TestWithTenant_OverwritesPreviousValue(t *testing.T) {
	first := &Tenant{
		ID:   uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		Slug: "first",
	}
	second := &Tenant{
		ID:   uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
		Slug: "second",
	}

	ctx := WithTenant(context.Background(), first)
	ctx = WithTenant(ctx, second)

	got := TenantFromContext(ctx)
	if got != second {
		t.Errorf("expected second tenant after overwrite, got %v", got)
	}
	gotID := TenantIDFromContext(ctx)
	if gotID != second.ID {
		t.Errorf("expected second tenant ID after overwrite, got %s", gotID)
	}
}

// ---------------------------------------------------------------------------
// model.go tests
// ---------------------------------------------------------------------------

func TestStateConstants(t *testing.T) {
	tests := []struct {
		name  string
		state State
		want  string
	}{
		{"StateActive", StateActive, "active"},
		{"StateInactive", StateInactive, "inactive"},
		{"StateSuspended", StateSuspended, "suspended"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.state) != tc.want {
				t.Errorf("State constant %s = %q, want %q", tc.name, tc.state, tc.want)
			}
		})
	}
}

func TestTenantStructFields(t *testing.T) {
	id := uuid.New()
	tenant := Tenant{
		ID:    id,
		Slug:  "test-slug",
		Name:  "Test Tenant",
		State: StateActive,
	}

	if tenant.ID != id {
		t.Errorf("ID field: got %s, want %s", tenant.ID, id)
	}
	if tenant.Slug != "test-slug" {
		t.Errorf("Slug field: got %q, want %q", tenant.Slug, "test-slug")
	}
	if tenant.Name != "Test Tenant" {
		t.Errorf("Name field: got %q, want %q", tenant.Name, "Test Tenant")
	}
	if tenant.State != StateActive {
		t.Errorf("State field: got %q, want %q", tenant.State, StateActive)
	}
}

// ---------------------------------------------------------------------------
// middleware.go tests
// ---------------------------------------------------------------------------

// chiRequest builds an *http.Request whose chi context contains the given
// "tenant-slug" URL parameter — matching what Resolver.Handler reads via
// chi.URLParam(r, "tenant-slug").
func chiRequest(slug string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/t/"+slug+"/anything", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenant-slug", slug)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// decodeJSONBody reads the response body into a map for assertion.
func decodeJSONBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON response body: %v", err)
	}
	return body
}

func TestResolver_Handler_SlugResolved_TenantInContextAnd200(t *testing.T) {
	want := newTestTenant()
	repo := &fakeRepo{returnTenant: want}
	resolver := NewResolver(repo)

	var capturedTenant *Tenant
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	resolver.Handler(next).ServeHTTP(rec, chiRequest("acme"))

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if capturedTenant == nil {
		t.Fatal("tenant was not injected into context")
	}
	if capturedTenant.ID != want.ID {
		t.Errorf("context tenant ID = %s, want %s", capturedTenant.ID, want.ID)
	}
	if capturedTenant.Slug != want.Slug {
		t.Errorf("context tenant Slug = %q, want %q", capturedTenant.Slug, want.Slug)
	}
}

func TestResolver_Handler_SlugNotFound_Returns404JSONError(t *testing.T) {
	repo := &fakeRepo{returnErr: ErrNotFound}
	resolver := NewResolver(repo)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	rec := httptest.NewRecorder()
	resolver.Handler(next).ServeHTTP(rec, chiRequest("unknown-slug"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if nextCalled {
		t.Error("next handler must not be called when slug is not found")
	}
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}
	body := decodeJSONBody(t, rec)
	if body["error"] != "tenant not found" {
		t.Errorf("response body error = %q, want %q", body["error"], "tenant not found")
	}
}

func TestResolver_Handler_SlugNotFound_WrappedErrNotFound_Returns404(t *testing.T) {
	// ErrNotFound is wrapped by the Store layer — errors.Is must still match.
	wrappedErr := errors.Join(errors.New("GetBySlug wrap"), ErrNotFound)
	repo := &fakeRepo{returnErr: wrappedErr}
	resolver := NewResolver(repo)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next must not be called on ErrNotFound")
	})

	rec := httptest.NewRecorder()
	resolver.Handler(next).ServeHTTP(rec, chiRequest("wrapped"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d (wrapped ErrNotFound)", rec.Code, http.StatusNotFound)
	}
	body := decodeJSONBody(t, rec)
	if body["error"] != "tenant not found" {
		t.Errorf("body error = %q, want %q", body["error"], "tenant not found")
	}
}

func TestResolver_Handler_StoreError_Returns503JSONError(t *testing.T) {
	storeErr := errors.New("connection refused")
	repo := &fakeRepo{returnErr: storeErr}
	resolver := NewResolver(repo)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	rec := httptest.NewRecorder()
	resolver.Handler(next).ServeHTTP(rec, chiRequest("acme"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if nextCalled {
		t.Error("next handler must not be called on store error")
	}
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}
	body := decodeJSONBody(t, rec)
	if body["error"] != "service unavailable" {
		t.Errorf("response body error = %q, want %q", body["error"], "service unavailable")
	}
}

func TestResolver_Handler_ContextPropagated_TenantIDReadable(t *testing.T) {
	want := newTestTenant()
	repo := &fakeRepo{returnTenant: want}
	resolver := NewResolver(repo)

	var capturedID uuid.UUID
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	resolver.Handler(next).ServeHTTP(rec, chiRequest("acme"))

	if capturedID != want.ID {
		t.Errorf("TenantIDFromContext inside handler = %s, want %s", capturedID, want.ID)
	}
}

func TestNewResolver_ReturnsNonNil(t *testing.T) {
	repo := &fakeRepo{}
	r := NewResolver(repo)
	if r == nil {
		t.Error("NewResolver returned nil")
	}
}
