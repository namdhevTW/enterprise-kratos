package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// fake store
// ---------------------------------------------------------------------------

type fakeSessionStore struct {
	getByToken    func(string) (*Session, error)
	revokeByToken func(string) error
}

func (f *fakeSessionStore) GetByToken(_ context.Context, _ uuid.UUID, token string) (*Session, error) {
	return f.getByToken(token)
}

func (f *fakeSessionStore) RevokeByToken(_ context.Context, _ uuid.UUID, token string) error {
	return f.revokeByToken(token)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newRouter wires the handler into a chi router so the full dispatch path is
// exercised (including the chi middleware chain).
func newRouter(store sessionStore) chi.Router {
	r := chi.NewRouter()
	h := NewHandler(store)
	h.Mount(r)
	return r
}

// withTenant returns a copy of r whose context carries the given tenant.
func withTenant(r *http.Request, tenantID uuid.UUID) *http.Request {
	t := &internaltenant.Tenant{ID: tenantID, Slug: "test"}
	return r.WithContext(internaltenant.WithTenant(r.Context(), t))
}

// fixedSession returns a well-formed, non-expired session for test assertions.
func fixedSession(tenantID uuid.UUID) *Session {
	return &Session{
		ID:         uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		TenantID:   tenantID,
		IdentityID: uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
		Token:      "tok-abc123",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		AAL:        "aal1",
		AMR:        []string{"password"},
		Active:     true,
	}
}

const testToken = "tok-abc123"

// ---------------------------------------------------------------------------
// GET /sessions/whoami
// ---------------------------------------------------------------------------

func TestWhoami_SuccessXSessionToken(t *testing.T) {
	tenantID := uuid.New()
	sess := fixedSession(tenantID)

	store := &fakeSessionStore{
		getByToken: func(token string) (*Session, error) {
			if token != testToken {
				return nil, fmt.Errorf("unexpected token: %s", token)
			}
			return sess, nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	requiredKeys := []string{"id", "identity_id", "tenant_id", "aal", "amr", "expires_at", "active"}
	for _, k := range requiredKeys {
		if _, ok := body[k]; !ok {
			t.Errorf("response body missing key %q", k)
		}
	}

	if body["aal"] != "aal1" {
		t.Errorf("expected aal=aal1, got %v", body["aal"])
	}
	if active, _ := body["active"].(bool); !active {
		t.Errorf("expected active=true")
	}
}

func TestWhoami_SuccessBearerToken(t *testing.T) {
	tenantID := uuid.New()
	sess := fixedSession(tenantID)

	store := &fakeSessionStore{
		getByToken: func(token string) (*Session, error) {
			if token != testToken {
				return nil, fmt.Errorf("unexpected token: %s", token)
			}
			return sess, nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestWhoami_NoTenant(t *testing.T) {
	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) {
			t.Fatal("GetByToken should not be called when tenant is missing")
			return nil, nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	// Request has no tenant injected into the context.
	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestWhoami_NoToken(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) {
			t.Fatal("GetByToken should not be called when no token is provided")
			return nil, nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req = withTenant(req, tenantID)
	// No X-Session-Token or Authorization header set.

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestWhoami_TokenNotFound(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) {
			return nil, fmt.Errorf("session.GetByToken: %w", ErrNotFound)
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	assertErrorBody(t, rr)
}

func TestWhoami_TokenRevoked(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) {
			return nil, fmt.Errorf("session.GetByToken: %w", ErrRevoked)
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	assertErrorBody(t, rr)
}

func TestWhoami_TokenExpired(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) {
			return nil, fmt.Errorf("session.GetByToken: %w", ErrExpired)
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	assertErrorBody(t, rr)
}

func TestWhoami_StoreError(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) {
			return nil, errors.New("unexpected db failure")
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	assertErrorBody(t, rr)
}

// ---------------------------------------------------------------------------
// DELETE /sessions/whoami
// ---------------------------------------------------------------------------

func TestLogout_Success(t *testing.T) {
	tenantID := uuid.New()
	revokedToken := ""

	store := &fakeSessionStore{
		revokeByToken: func(token string) error {
			revokedToken = token
			return nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if revokedToken != testToken {
		t.Errorf("expected RevokeByToken called with %q, got %q", testToken, revokedToken)
	}
	if rr.Body.Len() != 0 {
		t.Errorf("expected empty body on 204, got %q", rr.Body.String())
	}
}

func TestLogout_NoTenant(t *testing.T) {
	store := &fakeSessionStore{
		revokeByToken: func(_ string) error {
			t.Fatal("RevokeByToken should not be called when tenant is missing")
			return nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	// No tenant in context.

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestLogout_NoToken(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		revokeByToken: func(_ string) error {
			t.Fatal("RevokeByToken should not be called when no token is provided")
			return nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/whoami", nil)
	req = withTenant(req, tenantID)
	// No token headers set.

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestLogout_TokenNotFound(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		revokeByToken: func(_ string) error {
			return fmt.Errorf("session.RevokeByToken: %w", ErrNotFound)
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
	assertErrorBody(t, rr)
}

func TestLogout_StoreError(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		revokeByToken: func(_ string) error {
			return errors.New("unexpected db failure")
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	assertErrorBody(t, rr)
}

// ---------------------------------------------------------------------------
// Content-Type assertions
// ---------------------------------------------------------------------------

func TestWhoami_ContentTypeJSON(t *testing.T) {
	tenantID := uuid.New()
	sess := fixedSession(tenantID)

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) { return sess, nil },
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestLogout_ContentTypeOnError(t *testing.T) {
	tenantID := uuid.New()

	store := &fakeSessionStore{
		revokeByToken: func(_ string) error {
			return fmt.Errorf("session.RevokeByToken: %w", ErrNotFound)
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// Token extraction edge cases
// ---------------------------------------------------------------------------

func TestWhoami_BearerPrefixRequiredExact(t *testing.T) {
	tenantID := uuid.New()

	// Authorization header with a non-Bearer scheme should be treated as no token.
	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) {
			t.Fatal("GetByToken should not be called for non-Bearer Authorization")
			return nil, nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("Authorization", "Token "+testToken) // Not "Bearer "
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for non-Bearer auth scheme, got %d", rr.Code)
	}
}

func TestWhoami_XSessionTokenTakesPrecedenceOverBearer(t *testing.T) {
	tenantID := uuid.New()
	sess := fixedSession(tenantID)

	const xToken = "x-session-token-value"
	const bearerToken = "bearer-token-value"

	capturedToken := ""
	store := &fakeSessionStore{
		getByToken: func(token string) (*Session, error) {
			capturedToken = token
			return sess, nil
		},
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", xToken)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if capturedToken != xToken {
		t.Errorf("expected X-Session-Token %q to take precedence, but store received %q", xToken, capturedToken)
	}
}

// ---------------------------------------------------------------------------
// Sentinel error wrapping: errors.Is must traverse the wrap chain
// ---------------------------------------------------------------------------

func TestWhoami_ErrorsIsWrappedErrNotFound(t *testing.T) {
	tenantID := uuid.New()

	// Simulate the exact wrapping pattern used by Store.GetByToken.
	wrapped := fmt.Errorf("session.GetByToken tenant=%s: %w", tenantID, ErrNotFound)

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) { return nil, wrapped },
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrapped ErrNotFound, got %d", rr.Code)
	}
}

func TestWhoami_ErrorsIsWrappedErrRevoked(t *testing.T) {
	tenantID := uuid.New()

	wrapped := fmt.Errorf("session.GetByToken: %w", ErrRevoked)

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) { return nil, wrapped },
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrapped ErrRevoked, got %d", rr.Code)
	}
}

func TestWhoami_ErrorsIsWrappedErrExpired(t *testing.T) {
	tenantID := uuid.New()

	wrapped := fmt.Errorf("session.GetByToken: %w", ErrExpired)

	store := &fakeSessionStore{
		getByToken: func(_ string) (*Session, error) { return nil, wrapped },
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrapped ErrExpired, got %d", rr.Code)
	}
}

func TestLogout_ErrorsIsWrappedErrNotFound(t *testing.T) {
	tenantID := uuid.New()

	wrapped := fmt.Errorf("session.RevokeByToken: %w", ErrNotFound)

	store := &fakeSessionStore{
		revokeByToken: func(_ string) error { return wrapped },
	}

	r := chi.NewRouter()
	NewHandler(store).Mount(r)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/whoami", nil)
	req.Header.Set("X-Session-Token", testToken)
	req = withTenant(req, tenantID)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrapped ErrNotFound, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// shared assertion helper
// ---------------------------------------------------------------------------

// assertErrorBody verifies the response body is valid JSON containing an "error" key.
func assertErrorBody(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("expected JSON error body, decode failed: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Errorf("expected JSON body to contain \"error\" key, got %v", body)
	}
}
