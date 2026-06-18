package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// capturedRequest holds the parts of an incoming HTTP request that the test
// handler captures for later assertion.
type capturedRequest struct {
	method      string
	queryParams map[string]string
	body        []byte
	contentType string
}

func capture(r *http.Request) capturedRequest {
	body, _ := io.ReadAll(r.Body)
	params := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	return capturedRequest{
		method:      r.Method,
		queryParams: params,
		body:        body,
		contentType: r.Header.Get("Content-Type"),
	}
}

// --------------------------------------------------------------------------
// NewClient
// --------------------------------------------------------------------------

func TestNewClient_ReturnsNonNil(t *testing.T) {
	c := NewClient("http://hydra.example.com", nil)
	if c == nil {
		t.Fatal("expected non-nil *Client, got nil")
	}
}

func TestNewClient_NilHTTPClientUsesDefault(t *testing.T) {
	c := NewClient("http://hydra.example.com", nil)
	if c.httpClient != http.DefaultClient {
		t.Errorf("expected httpClient to be http.DefaultClient, got %v", c.httpClient)
	}
}

func TestNewClient_CustomHTTPClientIsPreserved(t *testing.T) {
	custom := &http.Client{}
	c := NewClient("http://hydra.example.com", custom)
	if c.httpClient != custom {
		t.Errorf("expected httpClient to be the provided custom client")
	}
}

func TestNewClient_AdminURLIsStored(t *testing.T) {
	const u = "http://hydra.internal:4445"
	c := NewClient(u, nil)
	if c.adminURL != u {
		t.Errorf("expected adminURL %q, got %q", u, c.adminURL)
	}
}

// --------------------------------------------------------------------------
// AcceptLoginRequest – success path
// --------------------------------------------------------------------------

func TestAcceptLoginRequest_Success_ReturnsRedirectURL(t *testing.T) {
	const wantRedirect = "https://hydra.example.com/callback"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: wantRedirect})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	got, err := c.AcceptLoginRequest(
		context.Background(),
		"challenge-abc",
		uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		"aal1",
		false,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantRedirect {
		t.Errorf("redirect URL: want %q, got %q", wantRedirect, got)
	}
}

func TestAcceptLoginRequest_Success_UsesPUTMethod(t *testing.T) {
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(
		context.Background(),
		"challenge-xyz",
		uuid.New(),
		uuid.New(),
		"aal1",
		false,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.method != http.MethodPut {
		t.Errorf("HTTP method: want PUT, got %s", cap.method)
	}
}

func TestAcceptLoginRequest_Success_SetsLoginChallengeQueryParam(t *testing.T) {
	const challenge = "my-login-challenge"
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), challenge, uuid.New(), uuid.New(), "aal1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cap.queryParams["login_challenge"]; got != challenge {
		t.Errorf("login_challenge query param: want %q, got %q", challenge, got)
	}
}

func TestAcceptLoginRequest_Success_BodySubjectMatchesIdentityID(t *testing.T) {
	identityID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", identityID, uuid.New(), "aal1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body acceptLoginBody
	if err := json.NewDecoder(bytes.NewReader(cap.body)).Decode(&body); err != nil {
		t.Fatalf("failed to decode captured request body: %v", err)
	}
	if body.Subject != identityID.String() {
		t.Errorf("subject: want %q, got %q", identityID.String(), body.Subject)
	}
}

func TestAcceptLoginRequest_Success_BodyRememberFalse(t *testing.T) {
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body acceptLoginBody
	if err := json.NewDecoder(bytes.NewReader(cap.body)).Decode(&body); err != nil {
		t.Fatalf("failed to decode captured request body: %v", err)
	}
	if body.Remember != false {
		t.Errorf("remember: want false, got %v", body.Remember)
	}
}

func TestAcceptLoginRequest_Success_BodyRememberTrue(t *testing.T) {
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body acceptLoginBody
	if err := json.NewDecoder(bytes.NewReader(cap.body)).Decode(&body); err != nil {
		t.Fatalf("failed to decode captured request body: %v", err)
	}
	if body.Remember != true {
		t.Errorf("remember: want true, got %v", body.Remember)
	}
}

func TestAcceptLoginRequest_Success_BodyRememberFor3600(t *testing.T) {
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body acceptLoginBody
	if err := json.NewDecoder(bytes.NewReader(cap.body)).Decode(&body); err != nil {
		t.Fatalf("failed to decode captured request body: %v", err)
	}
	if body.RememberFor != 3600 {
		t.Errorf("remember_for: want 3600, got %d", body.RememberFor)
	}
}

func TestAcceptLoginRequest_Success_ContextContainsTenantID(t *testing.T) {
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), tenantID, "aal1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body acceptLoginBody
	if err := json.NewDecoder(bytes.NewReader(cap.body)).Decode(&body); err != nil {
		t.Fatalf("failed to decode captured request body: %v", err)
	}
	got, ok := body.Context["tenant_id"]
	if !ok {
		t.Fatal("context missing key tenant_id")
	}
	if got != tenantID.String() {
		t.Errorf("context.tenant_id: want %q, got %v", tenantID.String(), got)
	}
}

func TestAcceptLoginRequest_Success_ContextContainsAAL(t *testing.T) {
	const wantAAL = "aal2"
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), wantAAL, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body acceptLoginBody
	if err := json.NewDecoder(bytes.NewReader(cap.body)).Decode(&body); err != nil {
		t.Fatalf("failed to decode captured request body: %v", err)
	}
	got, ok := body.Context["aal"]
	if !ok {
		t.Fatal("context missing key aal")
	}
	if got != wantAAL {
		t.Errorf("context.aal: want %q, got %v", wantAAL, got)
	}
}

func TestAcceptLoginRequest_Success_RequestContentTypeIsJSON(t *testing.T) {
	var cap capturedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap = capture(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(acceptLoginResponse{RedirectTo: "https://hydra.example.com/callback"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.contentType != "application/json" {
		t.Errorf("Content-Type: want %q, got %q", "application/json", cap.contentType)
	}
}

// --------------------------------------------------------------------------
// AcceptLoginRequest – error paths
// --------------------------------------------------------------------------

func TestAcceptLoginRequest_Non200_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
}

func TestAcceptLoginRequest_500_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestAcceptLoginRequest_ConnectionError_ReturnsError(t *testing.T) {
	// Start a server and immediately close it so connections are refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // closed before the request is made

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err == nil {
		t.Fatal("expected error for connection-refused, got nil")
	}
}

func TestAcceptLoginRequest_InvalidJSONResponse_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("this is not json {{{"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err == nil {
		t.Fatal("expected error for invalid JSON response, got nil")
	}
}

func TestAcceptLoginRequest_EmptyJSONResponse_ReturnsEmptyRedirect(t *testing.T) {
	// An empty JSON object is valid JSON; redirect_to will be the zero value "".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	got, err := c.AcceptLoginRequest(context.Background(), "ch", uuid.New(), uuid.New(), "aal1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty redirect URL for empty JSON body, got %q", got)
	}
}

func TestAcceptLoginRequest_ContextCancelled_ReturnsError(t *testing.T) {
	// The handler blocks; we cancel the client context so the HTTP Do() returns
	// an error. We then force-close the server connections to unblock the handler
	// goroutine and let httptest.Server.Close() drain cleanly.
	ready := make(chan struct{}, 1)
	unblock := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ready <- struct{}{}
		<-unblock // released by the test after the client has errored
	}))

	ctx, cancel := context.WithCancel(context.Background())
	c := NewClient(srv.URL, srv.Client())

	done := make(chan error, 1)
	go func() {
		_, err := c.AcceptLoginRequest(ctx, "ch", uuid.New(), uuid.New(), "aal1", false)
		done <- err
	}()

	<-ready  // wait until the handler is executing (request reached the server)
	cancel() // cancel the client context → Do() returns an error

	err := <-done // collect the client error before touching the server

	// Unblock the handler goroutine, then force-close connections so
	// httptest.Server.Close() can drain without hanging.
	close(unblock)
	srv.CloseClientConnections()
	srv.Close()

	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}
