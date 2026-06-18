package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/google/uuid"
)

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

// writeJSON writes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// newAdapter builds an Adapter pointed at the given test server URL.
func newTestAdapter(id string, authType authenticator.Type, serverURL string) *Adapter {
	return New(id, authType, serverURL, nil)
}

// realisticNodes returns a small slice of UINodes that mimics a real upstream
// TOTP enrollment response — used across multiple tests to keep responses
// realistic.
func realisticNodes() []authenticator.UINode {
	return []authenticator.UINode{
		{
			Type:  "input",
			Group: "totp",
			Attributes: authenticator.UINodeAttrs{
				Name:     "totp_code",
				Type:     "text",
				Required: true,
			},
			Messages: []authenticator.UIMessage{
				{ID: 1010010, Type: "info", Text: "Enter your authenticator code"},
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{
					ID:   1070006,
					Type: "info",
					Text: "Authentication Code",
				},
			},
		},
		{
			Type:  "input",
			Group: "totp",
			Attributes: authenticator.UINodeAttrs{
				Name:  "method",
				Type:  "hidden",
				Value: "totp",
			},
			Meta: authenticator.UINodeMeta{},
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessor tests
// ─────────────────────────────────────────────────────────────────────────────

func TestID(t *testing.T) {
	a := New("totp", authenticator.SecondFactor, "http://localhost", nil)
	if got := a.ID(); got != "totp" {
		t.Errorf("ID() = %q, want %q", got, "totp")
	}
}

func TestType_SecondFactor(t *testing.T) {
	a := New("totp", authenticator.SecondFactor, "http://localhost", nil)
	if got := a.Type(); got != authenticator.SecondFactor {
		t.Errorf("Type() = %d, want SecondFactor (%d)", got, authenticator.SecondFactor)
	}
}

func TestType_FirstFactor(t *testing.T) {
	a := New("passkey", authenticator.FirstFactor, "http://localhost", nil)
	if got := a.Type(); got != authenticator.FirstFactor {
		t.Errorf("Type() = %d, want FirstFactor (%d)", got, authenticator.FirstFactor)
	}
}

func TestType_Either(t *testing.T) {
	a := New("otp", authenticator.Either, "http://localhost", nil)
	if got := a.Type(); got != authenticator.Either {
		t.Errorf("Type() = %d, want Either (%d)", got, authenticator.Either)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// New() — default client
// ─────────────────────────────────────────────────────────────────────────────

// TestNew_NilClientUsesDefault verifies that passing nil as the client does
// not leave the adapter in a broken state: the adapter must use an internal
// http.Client (non-nil) so that subsequent calls do not panic.
func TestNew_NilClientUsesDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, startFlowResp{
			Nodes: realisticNodes(),
			State: "pending",
		})
	}))
	defer srv.Close()

	// nil client — New() must substitute its own default.
	a := New("totp", authenticator.SecondFactor, srv.URL, nil)
	if a.client == nil {
		t.Fatal("Adapter.client is nil after New() with nil client arg")
	}

	// Confirm the adapter is actually functional (makes a real HTTP call).
	_, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
	})
	if err != nil {
		t.Errorf("StartFlow with nil-client adapter returned unexpected error: %v", err)
	}
}

// TestNew_ProvidedClientIsUsed verifies that a caller-supplied *http.Client
// is stored rather than replaced.
func TestNew_ProvidedClientIsUsed(t *testing.T) {
	custom := &http.Client{}
	a := New("totp", authenticator.SecondFactor, "http://localhost", custom)
	if a.client != custom {
		t.Error("New() replaced the provided *http.Client with a different one")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// StartFlow tests
// ─────────────────────────────────────────────────────────────────────────────

func TestStartFlow_Success(t *testing.T) {
	nodes := realisticNodes()
	wantState := "challenge-issued"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("StartFlow: got method %s, want POST", r.Method)
		}
		if r.URL.Path != "/flows/start" {
			t.Errorf("StartFlow: got path %s, want /flows/start", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("StartFlow: Content-Type = %q, want application/json", ct)
		}

		// Decode and verify forwarded IDs.
		var req startFlowReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("StartFlow: could not decode request body: %v", err)
		}
		if req.TenantID == "" || req.IdentityID == "" || req.FlowID == "" {
			t.Errorf("StartFlow: missing IDs in request body: %+v", req)
		}

		writeJSON(w, http.StatusOK, startFlowResp{Nodes: nodes, State: wantState})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
	})

	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("StartFlow returned nil FlowState")
	}
	if state.State != wantState {
		t.Errorf("FlowState.State = %q, want %q", state.State, wantState)
	}
	if len(state.Nodes) != len(nodes) {
		t.Fatalf("FlowState.Nodes length = %d, want %d", len(state.Nodes), len(nodes))
	}
	// Verify first node shape is preserved round-trip through JSON.
	if state.Nodes[0].Attributes.Name != "totp_code" {
		t.Errorf("Nodes[0].Attributes.Name = %q, want %q", state.Nodes[0].Attributes.Name, "totp_code")
	}
	if state.Nodes[0].Group != "totp" {
		t.Errorf("Nodes[0].Group = %q, want %q", state.Nodes[0].Group, "totp")
	}
	if !state.Nodes[0].Attributes.Required {
		t.Error("Nodes[0].Attributes.Required = false, want true")
	}
}

func TestStartFlow_ParamsAreForwarded(t *testing.T) {
	wantChannel := "sms"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req startFlowReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Params["channel"] != wantChannel {
			t.Errorf("params[channel] = %q, want %q", req.Params["channel"], wantChannel)
		}
		writeJSON(w, http.StatusOK, startFlowResp{State: "pending"})
	}))
	defer srv.Close()

	a := newTestAdapter("otp", authenticator.SecondFactor, srv.URL)
	_, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
		Params:     map[string]string{"channel": wantChannel},
	})
	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}
}

func TestStartFlow_Server500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	_, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
	})
	if err == nil {
		t.Fatal("StartFlow expected error for 500 response, got nil")
	}
}

func TestStartFlow_ErrorBody(t *testing.T) {
	const upstreamMsg = "upstream error"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadGateway, errResp{Error: upstreamMsg})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	_, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
	})
	if err == nil {
		t.Fatal("StartFlow expected error for non-2xx + error body, got nil")
	}
	if !strings.Contains(err.Error(), upstreamMsg) {
		t.Errorf("error %q does not contain upstream message %q", err.Error(), upstreamMsg)
	}
}

func TestStartFlow_ConnectionRefused(t *testing.T) {
	// Point the adapter at a port that is not listening.
	a := New("totp", authenticator.SecondFactor, "http://127.0.0.1:1", nil)
	_, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
	})
	if err == nil {
		t.Fatal("StartFlow expected connection-refused error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CompleteFlow tests
// ─────────────────────────────────────────────────────────────────────────────

func TestCompleteFlow_Success(t *testing.T) {
	identityID := uuid.New()
	wantAAL := "aal2"
	wantAMR := []string{"totp", "mfa"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("CompleteFlow: got method %s, want POST", r.Method)
		}
		if r.URL.Path != "/flows/complete" {
			t.Errorf("CompleteFlow: got path %s, want /flows/complete", r.URL.Path)
		}

		var req completeFlowReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("CompleteFlow: could not decode request body: %v", err)
		}
		if req.IdentityID != identityID.String() {
			t.Errorf("CompleteFlow: IdentityID = %q, want %q", req.IdentityID, identityID.String())
		}
		if req.Values["totp_code"] == "" {
			t.Error("CompleteFlow: totp_code value not forwarded")
		}

		writeJSON(w, http.StatusOK, completeFlowResp{
			Success: true,
			AAL:     wantAAL,
			AMR:     wantAMR,
		})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	result, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: identityID,
		FlowID:     uuid.New(),
		FlowState:  "challenge-issued",
		Values:     map[string]string{"totp_code": "123456"},
	})

	if err != nil {
		t.Fatalf("CompleteFlow returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("CompleteFlow returned nil AuthResult")
	}
	if result.IdentityID != identityID {
		t.Errorf("AuthResult.IdentityID = %v, want %v", result.IdentityID, identityID)
	}
	if result.AAL != wantAAL {
		t.Errorf("AuthResult.AAL = %q, want %q", result.AAL, wantAAL)
	}
	if len(result.AMR) != len(wantAMR) {
		t.Fatalf("AuthResult.AMR length = %d, want %d", len(result.AMR), len(wantAMR))
	}
	for i, m := range wantAMR {
		if result.AMR[i] != m {
			t.Errorf("AuthResult.AMR[%d] = %q, want %q", i, result.AMR[i], m)
		}
	}
}

func TestCompleteFlow_SuccessFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, completeFlowResp{Success: false})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	result, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
		Values:     map[string]string{"totp_code": "000000"},
	})
	if err == nil {
		t.Fatal("CompleteFlow expected error when success=false, got nil")
	}
	if result != nil {
		t.Error("CompleteFlow expected nil AuthResult on failure, got non-nil")
	}
}

func TestCompleteFlow_Server400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, errResp{Error: "missing totp_code"})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	_, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
		Values:     map[string]string{},
	})
	if err == nil {
		t.Fatal("CompleteFlow expected error for 400 response, got nil")
	}
}

func TestCompleteFlow_Server500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	_, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
		Values:     map[string]string{"totp_code": "123456"},
	})
	if err == nil {
		t.Fatal("CompleteFlow expected error for 500 response, got nil")
	}
}

func TestCompleteFlow_ConnectionRefused(t *testing.T) {
	a := New("totp", authenticator.SecondFactor, "http://127.0.0.1:1", nil)
	_, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
		Values:     map[string]string{"totp_code": "123456"},
	})
	if err == nil {
		t.Fatal("CompleteFlow expected connection-refused error, got nil")
	}
}

// TestCompleteFlow_IdentityIDFromRequest verifies that AuthResult.IdentityID
// is taken from the request, not from anything the upstream returns (the
// upstream response does not include an identity_id field).
func TestCompleteFlow_IdentityIDFromRequest(t *testing.T) {
	id := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, completeFlowResp{
			Success: true,
			AAL:     "aal2",
			AMR:     []string{"totp"},
		})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	result, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: id,
		FlowID:     uuid.New(),
		Values:     map[string]string{"totp_code": "654321"},
	})
	if err != nil {
		t.Fatalf("CompleteFlow unexpected error: %v", err)
	}
	if result.IdentityID != id {
		t.Errorf("AuthResult.IdentityID = %v, want %v (the request IdentityID)", result.IdentityID, id)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Enroll tests
// ─────────────────────────────────────────────────────────────────────────────

func TestEnroll_Success(t *testing.T) {
	wantCredType := "totp"
	wantIdentifiers := []string{"user@example.com"}
	wantConfig := json.RawMessage(`{"secret":"BASE32SECRET","issuer":"enterprise"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Enroll: got method %s, want POST", r.Method)
		}
		if r.URL.Path != "/credentials/enroll" {
			t.Errorf("Enroll: got path %s, want /credentials/enroll", r.URL.Path)
		}

		var req enrollReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Enroll: could not decode request body: %v", err)
		}
		if req.TenantID == "" || req.IdentityID == "" {
			t.Errorf("Enroll: missing IDs in request body: %+v", req)
		}

		writeJSON(w, http.StatusOK, enrollResp{
			CredentialType:   wantCredType,
			Identifiers:      wantIdentifiers,
			CredentialConfig: wantConfig,
		})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	result, err := a.Enroll(context.Background(), &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		Values:     map[string]string{"totp_issuer": "enterprise"},
	})

	if err != nil {
		t.Fatalf("Enroll returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Enroll returned nil EnrollResult")
	}
	if result.CredentialType != wantCredType {
		t.Errorf("EnrollResult.CredentialType = %q, want %q", result.CredentialType, wantCredType)
	}
	if len(result.Identifiers) != len(wantIdentifiers) || result.Identifiers[0] != wantIdentifiers[0] {
		t.Errorf("EnrollResult.Identifiers = %v, want %v", result.Identifiers, wantIdentifiers)
	}
	// CredentialConfig must round-trip as valid JSON containing the expected keys.
	var cfg map[string]string
	if err := json.Unmarshal(result.CredentialConfig, &cfg); err != nil {
		t.Fatalf("EnrollResult.CredentialConfig is not valid JSON: %v", err)
	}
	if cfg["secret"] != "BASE32SECRET" {
		t.Errorf("CredentialConfig[secret] = %q, want %q", cfg["secret"], "BASE32SECRET")
	}
}

func TestEnroll_Server500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	result, err := a.Enroll(context.Background(), &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
	})
	if err == nil {
		t.Fatal("Enroll expected error for 500 response, got nil")
	}
	if result != nil {
		t.Error("Enroll expected nil EnrollResult on error, got non-nil")
	}
}

func TestEnroll_ErrorBody(t *testing.T) {
	const upstreamMsg = "identity not found"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnprocessableEntity, errResp{Error: upstreamMsg})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	_, err := a.Enroll(context.Background(), &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
	})
	if err == nil {
		t.Fatal("Enroll expected error for non-2xx + error body, got nil")
	}
	if !strings.Contains(err.Error(), upstreamMsg) {
		t.Errorf("error %q does not contain upstream message %q", err.Error(), upstreamMsg)
	}
}

func TestEnroll_ValuesAreForwarded(t *testing.T) {
	wantIssuer := "acme-corp"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req enrollReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Values["totp_issuer"] != wantIssuer {
			t.Errorf("values[totp_issuer] = %q, want %q", req.Values["totp_issuer"], wantIssuer)
		}
		writeJSON(w, http.StatusOK, enrollResp{
			CredentialType:   "totp",
			Identifiers:      nil,
			CredentialConfig: json.RawMessage(`{}`),
		})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	_, err := a.Enroll(context.Background(), &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		Values:     map[string]string{"totp_issuer": wantIssuer},
	})
	if err != nil {
		t.Fatalf("Enroll returned unexpected error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Unenroll tests
// ─────────────────────────────────────────────────────────────────────────────

func TestUnenroll_Success(t *testing.T) {
	credentialID := uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Unenroll: got method %s, want POST", r.Method)
		}
		if r.URL.Path != "/credentials/unenroll" {
			t.Errorf("Unenroll: got path %s, want /credentials/unenroll", r.URL.Path)
		}

		var req unenrollReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Unenroll: could not decode request body: %v", err)
		}
		if req.CredentialID != credentialID.String() {
			t.Errorf("Unenroll: CredentialID = %q, want %q", req.CredentialID, credentialID.String())
		}

		// Response body is intentionally ignored by the adapter.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	err := a.Unenroll(context.Background(), &authenticator.UnenrollRequest{
		TenantID:     uuid.New(),
		IdentityID:   uuid.New(),
		CredentialID: credentialID,
	})
	if err != nil {
		t.Errorf("Unenroll returned unexpected error: %v", err)
	}
}

// TestUnenroll_ResponseBodyIgnored verifies that a non-empty/garbage response
// body does not cause an error, since Unenroll passes nil for out.
func TestUnenroll_ResponseBodyIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	err := a.Unenroll(context.Background(), &authenticator.UnenrollRequest{
		TenantID:     uuid.New(),
		IdentityID:   uuid.New(),
		CredentialID: uuid.New(),
	})
	if err != nil {
		t.Errorf("Unenroll returned unexpected error for non-JSON response body: %v", err)
	}
}

func TestUnenroll_Server500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	err := a.Unenroll(context.Background(), &authenticator.UnenrollRequest{
		TenantID:     uuid.New(),
		IdentityID:   uuid.New(),
		CredentialID: uuid.New(),
	})
	if err == nil {
		t.Fatal("Unenroll expected error for 500 response, got nil")
	}
}

func TestUnenroll_ErrorBody(t *testing.T) {
	const upstreamMsg = "credential not found"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errResp{Error: upstreamMsg})
	}))
	defer srv.Close()

	a := newTestAdapter("totp", authenticator.SecondFactor, srv.URL)
	err := a.Unenroll(context.Background(), &authenticator.UnenrollRequest{
		TenantID:     uuid.New(),
		IdentityID:   uuid.New(),
		CredentialID: uuid.New(),
	})
	if err == nil {
		t.Fatal("Unenroll expected error for non-2xx + error body, got nil")
	}
	if !strings.Contains(err.Error(), upstreamMsg) {
		t.Errorf("error %q does not contain upstream message %q", err.Error(), upstreamMsg)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Error message wrapping
// ─────────────────────────────────────────────────────────────────────────────

// TestErrorWrapping_IncludesAdapterID verifies that errors from each method
// include the adapter's configured ID so operators can trace which upstream
// service is at fault.
func TestErrorWrapping_IncludesAdapterID(t *testing.T) {
	const adapterID = "enterprise-totp"

	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()

	a := newTestAdapter(adapterID, authenticator.SecondFactor, srv500.URL)
	ctx := context.Background()
	ids := func() (uuid.UUID, uuid.UUID, uuid.UUID) {
		return uuid.New(), uuid.New(), uuid.New()
	}

	t.Run("StartFlow", func(t *testing.T) {
		tid, iid, fid := ids()
		_, err := a.StartFlow(ctx, &authenticator.StartFlowRequest{TenantID: tid, IdentityID: iid, FlowID: fid})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), adapterID) {
			t.Errorf("error %q does not contain adapter ID %q", err.Error(), adapterID)
		}
	})

	t.Run("CompleteFlow", func(t *testing.T) {
		tid, iid, fid := ids()
		_, err := a.CompleteFlow(ctx, &authenticator.CompleteFlowRequest{TenantID: tid, IdentityID: iid, FlowID: fid})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), adapterID) {
			t.Errorf("error %q does not contain adapter ID %q", err.Error(), adapterID)
		}
	})

	t.Run("Enroll", func(t *testing.T) {
		tid, iid, _ := ids()
		_, err := a.Enroll(ctx, &authenticator.EnrollRequest{TenantID: tid, IdentityID: iid})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), adapterID) {
			t.Errorf("error %q does not contain adapter ID %q", err.Error(), adapterID)
		}
	})

	t.Run("Unenroll", func(t *testing.T) {
		tid, iid, cid := ids()
		err := a.Unenroll(ctx, &authenticator.UnenrollRequest{TenantID: tid, IdentityID: iid, CredentialID: cid})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), adapterID) {
			t.Errorf("error %q does not contain adapter ID %q", err.Error(), adapterID)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Interface compliance
// ─────────────────────────────────────────────────────────────────────────────

// TestAdapterImplementsInterface is a compile-time assertion that *Adapter
// satisfies the authenticator.Authenticator interface.
func TestAdapterImplementsInterface(t *testing.T) {
	var _ authenticator.Authenticator = (*Adapter)(nil)
}
