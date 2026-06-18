package password

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/google/uuid"
)

// newAdapter returns a freshly constructed Adapter for use in each test.
func newAdapter() *Adapter { return New() }

// mustHashPassword hashes a plaintext password at the adapter's configured cost
// and fails the test if hashing fails.
func mustHashPassword(t *testing.T, plain string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		t.Fatalf("mustHashPassword: %v", err)
	}
	return string(hash)
}

// marshalCredConfig encodes a credentialConfig JSON payload and fails the test
// on error.
func marshalCredConfig(t *testing.T, hashedPassword string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(credentialConfig{HashedPassword: hashedPassword})
	if err != nil {
		t.Fatalf("marshalCredConfig: %v", err)
	}
	return raw
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessor tests
// ─────────────────────────────────────────────────────────────────────────────

func TestID(t *testing.T) {
	a := newAdapter()
	if got := a.ID(); got != "password" {
		t.Errorf("ID() = %q, want %q", got, "password")
	}
}

func TestType(t *testing.T) {
	a := newAdapter()
	if got := a.Type(); got != authenticator.FirstFactor {
		t.Errorf("Type() = %d, want FirstFactor (%d)", got, authenticator.FirstFactor)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// StartFlow tests
// ─────────────────────────────────────────────────────────────────────────────

func TestStartFlow_ReturnsExactlyOneNode(t *testing.T) {
	a := newAdapter()
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
	if len(state.Nodes) != 1 {
		t.Fatalf("StartFlow node count = %d, want 1", len(state.Nodes))
	}
}

func TestStartFlow_NodeShape(t *testing.T) {
	a := newAdapter()
	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{})
	if err != nil {
		t.Fatalf("StartFlow error: %v", err)
	}

	node := state.Nodes[0]

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"Attributes.Name", node.Attributes.Name, "password"},
		{"Attributes.Type", node.Attributes.Type, "password"},
		{"Group", node.Group, "password"},
		{"Type", node.Type, "input"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("node.%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}

	if !node.Attributes.Required {
		t.Error("node.Attributes.Required = false, want true")
	}
}

func TestStartFlow_NilRequest(t *testing.T) {
	// Passing a nil request should not panic; StartFlow ignores the request.
	a := newAdapter()
	state, err := a.StartFlow(context.Background(), nil)
	if err != nil {
		t.Fatalf("StartFlow(nil) returned error: %v", err)
	}
	if state == nil || len(state.Nodes) != 1 {
		t.Error("StartFlow(nil) did not return the expected single-node FlowState")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CompleteFlow tests
// ─────────────────────────────────────────────────────────────────────────────

func TestCompleteFlow_Success(t *testing.T) {
	const plain = "correct-horse-battery-staple"
	a := newAdapter()
	id := uuid.New()

	req := &authenticator.CompleteFlowRequest{
		TenantID:         uuid.New(),
		IdentityID:       id,
		FlowID:           uuid.New(),
		Values:           map[string]string{"password": plain},
		CredentialConfig: marshalCredConfig(t, mustHashPassword(t, plain)),
	}

	result, err := a.CompleteFlow(context.Background(), req)
	if err != nil {
		t.Fatalf("CompleteFlow returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("CompleteFlow returned nil AuthResult")
	}
	if result.IdentityID != id {
		t.Errorf("AuthResult.IdentityID = %v, want %v", result.IdentityID, id)
	}
	if result.AAL != "aal1" {
		t.Errorf("AuthResult.AAL = %q, want %q", result.AAL, "aal1")
	}
	if len(result.AMR) != 1 || result.AMR[0] != "pwd" {
		t.Errorf("AuthResult.AMR = %v, want [pwd]", result.AMR)
	}
}

func TestCompleteFlow_WrongPassword(t *testing.T) {
	a := newAdapter()
	req := &authenticator.CompleteFlowRequest{
		TenantID:         uuid.New(),
		IdentityID:       uuid.New(),
		FlowID:           uuid.New(),
		Values:           map[string]string{"password": "wrong-password"},
		CredentialConfig: marshalCredConfig(t, mustHashPassword(t, "correct-password")),
	}

	result, err := a.CompleteFlow(context.Background(), req)
	if err == nil {
		t.Fatal("CompleteFlow expected an error for wrong password, got nil")
	}
	if result != nil {
		t.Error("CompleteFlow expected nil AuthResult on failure, got non-nil")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("error message %q does not contain %q", err.Error(), "invalid credentials")
	}
}

func TestCompleteFlow_MissingPasswordValue(t *testing.T) {
	a := newAdapter()

	tests := []struct {
		name   string
		values map[string]string
	}{
		{
			name:   "nil map",
			values: nil,
		},
		{
			name:   "empty string value",
			values: map[string]string{"password": ""},
		},
		{
			name:   "wrong key",
			values: map[string]string{"pass": "secret"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &authenticator.CompleteFlowRequest{
				TenantID:         uuid.New(),
				IdentityID:       uuid.New(),
				FlowID:           uuid.New(),
				Values:           tc.values,
				CredentialConfig: marshalCredConfig(t, mustHashPassword(t, "any")),
			}
			_, err := a.CompleteFlow(context.Background(), req)
			if err == nil {
				t.Fatal("expected error for missing password value, got nil")
			}
			if !strings.Contains(err.Error(), "missing password value") {
				t.Errorf("error %q does not contain %q", err.Error(), "missing password value")
			}
		})
	}
}

func TestCompleteFlow_MalformedCredentialConfig(t *testing.T) {
	a := newAdapter()

	tests := []struct {
		name   string
		config json.RawMessage
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: json.RawMessage(""),
		},
		{
			name:   "invalid JSON",
			config: json.RawMessage("{not valid json"),
		},
		{
			name:   "JSON array instead of object",
			config: json.RawMessage(`["password"]`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &authenticator.CompleteFlowRequest{
				TenantID:         uuid.New(),
				IdentityID:       uuid.New(),
				FlowID:           uuid.New(),
				Values:           map[string]string{"password": "any"},
				CredentialConfig: tc.config,
			}
			_, err := a.CompleteFlow(context.Background(), req)
			if err == nil {
				t.Fatal("expected error for malformed credential config, got nil")
			}
		})
	}
}

func TestCompleteFlow_EmptyHashedPassword(t *testing.T) {
	// The stored hash is present but empty — bcrypt should reject it.
	a := newAdapter()
	req := &authenticator.CompleteFlowRequest{
		TenantID:         uuid.New(),
		IdentityID:       uuid.New(),
		FlowID:           uuid.New(),
		Values:           map[string]string{"password": "some-password"},
		CredentialConfig: marshalCredConfig(t, ""),
	}
	_, err := a.CompleteFlow(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when hashed_password is empty, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Enroll tests
// ─────────────────────────────────────────────────────────────────────────────

func TestEnroll_Success(t *testing.T) {
	const plain = "my-super-secret"
	a := newAdapter()

	req := &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		Values:     map[string]string{"password": plain},
	}

	result, err := a.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Enroll returned nil EnrollResult")
	}

	// CredentialType must be "password".
	if result.CredentialType != "password" {
		t.Errorf("EnrollResult.CredentialType = %q, want %q", result.CredentialType, "password")
	}

	// CredentialConfig must unmarshal to a valid credentialConfig.
	var cfg credentialConfig
	if err := json.Unmarshal(result.CredentialConfig, &cfg); err != nil {
		t.Fatalf("failed to unmarshal CredentialConfig: %v", err)
	}

	// HashedPassword must be a valid bcrypt hash.
	if !strings.HasPrefix(cfg.HashedPassword, "$2a$") && !strings.HasPrefix(cfg.HashedPassword, "$2b$") {
		t.Errorf("HashedPassword does not look like a bcrypt hash: %q", cfg.HashedPassword)
	}

	// The hash must verify against the submitted plaintext.
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.HashedPassword), []byte(plain)); err != nil {
		t.Errorf("stored hash does not match submitted password: %v", err)
	}
}

func TestEnroll_HashCost(t *testing.T) {
	// Verify that the adapter uses cost 12 as specified by bcryptCost.
	const plain = "cost-check-password"
	a := newAdapter()

	req := &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		Values:     map[string]string{"password": plain},
	}

	result, err := a.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll error: %v", err)
	}

	var cfg credentialConfig
	if err := json.Unmarshal(result.CredentialConfig, &cfg); err != nil {
		t.Fatalf("unmarshal CredentialConfig: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(cfg.HashedPassword))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != bcryptCost {
		t.Errorf("bcrypt cost = %d, want %d", cost, bcryptCost)
	}
}

func TestEnroll_MissingPasswordValue(t *testing.T) {
	a := newAdapter()

	tests := []struct {
		name   string
		values map[string]string
	}{
		{
			name:   "nil map",
			values: nil,
		},
		{
			name:   "empty string value",
			values: map[string]string{"password": ""},
		},
		{
			name:   "wrong key",
			values: map[string]string{"pw": "secret"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &authenticator.EnrollRequest{
				TenantID:   uuid.New(),
				IdentityID: uuid.New(),
				Values:     tc.values,
			}
			result, err := a.Enroll(context.Background(), req)
			if err == nil {
				t.Fatal("expected error for missing password value, got nil")
			}
			if result != nil {
				t.Error("expected nil EnrollResult on error, got non-nil")
			}
			if !strings.Contains(err.Error(), "missing password value") {
				t.Errorf("error %q does not contain %q", err.Error(), "missing password value")
			}
		})
	}
}

func TestEnroll_IdentifiersIsNil(t *testing.T) {
	// Password credentials are looked up by identity_id; identifiers must be nil.
	a := newAdapter()
	req := &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		Values:     map[string]string{"password": "secret"},
	}
	result, err := a.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll error: %v", err)
	}
	if result.Identifiers != nil {
		t.Errorf("EnrollResult.Identifiers = %v, want nil", result.Identifiers)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Unenroll tests
// ─────────────────────────────────────────────────────────────────────────────

func TestUnenroll_IsNoOp(t *testing.T) {
	a := newAdapter()
	req := &authenticator.UnenrollRequest{
		TenantID:     uuid.New(),
		IdentityID:   uuid.New(),
		CredentialID: uuid.New(),
	}
	if err := a.Unenroll(context.Background(), req); err != nil {
		t.Errorf("Unenroll returned non-nil error: %v", err)
	}
}

func TestUnenroll_NilRequest(t *testing.T) {
	a := newAdapter()
	if err := a.Unenroll(context.Background(), nil); err != nil {
		t.Errorf("Unenroll(nil) returned non-nil error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Round-trip: Enroll → CompleteFlow
// ─────────────────────────────────────────────────────────────────────────────

func TestEnrollThenCompleteFlow_RoundTrip(t *testing.T) {
	tests := []struct {
		name           string
		enrollPassword string
		submitPassword string
		wantSuccess    bool
	}{
		{
			name:           "correct password",
			enrollPassword: "hunter2",
			submitPassword: "hunter2",
			wantSuccess:    true,
		},
		{
			name:           "wrong password",
			enrollPassword: "hunter2",
			submitPassword: "hunter3",
			wantSuccess:    false,
		},
		{
			name:           "case sensitive mismatch",
			enrollPassword: "SecretPass",
			submitPassword: "secretpass",
			wantSuccess:    false,
		},
		{
			name:           "unicode password correct",
			enrollPassword: "p@ssw0rd-é",
			submitPassword: "p@ssw0rd-é",
			wantSuccess:    true,
		},
		{
			name:           "unicode password wrong",
			enrollPassword: "p@ssw0rd-é",
			submitPassword: "p@ssw0rd-e",
			wantSuccess:    false,
		},
	}

	a := newAdapter()
	ctx := context.Background()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tenantID := uuid.New()
			identityID := uuid.New()

			enrollReq := &authenticator.EnrollRequest{
				TenantID:   tenantID,
				IdentityID: identityID,
				Values:     map[string]string{"password": tc.enrollPassword},
			}
			enrolled, err := a.Enroll(ctx, enrollReq)
			if err != nil {
				t.Fatalf("Enroll error: %v", err)
			}

			completeReq := &authenticator.CompleteFlowRequest{
				TenantID:         tenantID,
				IdentityID:       identityID,
				FlowID:           uuid.New(),
				Values:           map[string]string{"password": tc.submitPassword},
				CredentialConfig: enrolled.CredentialConfig,
			}
			result, err := a.CompleteFlow(ctx, completeReq)

			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("CompleteFlow expected success, got error: %v", err)
				}
				if result == nil {
					t.Fatal("CompleteFlow returned nil AuthResult on expected success")
				}
				if result.IdentityID != identityID {
					t.Errorf("AuthResult.IdentityID = %v, want %v", result.IdentityID, identityID)
				}
				if result.AAL != "aal1" {
					t.Errorf("AuthResult.AAL = %q, want aal1", result.AAL)
				}
				if len(result.AMR) != 1 || result.AMR[0] != "pwd" {
					t.Errorf("AuthResult.AMR = %v, want [pwd]", result.AMR)
				}
			} else {
				if err == nil {
					t.Fatal("CompleteFlow expected failure, got nil error")
				}
				if result != nil {
					t.Error("CompleteFlow expected nil AuthResult on failure")
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Interface compliance
// ─────────────────────────────────────────────────────────────────────────────

// TestAdapterImplementsInterface is a compile-time check that *Adapter satisfies
// the authenticator.Authenticator interface.
func TestAdapterImplementsInterface(t *testing.T) {
	var _ authenticator.Authenticator = (*Adapter)(nil)
}
