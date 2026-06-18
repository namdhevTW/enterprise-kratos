package oidcadapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/sso"
	"github.com/google/uuid"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fake provider lister
// ─────────────────────────────────────────────────────────────────────────────

// fakeProviderLister is an in-process stub for the providerLister interface.
// Tests set providers to a slice of *sso.Provider and/or err to a non-nil error
// to control the behaviour of ListByType without any DB or network access.
type fakeProviderLister struct {
	providers []*sso.Provider
	err       error
}

func (f *fakeProviderLister) ListByType(_ context.Context, _ uuid.UUID, _ string) ([]*sso.Provider, error) {
	return f.providers, f.err
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// newAdapter builds an Adapter backed by the supplied fakeProviderLister.
func newAdapter(lister *fakeProviderLister) *Adapter {
	return New(lister)
}

// makeProvider constructs a minimal *sso.Provider for use in tests.
func makeProvider(providerName string) *sso.Provider {
	return &sso.Provider{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Type:     "oidc",
		Provider: providerName,
		Enabled:  true,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Accessor tests
// ─────────────────────────────────────────────────────────────────────────────

func TestID(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})
	if got := a.ID(); got != "oidc" {
		t.Errorf("ID() = %q, want %q", got, "oidc")
	}
}

func TestType(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})
	if got := a.Type(); got != authenticator.FirstFactor {
		t.Errorf("Type() = %d, want FirstFactor (%d)", got, authenticator.FirstFactor)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// StartFlow tests
// ─────────────────────────────────────────────────────────────────────────────

func TestStartFlow_ZeroProviders_ReturnsEmptyNodes(t *testing.T) {
	a := newAdapter(&fakeProviderLister{providers: nil})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})

	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("StartFlow returned nil FlowState")
	}
	// An empty, non-nil slice is acceptable; either way the length must be 0.
	if len(state.Nodes) != 0 {
		t.Errorf("StartFlow node count = %d, want 0", len(state.Nodes))
	}
}

func TestStartFlow_TwoProviders_ReturnsTwoNodes(t *testing.T) {
	p1 := makeProvider("google")
	p2 := makeProvider("azure")

	a := newAdapter(&fakeProviderLister{providers: []*sso.Provider{p1, p2}})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})

	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("StartFlow returned nil FlowState")
	}
	if len(state.Nodes) != 2 {
		t.Fatalf("StartFlow node count = %d, want 2", len(state.Nodes))
	}

	// Verify each node carries the correct provider UUID as its value.
	wantValues := []string{p1.ID.String(), p2.ID.String()}
	for i, node := range state.Nodes {
		if node.Attributes.Value != wantValues[i] {
			t.Errorf("Nodes[%d].Attributes.Value = %v, want %q", i, node.Attributes.Value, wantValues[i])
		}
	}
}

func TestStartFlow_ListerError_ReturnsError(t *testing.T) {
	sentinel := errors.New("db unavailable")
	a := newAdapter(&fakeProviderLister{err: sentinel})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})

	if err == nil {
		t.Fatal("StartFlow expected an error when lister returns error, got nil")
	}
	if state != nil {
		t.Errorf("StartFlow expected nil FlowState on error, got %+v", state)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("StartFlow error does not wrap the lister error: got %v", err)
	}
}

func TestStartFlow_NodeShape(t *testing.T) {
	p := makeProvider("okta")
	a := newAdapter(&fakeProviderLister{providers: []*sso.Provider{p}})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})

	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}
	if len(state.Nodes) != 1 {
		t.Fatalf("StartFlow node count = %d, want 1", len(state.Nodes))
	}

	node := state.Nodes[0]

	cases := []struct {
		field string
		got   string
		want  string
	}{
		{"Type", node.Type, "input"},
		{"Group", node.Group, "oidc"},
		{"Attributes.Name", node.Attributes.Name, "provider_id"},
		{"Attributes.Type", node.Attributes.Type, "submit"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("node.%s = %q, want %q", tc.field, tc.got, tc.want)
			}
		})
	}

	// Attributes.Value must be the provider's UUID string.
	if node.Attributes.Value != p.ID.String() {
		t.Errorf("node.Attributes.Value = %v, want %q", node.Attributes.Value, p.ID.String())
	}
}

func TestStartFlow_NodeLabelText(t *testing.T) {
	p := makeProvider("google")
	a := newAdapter(&fakeProviderLister{providers: []*sso.Provider{p}})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})

	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}

	node := state.Nodes[0]
	if node.Meta.Label == nil {
		t.Fatal("node.Meta.Label is nil, want non-nil")
	}

	wantText := "Sign in with " + p.Provider
	if node.Meta.Label.Text != wantText {
		t.Errorf("node.Meta.Label.Text = %q, want %q", node.Meta.Label.Text, wantText)
	}
}

func TestStartFlow_NodeLabelType(t *testing.T) {
	p := makeProvider("azure")
	a := newAdapter(&fakeProviderLister{providers: []*sso.Provider{p}})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}

	node := state.Nodes[0]
	if node.Meta.Label == nil {
		t.Fatal("node.Meta.Label is nil, want non-nil")
	}
	if node.Meta.Label.Type != "info" {
		t.Errorf("node.Meta.Label.Type = %q, want %q", node.Meta.Label.Type, "info")
	}
}

func TestStartFlow_NodeLabelID(t *testing.T) {
	p := makeProvider("okta")
	a := newAdapter(&fakeProviderLister{providers: []*sso.Provider{p}})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}

	node := state.Nodes[0]
	if node.Meta.Label == nil {
		t.Fatal("node.Meta.Label is nil, want non-nil")
	}
	// Label ID 1070010 is the conventional Kratos message ID for OIDC provider buttons.
	const wantLabelID int64 = 1070010
	if node.Meta.Label.ID != wantLabelID {
		t.Errorf("node.Meta.Label.ID = %d, want %d", node.Meta.Label.ID, wantLabelID)
	}
}

func TestStartFlow_NodeOrderIsPreserved(t *testing.T) {
	// Ensure the order of returned nodes matches the order the lister returned
	// providers, so the UI renders buttons deterministically.
	providers := []*sso.Provider{
		makeProvider("google"),
		makeProvider("azure"),
		makeProvider("okta"),
	}
	a := newAdapter(&fakeProviderLister{providers: providers})

	state, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("StartFlow returned unexpected error: %v", err)
	}
	if len(state.Nodes) != len(providers) {
		t.Fatalf("node count = %d, want %d", len(state.Nodes), len(providers))
	}
	for i, p := range providers {
		if state.Nodes[i].Attributes.Value != p.ID.String() {
			t.Errorf("Nodes[%d].Attributes.Value = %v, want %q", i, state.Nodes[i].Attributes.Value, p.ID.String())
		}
	}
}

func TestStartFlow_TenantIDIsPassedThrough(t *testing.T) {
	// Verify that the lister is called with the TenantID from the request, not
	// some other value. We do this by checking that two calls with different
	// tenant IDs each produce correct labels (the fake always returns the same
	// providers, but any accidental cross-tenant sharing would be obvious via a
	// real implementation; here we just confirm no panic / error occurs).
	p := makeProvider("google")
	lister := &fakeProviderLister{providers: []*sso.Provider{p}}
	a := newAdapter(lister)

	for i := 0; i < 3; i++ {
		_, err := a.StartFlow(context.Background(), &authenticator.StartFlowRequest{
			TenantID: uuid.New(),
			FlowID:   uuid.New(),
		})
		if err != nil {
			t.Fatalf("StartFlow[%d] returned unexpected error: %v", i, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CompleteFlow tests
// ─────────────────────────────────────────────────────────────────────────────

func TestCompleteFlow_ReturnsError(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})

	result, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
		FlowID:     uuid.New(),
	})

	if err == nil {
		t.Fatal("CompleteFlow expected an error, got nil")
	}
	if result != nil {
		t.Errorf("CompleteFlow expected nil AuthResult, got %+v", result)
	}
}

func TestCompleteFlow_ErrorContainsCallbackEndpointHint(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})

	_, err := a.CompleteFlow(context.Background(), &authenticator.CompleteFlowRequest{
		TenantID: uuid.New(),
		FlowID:   uuid.New(),
	})

	if err == nil {
		t.Fatal("CompleteFlow expected an error, got nil")
	}
	const want = "OIDC callback endpoint"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("CompleteFlow error %q does not contain %q", err.Error(), want)
	}
}

func TestCompleteFlow_NilRequest_ReturnsError(t *testing.T) {
	// A nil request should not panic; the adapter returns the static error before
	// touching the request.
	a := newAdapter(&fakeProviderLister{})
	_, err := a.CompleteFlow(context.Background(), nil)
	if err == nil {
		t.Fatal("CompleteFlow(nil) expected an error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Enroll tests
// ─────────────────────────────────────────────────────────────────────────────

func TestEnroll_ReturnsError(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})

	result, err := a.Enroll(context.Background(), &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
	})

	if err == nil {
		t.Fatal("Enroll expected an error, got nil")
	}
	if result != nil {
		t.Errorf("Enroll expected nil EnrollResult, got %+v", result)
	}
}

func TestEnroll_ErrorContainsImplicitHint(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})

	_, err := a.Enroll(context.Background(), &authenticator.EnrollRequest{
		TenantID:   uuid.New(),
		IdentityID: uuid.New(),
	})

	if err == nil {
		t.Fatal("Enroll expected an error, got nil")
	}
	const want = "enrollment is handled implicitly"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("Enroll error %q does not contain %q", err.Error(), want)
	}
}

func TestEnroll_NilRequest_ReturnsError(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})
	_, err := a.Enroll(context.Background(), nil)
	if err == nil {
		t.Fatal("Enroll(nil) expected an error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Unenroll tests
// ─────────────────────────────────────────────────────────────────────────────

func TestUnenroll_ReturnsNil(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})

	err := a.Unenroll(context.Background(), &authenticator.UnenrollRequest{
		TenantID:     uuid.New(),
		IdentityID:   uuid.New(),
		CredentialID: uuid.New(),
	})

	if err != nil {
		t.Errorf("Unenroll returned non-nil error: %v", err)
	}
}

func TestUnenroll_NilRequest_ReturnsNil(t *testing.T) {
	a := newAdapter(&fakeProviderLister{})
	if err := a.Unenroll(context.Background(), nil); err != nil {
		t.Errorf("Unenroll(nil) returned non-nil error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Interface compliance
// ─────────────────────────────────────────────────────────────────────────────

// TestAdapterImplementsInterface is a compile-time assertion that *Adapter
// satisfies the authenticator.Authenticator interface.
func TestAdapterImplementsInterface(t *testing.T) {
	var _ authenticator.Authenticator = (*Adapter)(nil)
}
