package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/enterprise-idp/idpd/internal/authenticator"
)

// stubAuthn is a minimal Authenticator implementation used only in tests.
type stubAuthn struct {
	id    string
	atype authenticator.Type
}

func (s *stubAuthn) ID() string             { return s.id }
func (s *stubAuthn) Type() authenticator.Type { return s.atype }

func (s *stubAuthn) StartFlow(_ context.Context, _ *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
	return &authenticator.FlowState{}, nil
}

func (s *stubAuthn) CompleteFlow(_ context.Context, _ *authenticator.CompleteFlowRequest) (*authenticator.AuthResult, error) {
	return &authenticator.AuthResult{}, nil
}

func (s *stubAuthn) Enroll(_ context.Context, _ *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
	return &authenticator.EnrollResult{}, nil
}

func (s *stubAuthn) Unenroll(_ context.Context, _ *authenticator.UnenrollRequest) error {
	return nil
}

// helpers

func newStub(id string, t authenticator.Type) *stubAuthn {
	return &stubAuthn{id: id, atype: t}
}

// mustRegisterAll registers all stubs into reg without error, failing the test
// immediately if any registration returns an error.
func mustRegisterAll(tb testing.TB, reg *Registry, stubs ...*stubAuthn) {
	tb.Helper()
	for _, s := range stubs {
		if err := reg.Register(s); err != nil {
			tb.Fatalf("unexpected Register error for %q: %v", s.id, err)
		}
	}
}

// idsOf extracts the ID of each authenticator in the slice and returns them as
// a sorted (via map existence) set for order-independent comparison.
func idsOf(auths []authenticator.Authenticator) map[string]struct{} {
	m := make(map[string]struct{}, len(auths))
	for _, a := range auths {
		m[a.ID()] = struct{}{}
	}
	return m
}

// ---------------------------------------------------------------------------
// New()
// ---------------------------------------------------------------------------

func TestNew_ReturnsEmptyRegistry(t *testing.T) {
	t.Parallel()

	reg := New()

	if reg == nil {
		t.Fatal("New() returned nil")
	}
	if got := reg.All(); len(got) != 0 {
		t.Errorf("expected empty registry, got %d authenticator(s)", len(got))
	}
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegister_Success_GetReturnsRegistered(t *testing.T) {
	t.Parallel()

	reg := New()
	stub := newStub("password", authenticator.FirstFactor)

	if err := reg.Register(stub); err != nil {
		t.Fatalf("Register returned unexpected error: %v", err)
	}

	got, err := reg.Get("password")
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	if got != stub {
		t.Errorf("Get returned %v, want %v", got, stub)
	}
}

func TestRegister_Duplicate_ReturnsErrorWithID(t *testing.T) {
	t.Parallel()

	reg := New()
	stub := newStub("totp", authenticator.SecondFactor)

	if err := reg.Register(stub); err != nil {
		t.Fatalf("first Register returned unexpected error: %v", err)
	}

	err := reg.Register(stub)
	if err == nil {
		t.Fatal("expected error on duplicate Register, got nil")
	}
	if !strings.Contains(err.Error(), "totp") {
		t.Errorf("error message %q does not contain authenticator ID %q", err.Error(), "totp")
	}
}

func TestRegister_Duplicate_DifferentInstance_SameID_ReturnsError(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg, newStub("otp", authenticator.SecondFactor))

	// A second, distinct instance with the same ID must also be rejected.
	duplicate := newStub("otp", authenticator.SecondFactor)
	err := reg.Register(duplicate)
	if err == nil {
		t.Fatal("expected error registering second authenticator with same ID, got nil")
	}
}

// ---------------------------------------------------------------------------
// MustRegister
// ---------------------------------------------------------------------------

func TestMustRegister_Duplicate_Panics(t *testing.T) {
	t.Parallel()

	reg := New()
	reg.MustRegister(newStub("passkey", authenticator.SecondFactor))

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate MustRegister, but did not panic")
		}
	}()

	reg.MustRegister(newStub("passkey", authenticator.SecondFactor))
}

func TestMustRegister_Success_NoPanic(t *testing.T) {
	t.Parallel()

	reg := New()

	// Should not panic.
	reg.MustRegister(newStub("saml", authenticator.FirstFactor))

	got, err := reg.Get("saml")
	if err != nil {
		t.Fatalf("Get after MustRegister returned error: %v", err)
	}
	if got.ID() != "saml" {
		t.Errorf("got ID %q, want %q", got.ID(), "saml")
	}
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

func TestGet_NotFound_ReturnsErrNotFound(t *testing.T) {
	t.Parallel()

	reg := New()

	_, err := reg.Get("nonexistent")
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("errors.Is(err, ErrNotFound) = false; err = %v", err)
	}
}

func TestGet_NotFound_AfterOtherRegistrations(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg,
		newStub("password", authenticator.FirstFactor),
		newStub("totp", authenticator.SecondFactor),
	)

	_, err := reg.Get("oidc")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unregistered ID, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// All()
// ---------------------------------------------------------------------------

func TestAll_Empty_ReturnsEmptySlice(t *testing.T) {
	t.Parallel()

	reg := New()
	all := reg.All()

	if all == nil {
		t.Fatal("All() returned nil, want non-nil empty slice")
	}
	if len(all) != 0 {
		t.Errorf("All() returned %d items, want 0", len(all))
	}
}

func TestAll_WithItems_ReturnsAll(t *testing.T) {
	t.Parallel()

	reg := New()
	stubs := []*stubAuthn{
		newStub("password", authenticator.FirstFactor),
		newStub("totp", authenticator.SecondFactor),
		newStub("otp", authenticator.SecondFactor),
	}
	mustRegisterAll(t, reg, stubs...)

	all := reg.All()
	if len(all) != len(stubs) {
		t.Fatalf("All() returned %d items, want %d", len(all), len(stubs))
	}

	ids := idsOf(all)
	for _, s := range stubs {
		if _, ok := ids[s.id]; !ok {
			t.Errorf("All() missing authenticator %q", s.id)
		}
	}
}

func TestAll_ReturnsCopy_NotAliasedSlice(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg, newStub("password", authenticator.FirstFactor))

	a1 := reg.All()
	a2 := reg.All()

	// Mutating one slice must not affect the registry or the other slice.
	a1[0] = nil
	a2Result := reg.All()
	if len(a2Result) != 1 || a2Result[0] == nil {
		t.Error("All() snapshots appear to share backing storage with the registry")
	}
	_ = a2
}

// ---------------------------------------------------------------------------
// OfType
// ---------------------------------------------------------------------------

func TestOfType_FirstFactor_ReturnsOnlyFirstFactor(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg,
		newStub("password", authenticator.FirstFactor),
		newStub("oidc", authenticator.FirstFactor),
		newStub("totp", authenticator.SecondFactor),
		newStub("otp", authenticator.SecondFactor),
	)

	got := reg.OfType(authenticator.FirstFactor)

	// Either type is also acceptable (none registered here, but the predicate
	// should not exclude second-factor-only authenticators from a FirstFactor
	// query — only Either-typed ones satisfy both).
	for _, a := range got {
		at := a.Type()
		if at != authenticator.FirstFactor && at != authenticator.Either {
			t.Errorf("OfType(FirstFactor) returned authenticator %q with type %d", a.ID(), at)
		}
	}

	ids := idsOf(got)
	if _, ok := ids["password"]; !ok {
		t.Error("OfType(FirstFactor) missing 'password'")
	}
	if _, ok := ids["oidc"]; !ok {
		t.Error("OfType(FirstFactor) missing 'oidc'")
	}
	if _, ok := ids["totp"]; ok {
		t.Error("OfType(FirstFactor) should not include 'totp' (SecondFactor)")
	}
	if _, ok := ids["otp"]; ok {
		t.Error("OfType(FirstFactor) should not include 'otp' (SecondFactor)")
	}
}

func TestOfType_SecondFactor_ReturnsOnlySecondFactor(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg,
		newStub("password", authenticator.FirstFactor),
		newStub("totp", authenticator.SecondFactor),
		newStub("passkey", authenticator.SecondFactor),
	)

	got := reg.OfType(authenticator.SecondFactor)

	for _, a := range got {
		at := a.Type()
		if at != authenticator.SecondFactor && at != authenticator.Either {
			t.Errorf("OfType(SecondFactor) returned authenticator %q with type %d", a.ID(), at)
		}
	}

	ids := idsOf(got)
	if _, ok := ids["totp"]; !ok {
		t.Error("OfType(SecondFactor) missing 'totp'")
	}
	if _, ok := ids["passkey"]; !ok {
		t.Error("OfType(SecondFactor) missing 'passkey'")
	}
	if _, ok := ids["password"]; ok {
		t.Error("OfType(SecondFactor) should not include 'password' (FirstFactor)")
	}
}

func TestOfType_Either_MatchesBothFirstAndSecondQueries(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg,
		newStub("magic-link", authenticator.Either),
		newStub("password", authenticator.FirstFactor),
		newStub("totp", authenticator.SecondFactor),
	)

	// An Either-typed authenticator must appear in both OfType(FirstFactor)
	// and OfType(SecondFactor) results.
	firstFactors := idsOf(reg.OfType(authenticator.FirstFactor))
	secondFactors := idsOf(reg.OfType(authenticator.SecondFactor))

	if _, ok := firstFactors["magic-link"]; !ok {
		t.Error("Either-typed 'magic-link' should appear in OfType(FirstFactor)")
	}
	if _, ok := secondFactors["magic-link"]; !ok {
		t.Error("Either-typed 'magic-link' should appear in OfType(SecondFactor)")
	}

	// The plain first/second factor authenticators must not bleed into each
	// other's results.
	if _, ok := secondFactors["password"]; ok {
		t.Error("FirstFactor-only 'password' should not appear in OfType(SecondFactor)")
	}
	if _, ok := firstFactors["totp"]; ok {
		t.Error("SecondFactor-only 'totp' should not appear in OfType(FirstFactor)")
	}
}

func TestOfType_NoMatches_ReturnsNilOrEmptySlice(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg, newStub("password", authenticator.FirstFactor))

	got := reg.OfType(authenticator.SecondFactor)
	if len(got) != 0 {
		t.Errorf("expected no SecondFactor authenticators, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Concurrent safety
// ---------------------------------------------------------------------------

func TestRegistry_ConcurrentRegisterAndGet_Goroutine_Safe(t *testing.T) {
	t.Parallel()

	const numWorkers = 50

	reg := New()

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	// Each goroutine registers a uniquely-named authenticator, then immediately
	// reads it back. No synchronisation beyond the Registry's own mutex.
	for i := 0; i < numWorkers; i++ {
		i := i
		go func() {
			defer wg.Done()

			id := fmt.Sprintf("authn-%d", i)
			stub := newStub(id, authenticator.FirstFactor)

			if err := reg.Register(stub); err != nil {
				// A race between goroutines with the same id would be a bug in
				// the test, not the registry — IDs are unique here.
				t.Errorf("Register(%q) unexpected error: %v", id, err)
				return
			}

			got, err := reg.Get(id)
			if err != nil {
				t.Errorf("Get(%q) unexpected error: %v", id, err)
				return
			}
			if got.ID() != id {
				t.Errorf("Get(%q) returned authenticator with ID %q", id, got.ID())
			}
		}()
	}

	wg.Wait()

	// Verify final count.
	all := reg.All()
	if len(all) != numWorkers {
		t.Errorf("expected %d registered authenticators after concurrent registrations, got %d",
			numWorkers, len(all))
	}
}

func TestRegistry_ConcurrentAllAndOfType_DoNotRace(t *testing.T) {
	t.Parallel()

	reg := New()
	mustRegisterAll(t, reg,
		newStub("password", authenticator.FirstFactor),
		newStub("totp", authenticator.SecondFactor),
		newStub("magic", authenticator.Either),
	)

	const readers = 30
	var wg sync.WaitGroup
	wg.Add(readers * 2)

	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			_ = reg.All()
		}()
		go func() {
			defer wg.Done()
			_ = reg.OfType(authenticator.FirstFactor)
		}()
	}

	wg.Wait()
}
