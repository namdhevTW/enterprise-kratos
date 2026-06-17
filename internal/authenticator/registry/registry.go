package registry

import (
	"errors"
	"fmt"
	"sync"

	"github.com/enterprise-idp/idpd/internal/authenticator"
)

// ErrNotFound is returned when no authenticator is registered for a given ID.
var ErrNotFound = errors.New("authenticator not found")

// Registry maps authenticator IDs to their implementations. It is safe for
// concurrent use after all registrations are complete.
type Registry struct {
	mu    sync.RWMutex
	auths map[string]authenticator.Authenticator
}

// New returns an empty Registry.
func New() *Registry {
	return &Registry{auths: make(map[string]authenticator.Authenticator)}
}

// Register adds a to the registry. Returns an error if an authenticator with
// the same ID is already registered.
func (reg *Registry) Register(a authenticator.Authenticator) error {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	id := a.ID()
	if _, exists := reg.auths[id]; exists {
		return fmt.Errorf("authenticator %q is already registered", id)
	}
	reg.auths[id] = a
	return nil
}

// MustRegister calls Register and panics on error. Intended for use in init
// functions or server startup where a conflict is a programming error.
func (reg *Registry) MustRegister(a authenticator.Authenticator) {
	if err := reg.Register(a); err != nil {
		panic(err)
	}
}

// Get retrieves the authenticator registered under id. Returns ErrNotFound
// (wrapped) if no match exists.
func (reg *Registry) Get(id string) (authenticator.Authenticator, error) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	a, ok := reg.auths[id]
	if !ok {
		return nil, fmt.Errorf("registry.Get %q: %w", id, ErrNotFound)
	}
	return a, nil
}

// All returns a snapshot of every registered authenticator in undefined order.
func (reg *Registry) All() []authenticator.Authenticator {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	out := make([]authenticator.Authenticator, 0, len(reg.auths))
	for _, a := range reg.auths {
		out = append(out, a)
	}
	return out
}

// OfType returns all authenticators whose Type() matches t.
func (reg *Registry) OfType(t authenticator.Type) []authenticator.Authenticator {
	reg.mu.RLock()
	defer reg.mu.RUnlock()

	var out []authenticator.Authenticator
	for _, a := range reg.auths {
		if a.Type() == t || a.Type() == authenticator.Either {
			out = append(out, a)
		}
	}
	return out
}
