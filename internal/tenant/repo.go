package tenant

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the data access contract for tenant operations.
// All methods are tenant-aware and return wrapped errors for upstream handling.
type Repository interface {
	// GetBySlug retrieves a tenant by its URL-safe slug.
	// Returns ErrNotFound (wrapped) when no tenant matches.
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)

	// GetByID retrieves a tenant by its UUID primary key.
	// Returns ErrNotFound (wrapped) when no tenant matches.
	GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error)

	// Create inserts a new tenant with the given slug and name.
	// The initial state is set to 'active' by the database default.
	Create(ctx context.Context, slug, name string) (*Tenant, error)

	// UpdateState transitions a tenant to the given state string.
	UpdateState(ctx context.Context, id uuid.UUID, state string) error

	// List returns all tenants ordered by name ascending.
	List(ctx context.Context) ([]*Tenant, error)
}
