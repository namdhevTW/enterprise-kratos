package tenant

import "github.com/google/uuid"

// State represents the lifecycle state of a tenant.
type State string

const (
	StateActive   State = "active"
	StateInactive State = "inactive"
	StateSuspended State = "suspended"
)

// Tenant represents a single isolated tenant in the IDP.
type Tenant struct {
	ID    uuid.UUID `json:"id"    db:"id"`
	Slug  string    `json:"slug"  db:"slug"`
	Name  string    `json:"name"  db:"name"`
	State State     `json:"state" db:"state"`
}
