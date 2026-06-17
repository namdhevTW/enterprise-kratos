package tenant

import (
	"context"

	"github.com/google/uuid"
)

type contextKey int

const (
	tenantKey   contextKey = iota
	tenantIDKey contextKey = iota
)

// WithTenant returns a new context carrying the given *Tenant and its UUID.
func WithTenant(ctx context.Context, t *Tenant) context.Context {
	ctx = context.WithValue(ctx, tenantKey, t)
	ctx = context.WithValue(ctx, tenantIDKey, t.ID)
	return ctx
}

// TenantFromContext retrieves the *Tenant stored by the middleware. Returns nil
// when the context was not enriched by the tenant middleware.
func TenantFromContext(ctx context.Context) *Tenant {
	t, _ := ctx.Value(tenantKey).(*Tenant)
	return t
}

// TenantIDFromContext retrieves the tenant UUID stored by the middleware.
// Returns uuid.Nil when the context was not enriched by the tenant middleware.
func TenantIDFromContext(ctx context.Context) uuid.UUID {
	id, _ := ctx.Value(tenantIDKey).(uuid.UUID)
	return id
}
