-- name: GetTenantBySlug :one
SELECT id, slug, name, state
FROM tenants
WHERE slug = $1;

-- name: GetTenantByID :one
SELECT id, slug, name, state
FROM tenants
WHERE id = $1;

-- name: CreateTenant :one
INSERT INTO tenants (slug, name)
VALUES ($1, $2)
RETURNING id, slug, name, state;

-- name: UpdateTenantState :exec
UPDATE tenants
SET state = $2
WHERE id = $1;

-- name: ListTenants :many
SELECT id, slug, name, state
FROM tenants
ORDER BY name ASC;
