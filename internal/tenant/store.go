package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/enterprise-idp/idpd/internal/dbutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Repository methods when the requested tenant does
// not exist. Callers can test for it with errors.Is.
var ErrNotFound = errors.New("tenant not found")

// Store is a pgx-backed implementation of Repository.
type Store struct {
	pool dbutil.Querier
}

// NewStore constructs a Store from an existing pgxpool.Pool. The caller is
// responsible for the pool lifecycle (Close).
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: dbutil.Wrap(pool)}
}

const sqlGetBySlug = `
SELECT id, slug, name, state
FROM tenants
WHERE slug = $1
`

// GetBySlug implements Repository.
func (s *Store) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	row := s.pool.QueryRow(ctx, sqlGetBySlug, slug)
	t, err := scanTenant(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("GetBySlug %q: %w", slug, ErrNotFound)
		}
		return nil, fmt.Errorf("GetBySlug %q: %w", slug, err)
	}
	return t, nil
}

const sqlGetByID = `
SELECT id, slug, name, state
FROM tenants
WHERE id = $1
`

// GetByID implements Repository.
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	row := s.pool.QueryRow(ctx, sqlGetByID, id)
	t, err := scanTenant(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("GetByID %q: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("GetByID %q: %w", id, err)
	}
	return t, nil
}

const sqlCreate = `
INSERT INTO tenants (slug, name)
VALUES ($1, $2)
RETURNING id, slug, name, state
`

// Create implements Repository.
func (s *Store) Create(ctx context.Context, slug, name string) (*Tenant, error) {
	row := s.pool.QueryRow(ctx, sqlCreate, slug, name)
	t, err := scanTenant(row)
	if err != nil {
		return nil, fmt.Errorf("Create tenant slug=%q name=%q: %w", slug, name, err)
	}
	return t, nil
}

const sqlUpdateState = `
UPDATE tenants
SET state = $2
WHERE id = $1
`

// UpdateState implements Repository.
func (s *Store) UpdateState(ctx context.Context, id uuid.UUID, state string) error {
	tag, err := s.pool.Exec(ctx, sqlUpdateState, id, state)
	if err != nil {
		return fmt.Errorf("UpdateState id=%q state=%q: %w", id, state, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("UpdateState id=%q: %w", id, ErrNotFound)
	}
	return nil
}

const sqlList = `
SELECT id, slug, name, state
FROM tenants
ORDER BY name ASC
`

// List implements Repository.
func (s *Store) List(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.pool.Query(ctx, sqlList)
	if err != nil {
		return nil, fmt.Errorf("List tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, fmt.Errorf("List tenants scan: %w", err)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("List tenants iterate: %w", err)
	}
	return tenants, nil
}

// scanner is satisfied by both pgx.Row and pgx.Rows so we can share scanTenant.
type scanner interface {
	Scan(dest ...any) error
}

// scanTenant reads a single tenant row in (id, slug, name, state) column order.
func scanTenant(s scanner) (*Tenant, error) {
	var t Tenant
	err := s.Scan(&t.ID, &t.Slug, &t.Name, &t.State)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
