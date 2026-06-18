// Package dbutil provides a thin abstraction over pgxpool.Pool so that stores
// can be unit-tested with pgxmock without depending on a real database.
package dbutil

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the minimal interface required by IDP store implementations.
// *pgxpool.Pool satisfies it via Wrap; pgxmock pools satisfy it directly.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// poolAdapter wraps *pgxpool.Pool so its QueryRow return type (pgxpool.Row)
// is narrowed to the pgx.Row interface expected by Querier.
type poolAdapter struct{ p *pgxpool.Pool }

func (a *poolAdapter) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return a.p.QueryRow(ctx, sql, args...)
}
func (a *poolAdapter) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return a.p.Query(ctx, sql, args...)
}
func (a *poolAdapter) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return a.p.Exec(ctx, sql, args...)
}

// Wrap returns a Querier backed by pool. Use this when constructing stores.
func Wrap(pool *pgxpool.Pool) Querier { return &poolAdapter{p: pool} }
