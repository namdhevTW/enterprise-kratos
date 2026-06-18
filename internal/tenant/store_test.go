package tenant

import (
	"context"
	"errors"
	"regexp"
	"testing"

	pgxmock "github.com/pashagolub/pgxmock/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// newTestTenantStore creates a Store backed by a pgxmock pool. The caller is
// responsible for calling mock.ExpectationsWereMet() at the end of each test.
func newTestTenantStore(t *testing.T) (*Store, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	s := &Store{pool: mock}
	return s, mock
}

// tenantRow returns a new pgxmock.Rows pre-populated with a single Tenant row.
func tenantRow(t *Tenant) *pgxmock.Rows {
	return pgxmock.NewRows([]string{"id", "slug", "name", "state"}).
		AddRow(t.ID, t.Slug, t.Name, t.State)
}

// emptyTenantRows returns a Rows set with the expected columns but no data
// rows, causing pgx.Row.Scan to return pgx.ErrNoRows.
func emptyTenantRows() *pgxmock.Rows {
	return pgxmock.NewRows([]string{"id", "slug", "name", "state"})
}

// ---------------------------------------------------------------------------
// GetBySlug
// ---------------------------------------------------------------------------

func TestStore_GetBySlug_Success(t *testing.T) {
	s, mock := newTestTenantStore(t)
	defer mock.ExpectationsWereMet() //nolint:errcheck

	want := &Tenant{
		ID:    uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Slug:  "acme",
		Name:  "Acme Corp",
		State: StateActive,
	}

	mock.ExpectQuery(regexp.QuoteMeta(sqlGetBySlug)).
		WithArgs("acme").
		WillReturnRows(tenantRow(want))

	got, err := s.GetBySlug(context.Background(), "acme")
	if err != nil {
		t.Fatalf("GetBySlug: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetBySlug: returned nil tenant")
	}
	if got.ID != want.ID {
		t.Errorf("ID: got %s, want %s", got.ID, want.ID)
	}
	if got.Slug != want.Slug {
		t.Errorf("Slug: got %q, want %q", got.Slug, want.Slug)
	}
	if got.Name != want.Name {
		t.Errorf("Name: got %q, want %q", got.Name, want.Name)
	}
	if got.State != want.State {
		t.Errorf("State: got %q, want %q", got.State, want.State)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetBySlug_NotFound(t *testing.T) {
	s, mock := newTestTenantStore(t)

	mock.ExpectQuery(regexp.QuoteMeta(sqlGetBySlug)).
		WithArgs("missing").
		WillReturnRows(emptyTenantRows())

	_, err := s.GetBySlug(context.Background(), "missing")
	if err == nil {
		t.Fatal("GetBySlug: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetBySlug: error = %v, want errors.Is(ErrNotFound)", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetBySlug_DBError(t *testing.T) {
	s, mock := newTestTenantStore(t)

	dbErr := errors.New("connection reset by peer")
	mock.ExpectQuery(regexp.QuoteMeta(sqlGetBySlug)).
		WithArgs("acme").
		WillReturnError(dbErr)

	_, err := s.GetBySlug(context.Background(), "acme")
	if err == nil {
		t.Fatal("GetBySlug: expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("GetBySlug: DB error should NOT be wrapped as ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("GetBySlug: error = %v, want to wrap %v", err, dbErr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------------

func TestStore_GetByID_Success(t *testing.T) {
	s, mock := newTestTenantStore(t)

	want := &Tenant{
		ID:    uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Slug:  "beta",
		Name:  "Beta Inc",
		State: StateActive,
	}

	mock.ExpectQuery(regexp.QuoteMeta(sqlGetByID)).
		WithArgs(want.ID).
		WillReturnRows(tenantRow(want))

	got, err := s.GetByID(context.Background(), want.ID)
	if err != nil {
		t.Fatalf("GetByID: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetByID: returned nil tenant")
	}
	if got.ID != want.ID {
		t.Errorf("ID: got %s, want %s", got.ID, want.ID)
	}
	if got.Slug != want.Slug {
		t.Errorf("Slug: got %q, want %q", got.Slug, want.Slug)
	}
	if got.Name != want.Name {
		t.Errorf("Name: got %q, want %q", got.Name, want.Name)
	}
	if got.State != want.State {
		t.Errorf("State: got %q, want %q", got.State, want.State)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetByID_NotFound(t *testing.T) {
	s, mock := newTestTenantStore(t)

	id := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	mock.ExpectQuery(regexp.QuoteMeta(sqlGetByID)).
		WithArgs(id).
		WillReturnRows(emptyTenantRows())

	_, err := s.GetByID(context.Background(), id)
	if err == nil {
		t.Fatal("GetByID: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID: error = %v, want errors.Is(ErrNotFound)", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetByID_DBError(t *testing.T) {
	s, mock := newTestTenantStore(t)

	id := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	dbErr := errors.New("unexpected EOF")
	mock.ExpectQuery(regexp.QuoteMeta(sqlGetByID)).
		WithArgs(id).
		WillReturnError(dbErr)

	_, err := s.GetByID(context.Background(), id)
	if err == nil {
		t.Fatal("GetByID: expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("GetByID: DB error should NOT be wrapped as ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("GetByID: error = %v, want to wrap %v", err, dbErr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestStore_Create_Success(t *testing.T) {
	s, mock := newTestTenantStore(t)

	returned := &Tenant{
		ID:    uuid.MustParse("55555555-5555-5555-5555-555555555555"),
		Slug:  "gamma",
		Name:  "Gamma LLC",
		State: StateActive,
	}

	mock.ExpectQuery(regexp.QuoteMeta(sqlCreate)).
		WithArgs("gamma", "Gamma LLC").
		WillReturnRows(tenantRow(returned))

	got, err := s.Create(context.Background(), "gamma", "Gamma LLC")
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("Create: returned nil tenant")
	}
	if got.ID != returned.ID {
		t.Errorf("ID: got %s, want %s", got.ID, returned.ID)
	}
	if got.Slug != returned.Slug {
		t.Errorf("Slug: got %q, want %q", got.Slug, returned.Slug)
	}
	if got.Name != returned.Name {
		t.Errorf("Name: got %q, want %q", got.Name, returned.Name)
	}
	if got.State != returned.State {
		t.Errorf("State: got %q, want %q", got.State, returned.State)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Create_DBError(t *testing.T) {
	s, mock := newTestTenantStore(t)

	dbErr := errors.New("unique constraint violation")
	mock.ExpectQuery(regexp.QuoteMeta(sqlCreate)).
		WithArgs("duplicate", "Duplicate Tenant").
		WillReturnError(dbErr)

	_, err := s.Create(context.Background(), "duplicate", "Duplicate Tenant")
	if err == nil {
		t.Fatal("Create: expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("Create: error = %v, want to wrap %v", err, dbErr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UpdateState
// ---------------------------------------------------------------------------

func TestStore_UpdateState_Success(t *testing.T) {
	s, mock := newTestTenantStore(t)

	id := uuid.MustParse("66666666-6666-6666-6666-666666666666")

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateState)).
		WithArgs(id, string(StateInactive)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.UpdateState(context.Background(), id, string(StateInactive))
	if err != nil {
		t.Fatalf("UpdateState: unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_UpdateState_NotFound(t *testing.T) {
	s, mock := newTestTenantStore(t)

	id := uuid.MustParse("77777777-7777-7777-7777-777777777777")

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateState)).
		WithArgs(id, string(StateSuspended)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := s.UpdateState(context.Background(), id, string(StateSuspended))
	if err == nil {
		t.Fatal("UpdateState: expected error for 0 rows affected, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateState: error = %v, want errors.Is(ErrNotFound)", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_UpdateState_DBError(t *testing.T) {
	s, mock := newTestTenantStore(t)

	id := uuid.MustParse("88888888-8888-8888-8888-888888888888")
	dbErr := errors.New("transaction aborted")

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateState)).
		WithArgs(id, string(StateActive)).
		WillReturnError(dbErr)

	err := s.UpdateState(context.Background(), id, string(StateActive))
	if err == nil {
		t.Fatal("UpdateState: expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateState: DB error should NOT be wrapped as ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("UpdateState: error = %v, want to wrap %v", err, dbErr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

func TestStore_List_SuccessMultipleRows(t *testing.T) {
	s, mock := newTestTenantStore(t)

	t1 := &Tenant{
		ID:    uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		Slug:  "alpha",
		Name:  "Alpha Corp",
		State: StateActive,
	}
	t2 := &Tenant{
		ID:    uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
		Slug:  "beta",
		Name:  "Beta Corp",
		State: StateInactive,
	}

	rows := pgxmock.NewRows([]string{"id", "slug", "name", "state"}).
		AddRow(t1.ID, t1.Slug, t1.Name, t1.State).
		AddRow(t2.ID, t2.Slug, t2.Name, t2.State)

	mock.ExpectQuery(regexp.QuoteMeta(sqlList)).
		WillReturnRows(rows)

	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List: got %d tenants, want 2", len(got))
	}

	// Validate first tenant.
	if got[0].ID != t1.ID {
		t.Errorf("List[0].ID: got %s, want %s", got[0].ID, t1.ID)
	}
	if got[0].Slug != t1.Slug {
		t.Errorf("List[0].Slug: got %q, want %q", got[0].Slug, t1.Slug)
	}
	if got[0].Name != t1.Name {
		t.Errorf("List[0].Name: got %q, want %q", got[0].Name, t1.Name)
	}
	if got[0].State != t1.State {
		t.Errorf("List[0].State: got %q, want %q", got[0].State, t1.State)
	}

	// Validate second tenant.
	if got[1].ID != t2.ID {
		t.Errorf("List[1].ID: got %s, want %s", got[1].ID, t2.ID)
	}
	if got[1].Slug != t2.Slug {
		t.Errorf("List[1].Slug: got %q, want %q", got[1].Slug, t2.Slug)
	}
	if got[1].State != t2.State {
		t.Errorf("List[1].State: got %q, want %q", got[1].State, t2.State)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_List_EmptyResult(t *testing.T) {
	s, mock := newTestTenantStore(t)

	mock.ExpectQuery(regexp.QuoteMeta(sqlList)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "slug", "name", "state"}))

	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	// Store returns nil slice when no rows; both nil and empty slice are acceptable.
	if len(got) != 0 {
		t.Errorf("List: got %d tenants, want 0", len(got))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_List_DBError(t *testing.T) {
	s, mock := newTestTenantStore(t)

	dbErr := errors.New("network timeout")
	mock.ExpectQuery(regexp.QuoteMeta(sqlList)).
		WillReturnError(dbErr)

	_, err := s.List(context.Background())
	if err == nil {
		t.Fatal("List: expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("List: error = %v, want to wrap %v", err, dbErr)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_List_ScanError(t *testing.T) {
	s, mock := newTestTenantStore(t)

	// Provide a row where the first column is an incompatible type (int instead
	// of uuid.UUID) so that Scan fails mid-iteration.
	rows := pgxmock.NewRows([]string{"id", "slug", "name", "state"}).
		AddRow(42 /* bad type */, "bad-slug", "Bad Tenant", string(StateActive))

	mock.ExpectQuery(regexp.QuoteMeta(sqlList)).
		WillReturnRows(rows)

	_, err := s.List(context.Background())
	if err == nil {
		t.Fatal("List: expected scan error, got nil")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// scanTenant — edge cases
// ---------------------------------------------------------------------------

// TestScanTenant_ErrNoRows validates that scanTenant propagates pgx.ErrNoRows
// unchanged so that GetBySlug / GetByID can wrap it as ErrNotFound.
func TestScanTenant_ErrNoRows(t *testing.T) {
	_, err := scanTenant(errRowScanner{err: pgx.ErrNoRows})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("scanTenant: error = %v, want pgx.ErrNoRows", err)
	}
}

// TestScanTenant_ArbitraryError validates that arbitrary scan errors bubble up.
func TestScanTenant_ArbitraryError(t *testing.T) {
	sentinel := errors.New("some scan failure")
	_, err := scanTenant(errRowScanner{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Errorf("scanTenant: error = %v, want sentinel", err)
	}
}

// errRowScanner is a minimal scanner that always returns the given error.
type errRowScanner struct{ err error }

func (e errRowScanner) Scan(_ ...any) error { return e.err }
