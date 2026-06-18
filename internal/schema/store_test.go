package schema

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/enterprise-idp/idpd/internal/dbutil"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgxmock "github.com/pashagolub/pgxmock/v4"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const getActiveSQL = `
			SELECT id, tenant_id, version, schema, is_active
			FROM identity_schemas
			WHERE tenant_id = $1 AND is_active = true
			ORDER BY version DESC
			LIMIT 1
		`

const insertDefaultSQL = `
			INSERT INTO identity_schemas (tenant_id, version, schema, is_active)
			VALUES ($1, 1, $2, true)
			RETURNING id, tenant_id, version, schema, is_active
		`

func newTestSchemaStore(t *testing.T) (*Store, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	s := &Store{pool: mock.(dbutil.Querier)}
	return s, mock
}

func schemaColumns() []string {
	return []string{"id", "tenant_id", "version", "schema", "is_active"}
}

// ---------------------------------------------------------------------------
// GetActive tests
// ---------------------------------------------------------------------------

func TestGetActive_Success(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()
	schemaID := uuid.New()
	schemaBytes := []byte(`{"type":"object"}`)

	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(
			pgxmock.NewRows(schemaColumns()).
				AddRow(schemaID, tenantID, 3, schemaBytes, true),
		)

	got, err := s.GetActive(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != schemaID {
		t.Errorf("ID: want %v, got %v", schemaID, got.ID)
	}
	if got.TenantID != tenantID {
		t.Errorf("TenantID: want %v, got %v", tenantID, got.TenantID)
	}
	if got.Version != 3 {
		t.Errorf("Version: want 3, got %d", got.Version)
	}
	if string(got.Schema) != string(schemaBytes) {
		t.Errorf("Schema: want %s, got %s", schemaBytes, got.Schema)
	}
	if !got.IsActive {
		t.Error("IsActive: want true, got false")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGetActive_NotFound(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()

	// Empty rows causes Scan to return pgx.ErrNoRows.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(schemaColumns()))

	_, err := s.GetActive(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestGetActive_DBError(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()
	dbErr := errors.New("connection refused")

	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnError(dbErr)

	_, err := s.GetActive(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("should not be ErrNotFound for a real DB error")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EnsureDefault tests
// ---------------------------------------------------------------------------

func TestEnsureDefault_FoundOnFirstGetActive(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()
	schemaID := uuid.New()
	schemaBytes := []byte(`{"type":"object","properties":{"email":{}}}`)

	// GetActive returns an existing schema — no insert should happen.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(
			pgxmock.NewRows(schemaColumns()).
				AddRow(schemaID, tenantID, 1, schemaBytes, true),
		)

	got, err := s.EnsureDefault(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != schemaID {
		t.Errorf("ID: want %v, got %v", schemaID, got.ID)
	}
	if got.TenantID != tenantID {
		t.Errorf("TenantID: want %v, got %v", tenantID, got.TenantID)
	}
	if got.Version != 1 {
		t.Errorf("Version: want 1, got %d", got.Version)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestEnsureDefault_NotFound_InsertSucceeds(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()
	newSchemaID := uuid.New()
	insertedBytes := []byte(`{"$schema":"http://json-schema.org/draft-07/schema#"}`)

	// First GetActive: no rows → ErrNotFound.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(schemaColumns()))

	// INSERT returns the newly-created row.
	mock.ExpectQuery(regexp.QuoteMeta(insertDefaultSQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnRows(
			pgxmock.NewRows(schemaColumns()).
				AddRow(newSchemaID, tenantID, 1, insertedBytes, true),
		)

	got, err := s.EnsureDefault(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != newSchemaID {
		t.Errorf("ID: want %v, got %v", newSchemaID, got.ID)
	}
	if got.TenantID != tenantID {
		t.Errorf("TenantID: want %v, got %v", tenantID, got.TenantID)
	}
	if got.Version != 1 {
		t.Errorf("Version: want 1, got %d", got.Version)
	}
	if !got.IsActive {
		t.Error("IsActive: want true, got false")
	}
	if string(got.Schema) != string(insertedBytes) {
		t.Errorf("Schema: want %s, got %s", insertedBytes, got.Schema)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestEnsureDefault_NotFound_InsertFails_SecondGetActiveSucceeds(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()
	racedSchemaID := uuid.New()
	racedBytes := []byte(`{"type":"object"}`)
	insertErr := errors.New("unique constraint violation")

	// First GetActive: not found.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(schemaColumns()))

	// INSERT fails (concurrent insert from another request).
	mock.ExpectQuery(regexp.QuoteMeta(insertDefaultSQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnError(insertErr)

	// Second GetActive (race recovery): finds the row the concurrent request inserted.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(
			pgxmock.NewRows(schemaColumns()).
				AddRow(racedSchemaID, tenantID, 1, racedBytes, true),
		)

	got, err := s.EnsureDefault(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != racedSchemaID {
		t.Errorf("ID: want %v, got %v", racedSchemaID, got.ID)
	}
	if got.TenantID != tenantID {
		t.Errorf("TenantID: want %v, got %v", tenantID, got.TenantID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestEnsureDefault_NotFound_InsertFails_SecondGetActiveAlsoFails(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()
	insertErr := errors.New("disk full")

	// First GetActive: not found.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(schemaColumns()))

	// INSERT fails.
	mock.ExpectQuery(regexp.QuoteMeta(insertDefaultSQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnError(insertErr)

	// Second GetActive (race recovery): also fails with ErrNoRows → ErrNotFound,
	// so the function must return the original insertErr wrapped.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(schemaColumns()))

	_, err := s.EnsureDefault(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, insertErr) {
		t.Errorf("expected insertErr to be wrapped, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Ensure pgx.ErrNoRows sentinel is exercised at the Scan layer.
// This verifies the empty-rows path truly produces pgx.ErrNoRows → ErrNotFound.
// ---------------------------------------------------------------------------

func TestGetActive_NotFound_IsPgxErrNoRows(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows(schemaColumns()))

	_, err := s.GetActive(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// The raw pgx.ErrNoRows should NOT surface — only the wrapped ErrNotFound.
	if errors.Is(err, pgx.ErrNoRows) {
		t.Error("pgx.ErrNoRows should be unwrapped into ErrNotFound, not re-exported")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound in chain, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// EnsureDefault with a non-ErrNotFound error on first GetActive.
// ---------------------------------------------------------------------------

func TestEnsureDefault_FirstGetActiveDBError(t *testing.T) {
	s, mock := newTestSchemaStore(t)
	defer mock.Close()

	tenantID := uuid.New()
	dbErr := errors.New("network timeout")

	// GetActive fails with a real DB error (not ErrNoRows) — EnsureDefault
	// must propagate it immediately without attempting an insert.
	mock.ExpectQuery(regexp.QuoteMeta(getActiveSQL)).
		WithArgs(tenantID).
		WillReturnError(dbErr)

	_, err := s.EnsureDefault(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected dbErr to be wrapped, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
