package identity

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgxmock "github.com/pashagolub/pgxmock/v4"
)

// newTestIdentityStore creates a Store backed by a pgxmock pool and returns
// both so callers can set up expectations and verify them.
func newTestIdentityStore(t *testing.T) (*Store, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	s := &Store{pool: mock}
	return s, mock
}

// ---- helpers ----------------------------------------------------------------

var (
	testTenantID   = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	testIdentityID = uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	testSchemaID   = uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	testCredID     = uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")

	testCredType    = "password"
	testIdentifier  = "user@example.com"
	testIdentifiers = []string{"user@example.com"}
	testConfig      = json.RawMessage(`{"hashed_password":"$2a$12$x"}`)
	testTraits      = json.RawMessage(`{"email":"test@example.com"}`)
)

// credentialColumns lists the columns returned by credential SELECT/INSERT queries.
var credentialColumns = []string{"id", "tenant_id", "identity_id", "type", "identifiers", "config"}

// identityColumns lists the columns returned by identity SELECT/INSERT queries.
var identityColumns = []string{"id", "tenant_id", "schema_id", "traits", "state"}

// configBytes is the raw JSON bytes that the DB returns for config.
var configBytes = []byte(`{"hashed_password":"$2a$12$x"}`)

// traitsBytes is the raw JSON bytes that the DB returns for traits.
var traitsBytes = []byte(`{"email":"test@example.com"}`)

// ---- GetByIdentifier --------------------------------------------------------

func TestGetByIdentifier_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, identity_id, type, identifiers, config
			FROM identity_credentials
			WHERE tenant_id = $1 AND type = $2 AND $3 = ANY(identifiers)
			LIMIT 1
		`)).
		WithArgs(testTenantID, testCredType, testIdentifier).
		WillReturnRows(
			pgxmock.NewRows(credentialColumns).
				AddRow(testCredID, testTenantID, testIdentityID, testCredType, testIdentifiers, configBytes),
		)

	cred, err := s.GetByIdentifier(context.Background(), testTenantID, testCredType, testIdentifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.ID != testCredID {
		t.Errorf("ID: got %s, want %s", cred.ID, testCredID)
	}
	if cred.TenantID != testTenantID {
		t.Errorf("TenantID: got %s, want %s", cred.TenantID, testTenantID)
	}
	if cred.IdentityID != testIdentityID {
		t.Errorf("IdentityID: got %s, want %s", cred.IdentityID, testIdentityID)
	}
	if cred.Type != testCredType {
		t.Errorf("Type: got %s, want %s", cred.Type, testCredType)
	}
	if len(cred.Identifiers) != 1 || cred.Identifiers[0] != testIdentifier {
		t.Errorf("Identifiers: got %v, want %v", cred.Identifiers, testIdentifiers)
	}
	if string(cred.Config) != string(testConfig) {
		t.Errorf("Config: got %s, want %s", cred.Config, testConfig)
	}
}

func TestGetByIdentifier_NotFound(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, identity_id, type, identifiers, config
			FROM identity_credentials
			WHERE tenant_id = $1 AND type = $2 AND $3 = ANY(identifiers)
			LIMIT 1
		`)).
		WithArgs(testTenantID, testCredType, testIdentifier).
		WillReturnRows(pgxmock.NewRows(credentialColumns))

	_, err := s.GetByIdentifier(context.Background(), testTenantID, testCredType, testIdentifier)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetByIdentifier_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("connection refused")
	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, identity_id, type, identifiers, config
			FROM identity_credentials
			WHERE tenant_id = $1 AND type = $2 AND $3 = ANY(identifiers)
			LIMIT 1
		`)).
		WithArgs(testTenantID, testCredType, testIdentifier).
		WillReturnError(dbErr)

	_, err := s.GetByIdentifier(context.Background(), testTenantID, testCredType, testIdentifier)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("expected a DB error, not ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// ---- GetByIdentityAndType ---------------------------------------------------

func TestGetByIdentityAndType_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, identity_id, type, identifiers, config
			FROM identity_credentials
			WHERE tenant_id = $1 AND identity_id = $2 AND type = $3
			LIMIT 1
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType).
		WillReturnRows(
			pgxmock.NewRows(credentialColumns).
				AddRow(testCredID, testTenantID, testIdentityID, testCredType, testIdentifiers, configBytes),
		)

	cred, err := s.GetByIdentityAndType(context.Background(), testTenantID, testIdentityID, testCredType)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.ID != testCredID {
		t.Errorf("ID: got %s, want %s", cred.ID, testCredID)
	}
	if cred.IdentityID != testIdentityID {
		t.Errorf("IdentityID: got %s, want %s", cred.IdentityID, testIdentityID)
	}
	if cred.Type != testCredType {
		t.Errorf("Type: got %s, want %s", cred.Type, testCredType)
	}
}

func TestGetByIdentityAndType_NotFound(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, identity_id, type, identifiers, config
			FROM identity_credentials
			WHERE tenant_id = $1 AND identity_id = $2 AND type = $3
			LIMIT 1
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType).
		WillReturnRows(pgxmock.NewRows(credentialColumns))

	_, err := s.GetByIdentityAndType(context.Background(), testTenantID, testIdentityID, testCredType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetByIdentityAndType_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("timeout")
	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, identity_id, type, identifiers, config
			FROM identity_credentials
			WHERE tenant_id = $1 AND identity_id = $2 AND type = $3
			LIMIT 1
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType).
		WillReturnError(dbErr)

	_, err := s.GetByIdentityAndType(context.Background(), testTenantID, testIdentityID, testCredType)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("expected a DB error, not ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// ---- CreateCredential -------------------------------------------------------

func TestCreateCredential_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, identity_id, type, identifiers, config
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(
			pgxmock.NewRows(credentialColumns).
				AddRow(testCredID, testTenantID, testIdentityID, testCredType, testIdentifiers, configBytes),
		)

	cred, err := s.CreateCredential(context.Background(), testTenantID, testIdentityID, testCredType, testIdentifiers, testConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.ID != testCredID {
		t.Errorf("ID: got %s, want %s", cred.ID, testCredID)
	}
	if cred.Type != testCredType {
		t.Errorf("Type: got %s, want %s", cred.Type, testCredType)
	}
	if len(cred.Identifiers) != 1 || cred.Identifiers[0] != testIdentifier {
		t.Errorf("Identifiers: got %v, want %v", cred.Identifiers, testIdentifiers)
	}
	if string(cred.Config) != string(testConfig) {
		t.Errorf("Config: got %s, want %s", cred.Config, testConfig)
	}
}

func TestCreateCredential_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("unique violation")
	mock.ExpectQuery(regexp.QuoteMeta(`
			INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, identity_id, type, identifiers, config
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(dbErr)

	_, err := s.CreateCredential(context.Background(), testTenantID, testIdentityID, testCredType, testIdentifiers, testConfig)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// CreateCredential does not have a "not found" path since it's an INSERT.
// The DB error test covers constraint violation scenarios.

// ---- CreateIdentity ---------------------------------------------------------

func TestCreateIdentity_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	newID := uuid.MustParse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")

	mock.ExpectQuery(regexp.QuoteMeta(`
			INSERT INTO identities (tenant_id, schema_id, traits, state)
			VALUES ($1, $2, $3, $4)
			RETURNING id, tenant_id, schema_id, traits, state
		`)).
		WithArgs(testTenantID, testSchemaID, pgxmock.AnyArg(), StateActive).
		WillReturnRows(
			pgxmock.NewRows(identityColumns).
				AddRow(newID, testTenantID, testSchemaID, traitsBytes, StateActive),
		)

	ident, err := s.CreateIdentity(context.Background(), testTenantID, testSchemaID, testTraits, StateActive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ident.ID != newID {
		t.Errorf("ID: got %s, want %s", ident.ID, newID)
	}
	if ident.TenantID != testTenantID {
		t.Errorf("TenantID: got %s, want %s", ident.TenantID, testTenantID)
	}
	if ident.SchemaID != testSchemaID {
		t.Errorf("SchemaID: got %s, want %s", ident.SchemaID, testSchemaID)
	}
	if ident.State != StateActive {
		t.Errorf("State: got %s, want %s", ident.State, StateActive)
	}
	if string(ident.Traits) != string(testTraits) {
		t.Errorf("Traits: got %s, want %s", ident.Traits, testTraits)
	}
}

func TestCreateIdentity_PendingVerificationState(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	newID := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")

	mock.ExpectQuery(regexp.QuoteMeta(`
			INSERT INTO identities (tenant_id, schema_id, traits, state)
			VALUES ($1, $2, $3, $4)
			RETURNING id, tenant_id, schema_id, traits, state
		`)).
		WithArgs(testTenantID, testSchemaID, pgxmock.AnyArg(), StatePendingVerification).
		WillReturnRows(
			pgxmock.NewRows(identityColumns).
				AddRow(newID, testTenantID, testSchemaID, traitsBytes, StatePendingVerification),
		)

	ident, err := s.CreateIdentity(context.Background(), testTenantID, testSchemaID, testTraits, StatePendingVerification)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ident.State != StatePendingVerification {
		t.Errorf("State: got %s, want %s", ident.State, StatePendingVerification)
	}
}

func TestCreateIdentity_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("foreign key violation")
	mock.ExpectQuery(regexp.QuoteMeta(`
			INSERT INTO identities (tenant_id, schema_id, traits, state)
			VALUES ($1, $2, $3, $4)
			RETURNING id, tenant_id, schema_id, traits, state
		`)).
		WithArgs(testTenantID, testSchemaID, pgxmock.AnyArg(), StateActive).
		WillReturnError(dbErr)

	_, err := s.CreateIdentity(context.Background(), testTenantID, testSchemaID, testTraits, StateActive)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// ---- GetIdentity ------------------------------------------------------------

func TestGetIdentity_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, schema_id, traits, state
			FROM identities
			WHERE tenant_id = $1 AND id = $2
		`)).
		WithArgs(testTenantID, testIdentityID).
		WillReturnRows(
			pgxmock.NewRows(identityColumns).
				AddRow(testIdentityID, testTenantID, testSchemaID, traitsBytes, StateActive),
		)

	ident, err := s.GetIdentity(context.Background(), testTenantID, testIdentityID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ident.ID != testIdentityID {
		t.Errorf("ID: got %s, want %s", ident.ID, testIdentityID)
	}
	if ident.TenantID != testTenantID {
		t.Errorf("TenantID: got %s, want %s", ident.TenantID, testTenantID)
	}
	if ident.SchemaID != testSchemaID {
		t.Errorf("SchemaID: got %s, want %s", ident.SchemaID, testSchemaID)
	}
	if ident.State != StateActive {
		t.Errorf("State: got %s, want %s", ident.State, StateActive)
	}
	if string(ident.Traits) != string(testTraits) {
		t.Errorf("Traits: got %s, want %s", ident.Traits, testTraits)
	}
}

func TestGetIdentity_NotFound(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, schema_id, traits, state
			FROM identities
			WHERE tenant_id = $1 AND id = $2
		`)).
		WithArgs(testTenantID, testIdentityID).
		WillReturnRows(pgxmock.NewRows(identityColumns))

	_, err := s.GetIdentity(context.Background(), testTenantID, testIdentityID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetIdentity_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("network error")
	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT id, tenant_id, schema_id, traits, state
			FROM identities
			WHERE tenant_id = $1 AND id = $2
		`)).
		WithArgs(testTenantID, testIdentityID).
		WillReturnError(dbErr)

	_, err := s.GetIdentity(context.Background(), testTenantID, testIdentityID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("expected a DB error, not ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// ---- UpdateIdentityState ----------------------------------------------------

func TestUpdateIdentityState_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE identities SET state = $3 WHERE tenant_id = $1 AND id = $2`,
	)).
		WithArgs(testTenantID, testIdentityID, StateActive).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.UpdateIdentityState(context.Background(), testTenantID, testIdentityID, StateActive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateIdentityState_NotFound(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE identities SET state = $3 WHERE tenant_id = $1 AND id = $2`,
	)).
		WithArgs(testTenantID, testIdentityID, StateActive).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := s.UpdateIdentityState(context.Background(), testTenantID, testIdentityID, StateActive)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateIdentityState_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("db write error")
	mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE identities SET state = $3 WHERE tenant_id = $1 AND id = $2`,
	)).
		WithArgs(testTenantID, testIdentityID, StateActive).
		WillReturnError(dbErr)

	err := s.UpdateIdentityState(context.Background(), testTenantID, testIdentityID, StateActive)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("expected a DB error, not ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// ---- GetIdentityIDByIdentifier ----------------------------------------------

func TestGetIdentityIDByIdentifier_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT identity_id FROM identity_credentials
			WHERE tenant_id = $1 AND $2 = ANY(identifiers)
			LIMIT 1
		`)).
		WithArgs(testTenantID, testIdentifier).
		WillReturnRows(
			pgxmock.NewRows([]string{"identity_id"}).
				AddRow(testIdentityID),
		)

	got, err := s.GetIdentityIDByIdentifier(context.Background(), testTenantID, testIdentifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testIdentityID {
		t.Errorf("identity_id: got %s, want %s", got, testIdentityID)
	}
}

func TestGetIdentityIDByIdentifier_NotFound(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT identity_id FROM identity_credentials
			WHERE tenant_id = $1 AND $2 = ANY(identifiers)
			LIMIT 1
		`)).
		WithArgs(testTenantID, testIdentifier).
		WillReturnRows(pgxmock.NewRows([]string{"identity_id"}))

	got, err := s.GetIdentityIDByIdentifier(context.Background(), testTenantID, testIdentifier)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
	if got != uuid.Nil {
		t.Errorf("expected uuid.Nil on not-found, got %s", got)
	}
}

func TestGetIdentityIDByIdentifier_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("context deadline exceeded")
	mock.ExpectQuery(regexp.QuoteMeta(`
			SELECT identity_id FROM identity_credentials
			WHERE tenant_id = $1 AND $2 = ANY(identifiers)
			LIMIT 1
		`)).
		WithArgs(testTenantID, testIdentifier).
		WillReturnError(dbErr)

	got, err := s.GetIdentityIDByIdentifier(context.Background(), testTenantID, testIdentifier)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("expected a DB error, not ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
	if got != uuid.Nil {
		t.Errorf("expected uuid.Nil on DB error, got %s", got)
	}
}

// ---- UpdateTraits -----------------------------------------------------------

func TestUpdateTraits_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE identities SET traits = $3 WHERE tenant_id = $1 AND id = $2`,
	)).
		WithArgs(testTenantID, testIdentityID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.UpdateTraits(context.Background(), testTenantID, testIdentityID, testTraits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateTraits_NotFound(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE identities SET traits = $3 WHERE tenant_id = $1 AND id = $2`,
	)).
		WithArgs(testTenantID, testIdentityID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := s.UpdateTraits(context.Background(), testTenantID, testIdentityID, testTraits)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestUpdateTraits_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("serialization failure")
	mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE identities SET traits = $3 WHERE tenant_id = $1 AND id = $2`,
	)).
		WithArgs(testTenantID, testIdentityID, pgxmock.AnyArg()).
		WillReturnError(dbErr)

	err := s.UpdateTraits(context.Background(), testTenantID, testIdentityID, testTraits)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("expected a DB error, not ErrNotFound")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// ---- UpsertCredential -------------------------------------------------------

func TestUpsertCredential_Success(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	mock.ExpectExec(regexp.QuoteMeta(`
			INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, type, identifiers) DO UPDATE
			  SET config = EXCLUDED.config,
			      identifiers = EXCLUDED.identifiers
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := s.UpsertCredential(context.Background(), testTenantID, testIdentityID, testCredType, testIdentifiers, testConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpsertCredential_UpdatePath(t *testing.T) {
	// When ON CONFLICT triggers the DO UPDATE branch, the command tag is still
	// returned without error. Simulate it by returning 1 row affected as well.
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	updatedConfig := json.RawMessage(`{"hashed_password":"$2a$12$new"}`)

	mock.ExpectExec(regexp.QuoteMeta(`
			INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, type, identifiers) DO UPDATE
			  SET config = EXCLUDED.config,
			      identifiers = EXCLUDED.identifiers
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := s.UpsertCredential(context.Background(), testTenantID, testIdentityID, testCredType, testIdentifiers, updatedConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpsertCredential_DBError(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	defer func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %v", err)
		}
	}()

	dbErr := errors.New("constraint violation")
	mock.ExpectExec(regexp.QuoteMeta(`
			INSERT INTO identity_credentials (tenant_id, identity_id, type, identifiers, config)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, type, identifiers) DO UPDATE
			  SET config = EXCLUDED.config,
			      identifiers = EXCLUDED.identifiers
		`)).
		WithArgs(testTenantID, testIdentityID, testCredType, pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnError(dbErr)

	err := s.UpsertCredential(context.Background(), testTenantID, testIdentityID, testCredType, testIdentifiers, testConfig)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

// ---- ErrNotFound sentinel behaviour ----------------------------------------

// TestErrNotFoundIsDistinct verifies that ErrNotFound is never accidentally
// equal to pgx.ErrNoRows, ensuring the store correctly wraps and translates.
func TestErrNotFoundIsDistinct(t *testing.T) {
	if errors.Is(ErrNotFound, pgx.ErrNoRows) {
		t.Error("ErrNotFound must NOT be pgx.ErrNoRows; it is a domain-level sentinel")
	}
}

// ---- newTestIdentityStore sanity -------------------------------------------

func TestNewTestIdentityStore_HelperWorks(t *testing.T) {
	s, mock := newTestIdentityStore(t)
	if s == nil {
		t.Fatal("store must not be nil")
	}
	if mock == nil {
		t.Fatal("mock must not be nil")
	}
	// No expectations set; verify passes trivially.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
