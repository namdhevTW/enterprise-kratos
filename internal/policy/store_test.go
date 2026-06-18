package policy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/enterprise-idp/idpd/internal/dbutil"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgxmock "github.com/pashagolub/pgxmock/v4"
)

// newTestPolicyStore creates a pgxmock pool and wires it into a Store.
// The caller is responsible for calling mock.ExpectationsWereMet() after each sub-test.
func newTestPolicyStore(t *testing.T) (*Store, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	// PgxPoolIface satisfies dbutil.Querier (QueryRow / Query / Exec).
	s := &Store{pool: mock.(dbutil.Querier)}
	return s, mock
}

// selectPolicySQL is the exact SQL used by Get.
const selectPolicySQL = `SELECT policy FROM tenant_flow_policies WHERE tenant_id = $1`

// upsertPolicySQL is the exact SQL used by Upsert (trimmed to match literal matching).
const upsertPolicySQL = `
			INSERT INTO tenant_flow_policies (tenant_id, policy)
			VALUES ($1, $2)
			ON CONFLICT (tenant_id) DO UPDATE SET policy = EXCLUDED.policy
		`

// ---- Get tests ---------------------------------------------------------------

// TestStoreGet_NoRow verifies that Get returns Default() (with no error) when
// the tenant has no row in tenant_flow_policies.
func TestStoreGet_NoRow(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()

	// Return empty rows — Scan will return pgx.ErrNoRows.
	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}))

	got, err := s.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	want := Default()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Get (no row) = %+v; want Default() = %+v", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_NoRow_AllowedFirstFactors is a more targeted assertion that the
// Default policy returned on ErrNoRows has AllowedFirstFactors == ["password"].
func TestStoreGet_NoRow_AllowedFirstFactors(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}))

	got, err := s.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	want := []string{"password"}
	if !reflect.DeepEqual(got.Login.AllowedFirstFactors, want) {
		t.Errorf("AllowedFirstFactors = %v; want %v", got.Login.AllowedFirstFactors, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_Success verifies that Get deserialises the stored JSONB bytes
// and returns the correct FlowPolicy.
func TestStoreGet_Success(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()

	// Build a non-default policy to confirm we're reading from the DB, not Default().
	stored := FlowPolicy{
		Login: LoginPolicy{
			AllowedFirstFactors:  []string{"password", "oidc"},
			AllowedSecondFactors: []string{"totp"},
			MFARequired:          true,
			SSOOnly:              false,
		},
		Registration: RegistrationPolicy{
			Enabled:             true,
			RequireVerification: true,
		},
		Session: SessionPolicy{
			TTL:               "8h",
			RequiredAAL:       "aal2",
			InactivityTimeout: "30m",
		},
		Recovery: RecoveryPolicy{
			Enabled:        true,
			AllowedMethods: []string{"link", "otp"},
		},
	}

	rawJSON, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("json.Marshal stored policy: %v", err)
	}

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}).AddRow(rawJSON))

	got, err := s.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	if !reflect.DeepEqual(*got, stored) {
		t.Errorf("Get returned\n  %+v\nwant\n  %+v", *got, stored)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_Success_LoginAllowedFirstFactors drills into the Login sub-policy
// returned from a successful Get.
func TestStoreGet_Success_LoginAllowedFirstFactors(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()

	stored := FlowPolicy{
		Login: LoginPolicy{
			AllowedFirstFactors:  []string{"password", "oidc"},
			AllowedSecondFactors: []string{"totp"},
			MFARequired:          true,
			SSOOnly:              false,
		},
	}
	rawJSON, _ := json.Marshal(stored)

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}).AddRow(rawJSON))

	got, err := s.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	wantFactors := []string{"password", "oidc"}
	if !reflect.DeepEqual(got.Login.AllowedFirstFactors, wantFactors) {
		t.Errorf("AllowedFirstFactors = %v; want %v", got.Login.AllowedFirstFactors, wantFactors)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_Success_MFARequired verifies that MFARequired is correctly
// unmarshalled from the stored JSON.
func TestStoreGet_Success_MFARequired(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()

	stored := FlowPolicy{
		Login: LoginPolicy{
			AllowedFirstFactors:  []string{"password", "oidc"},
			AllowedSecondFactors: []string{"totp"},
			MFARequired:          true,
		},
	}
	rawJSON, _ := json.Marshal(stored)

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}).AddRow(rawJSON))

	got, err := s.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get returned unexpected error: %v", err)
	}
	if !got.Login.MFARequired {
		t.Errorf("MFARequired = false; want true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_DBError verifies that a database-level error is propagated as
// a non-nil error from Get.
func TestStoreGet_DBError(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	dbErr := errors.New("connection reset by peer")

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnError(dbErr)

	got, err := s.Get(context.Background(), tenantID)
	if err == nil {
		t.Fatalf("Get returned nil error; want error wrapping %q", dbErr)
	}
	if got != nil {
		t.Errorf("Get returned non-nil policy on error: %+v", got)
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("err = %v; want errors.Is(err, %v) == true", err, dbErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_DBError_ContainsTenantID verifies that the error message
// includes the tenant ID for easier debugging.
func TestStoreGet_DBError_ContainsTenantID(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnError(errors.New("timeout"))

	_, err := s.Get(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), tenantID.String()) {
		t.Errorf("error %q does not contain tenant ID %q", err.Error(), tenantID.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_NotPgxErrNoRows verifies that a non-pgx.ErrNoRows error is NOT
// silently treated as the Default policy.
func TestStoreGet_NotPgxErrNoRows(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	someOtherErr := errors.New("some other error")

	// Ensure someOtherErr is distinct from pgx.ErrNoRows.
	if errors.Is(someOtherErr, pgx.ErrNoRows) {
		t.Fatal("test setup: someOtherErr must not be pgx.ErrNoRows")
	}

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnError(someOtherErr)

	got, err := s.Get(context.Background(), tenantID)
	if err == nil {
		t.Fatal("Get returned nil error; want non-nil error")
	}
	if reflect.DeepEqual(got, Default()) {
		t.Error("Get silently returned Default() for a non-ErrNoRows error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_InvalidJSON verifies that Get returns a decode error when the
// stored JSONB is not valid JSON.
func TestStoreGet_InvalidJSON(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	badJSON := []byte("{this is not valid json!!!}")

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}).AddRow(badJSON))

	got, err := s.Get(context.Background(), tenantID)
	if err == nil {
		t.Fatalf("Get returned nil error on invalid JSON; got policy: %+v", got)
	}
	if got != nil {
		t.Errorf("Get returned non-nil policy on decode error: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreGet_InvalidJSON_ContainsTenantID checks that the decode error
// message references the tenant for observability.
func TestStoreGet_InvalidJSON_ContainsTenantID(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	badJSON := []byte("not-json")

	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}).AddRow(badJSON))

	_, err := s.Get(context.Background(), tenantID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), tenantID.String()) {
		t.Errorf("error %q does not contain tenant ID %q", err.Error(), tenantID.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---- Upsert tests ------------------------------------------------------------

// TestStoreUpsert_Success verifies that a successful Exec returns nil.
func TestStoreUpsert_Success(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	p := Default()

	// The policy bytes are JSON-marshalled inside Upsert; we can't predict the
	// exact byte slice ordering, so use AnyArg() for the second parameter.
	mock.ExpectExec(regexp.QuoteMeta(upsertPolicySQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	err := s.Upsert(context.Background(), tenantID, p)
	if err != nil {
		t.Fatalf("Upsert returned unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreUpsert_Success_NilError is a targeted check that the return value
// is exactly nil (not an error interface wrapping nil).
func TestStoreUpsert_Success_NilError(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	p := &FlowPolicy{
		Login: LoginPolicy{
			AllowedFirstFactors:  []string{"password", "oidc"},
			AllowedSecondFactors: []string{"totp"},
			MFARequired:          true,
		},
		Registration: RegistrationPolicy{Enabled: true},
		Session:      SessionPolicy{TTL: "12h", RequiredAAL: "aal1", InactivityTimeout: "2h"},
		Recovery:     RecoveryPolicy{Enabled: false},
	}

	mock.ExpectExec(regexp.QuoteMeta(upsertPolicySQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	if err := s.Upsert(context.Background(), tenantID, p); err != nil {
		t.Errorf("Upsert = %v; want nil", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreUpsert_UpdateConflict verifies Upsert also works when the result
// tag is UPDATE (ON CONFLICT branch was taken).
func TestStoreUpsert_UpdateConflict(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	p := Default()

	mock.ExpectExec(regexp.QuoteMeta(upsertPolicySQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.Upsert(context.Background(), tenantID, p)
	if err != nil {
		t.Fatalf("Upsert (UPDATE path) returned unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreUpsert_DBError verifies that a DB-level error from Exec is wrapped
// and returned by Upsert.
func TestStoreUpsert_DBError(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	p := Default()
	dbErr := errors.New("network failure")

	mock.ExpectExec(regexp.QuoteMeta(upsertPolicySQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnError(dbErr)

	err := s.Upsert(context.Background(), tenantID, p)
	if err == nil {
		t.Fatalf("Upsert returned nil error; want error wrapping %q", dbErr)
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("err = %v; want errors.Is(err, %v) == true", err, dbErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStoreUpsert_DBError_ContainsTenantID verifies that the error message
// from a DB failure includes the tenant ID.
func TestStoreUpsert_DBError_ContainsTenantID(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.MustParse("cafecafe-cafe-cafe-cafe-cafecafecafe")
	p := Default()

	mock.ExpectExec(regexp.QuoteMeta(upsertPolicySQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnError(errors.New("disk full"))

	err := s.Upsert(context.Background(), tenantID, p)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), tenantID.String()) {
		t.Errorf("error %q does not contain tenant ID %q", err.Error(), tenantID.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---- Round-trip through Store ------------------------------------------------

// TestStoreGetAfterUpsert exercises the full marshal→DB→unmarshal path using
// two sequential mock expectations: first an Upsert, then a Get that returns
// the same JSON the Upsert would have written.
func TestStoreGetAfterUpsert(t *testing.T) {
	t.Parallel()
	s, mock := newTestPolicyStore(t)

	tenantID := uuid.New()
	original := &FlowPolicy{
		Login: LoginPolicy{
			AllowedFirstFactors:  []string{"saml"},
			AllowedSecondFactors: []string{"otp"},
			MFARequired:          true,
			SSOOnly:              true,
		},
		Registration: RegistrationPolicy{Enabled: false, RequireVerification: false},
		Session:      SessionPolicy{TTL: "4h", RequiredAAL: "aal2", InactivityTimeout: "15m"},
		Recovery:     RecoveryPolicy{Enabled: true, AllowedMethods: []string{"otp"}},
	}

	rawJSON, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Expect Upsert (Exec).
	mock.ExpectExec(regexp.QuoteMeta(upsertPolicySQL)).
		WithArgs(tenantID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	// Expect Get (QueryRow).
	mock.ExpectQuery(regexp.QuoteMeta(selectPolicySQL)).
		WithArgs(tenantID).
		WillReturnRows(pgxmock.NewRows([]string{"policy"}).AddRow(rawJSON))

	if err := s.Upsert(context.Background(), tenantID, original); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := s.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(*got, *original) {
		t.Errorf("round-trip mismatch:\n  got  %+v\n  want %+v", *got, *original)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
