package flow

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgxmock "github.com/pashagolub/pgxmock/v4"
)

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newTestFlowStore(t *testing.T) (*Store, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock: %v", err)
	}
	return &Store{pool: mock}, mock
}

// validUIJSON is what the DB returns for the ui column.
var validUIJSON = []byte(`{"action":"","method":"POST","nodes":[]}`)

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestStore_Create_Success(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.Nil
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	ui := UI{Method: "POST", Nodes: nil}

	const sqlCreate = `
			INSERT INTO self_service_flows (tenant_id, type, state, ui, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, type, state, identity_id, ui, expires_at
		`

	mock.ExpectQuery(regexp.QuoteMeta(sqlCreate)).
		WithArgs(tenantID, string(TypeLogin), string(StatePending), pgxmock.AnyArg(), expiresAt).
		WillReturnRows(
			pgxmock.NewRows([]string{"id", "tenant_id", "type", "state", "identity_id", "ui", "expires_at"}).
				AddRow(flowID, tenantID, string(TypeLogin), string(StatePending), &identityID, validUIJSON, expiresAt),
		)

	got, err := s.Create(context.Background(), tenantID, TypeLogin, ui, expiresAt)
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("Create: expected non-nil flow")
	}
	if got.ID != flowID {
		t.Errorf("Create: ID = %v, want %v", got.ID, flowID)
	}
	if got.TenantID != tenantID {
		t.Errorf("Create: TenantID = %v, want %v", got.TenantID, tenantID)
	}
	if got.Type != TypeLogin {
		t.Errorf("Create: Type = %v, want %v", got.Type, TypeLogin)
	}
	if got.State != StatePending {
		t.Errorf("Create: State = %v, want %v", got.State, StatePending)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Create_DBError(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	expiresAt := time.Now().Add(time.Hour).UTC()
	dbErr := errors.New("connection refused")

	const sqlCreate = `
			INSERT INTO self_service_flows (tenant_id, type, state, ui, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, type, state, identity_id, ui, expires_at
		`

	mock.ExpectQuery(regexp.QuoteMeta(sqlCreate)).
		WithArgs(tenantID, string(TypeRegistration), string(StatePending), pgxmock.AnyArg(), expiresAt).
		WillReturnError(dbErr)

	got, err := s.Create(context.Background(), tenantID, TypeRegistration, UI{}, expiresAt)
	if err == nil {
		t.Fatal("Create: expected error, got nil")
	}
	if got != nil {
		t.Errorf("Create: expected nil flow on error, got %+v", got)
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("Create: error chain does not contain dbErr: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

func TestStore_Get_Success(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	const sqlGet = `
			SELECT id, tenant_id, type, state, identity_id, ui, expires_at
			FROM self_service_flows
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectQuery(regexp.QuoteMeta(sqlGet)).
		WithArgs(tenantID, flowID).
		WillReturnRows(
			pgxmock.NewRows([]string{"id", "tenant_id", "type", "state", "identity_id", "ui", "expires_at"}).
				AddRow(flowID, tenantID, string(TypeLogin), string(StatePending), nil, validUIJSON, expiresAt),
		)

	got, err := s.Get(context.Background(), tenantID, flowID)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("Get: expected non-nil flow")
	}
	if got.ID != flowID {
		t.Errorf("Get: ID = %v, want %v", got.ID, flowID)
	}
	if got.Type != TypeLogin {
		t.Errorf("Get: Type = %v, want %v", got.Type, TypeLogin)
	}
	if got.State != StatePending {
		t.Errorf("Get: State = %v, want %v", got.State, StatePending)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()

	const sqlGet = `
			SELECT id, tenant_id, type, state, identity_id, ui, expires_at
			FROM self_service_flows
			WHERE tenant_id = $1 AND id = $2
		`

	// Empty rows causes pgx to return ErrNoRows on Scan.
	mock.ExpectQuery(regexp.QuoteMeta(sqlGet)).
		WithArgs(tenantID, flowID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "type", "state", "identity_id", "ui", "expires_at"}))

	got, err := s.Get(context.Background(), tenantID, flowID)
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if got != nil {
		t.Errorf("Get: expected nil flow on not-found, got %+v", got)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: expected ErrNotFound in chain, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Get_DBError(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	dbErr := errors.New("network timeout")

	const sqlGet = `
			SELECT id, tenant_id, type, state, identity_id, ui, expires_at
			FROM self_service_flows
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectQuery(regexp.QuoteMeta(sqlGet)).
		WithArgs(tenantID, flowID).
		WillReturnError(dbErr)

	got, err := s.Get(context.Background(), tenantID, flowID)
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if got != nil {
		t.Errorf("Get: expected nil flow on error, got %+v", got)
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("Get: should not be ErrNotFound for a DB error")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		t.Error("Get: should not expose pgx.ErrNoRows directly")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Get_ExpiredFlow(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	// expiresAt in the past so the flow is expired.
	expiresAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)

	const sqlGet = `
			SELECT id, tenant_id, type, state, identity_id, ui, expires_at
			FROM self_service_flows
			WHERE tenant_id = $1 AND id = $2
		`
	const sqlUpdateState = `
			UPDATE self_service_flows
			SET state = $3
			WHERE tenant_id = $1 AND id = $2
		`

	// First: the SELECT returns a pending-but-expired flow.
	mock.ExpectQuery(regexp.QuoteMeta(sqlGet)).
		WithArgs(tenantID, flowID).
		WillReturnRows(
			pgxmock.NewRows([]string{"id", "tenant_id", "type", "state", "identity_id", "ui", "expires_at"}).
				AddRow(flowID, tenantID, string(TypeLogin), string(StatePending), nil, validUIJSON, expiresAt),
		)

	// Then Get calls UpdateState internally (best-effort, error ignored).
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateState)).
		WithArgs(tenantID, flowID, string(StateExpired)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	got, err := s.Get(context.Background(), tenantID, flowID)
	if err == nil {
		t.Fatal("Get: expected ErrExpired, got nil")
	}
	if got != nil {
		t.Errorf("Get: expected nil flow on expired, got %+v", got)
	}
	if !errors.Is(err, ErrExpired) {
		t.Errorf("Get: expected ErrExpired in chain, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStore_Get_ExpiredFlow_UpdateStateFails verifies that Get still returns
// ErrExpired even when the best-effort UpdateState call fails.
func TestStore_Get_ExpiredFlow_UpdateStateFails(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	expiresAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)

	const sqlGet = `
			SELECT id, tenant_id, type, state, identity_id, ui, expires_at
			FROM self_service_flows
			WHERE tenant_id = $1 AND id = $2
		`
	const sqlUpdateState = `
			UPDATE self_service_flows
			SET state = $3
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectQuery(regexp.QuoteMeta(sqlGet)).
		WithArgs(tenantID, flowID).
		WillReturnRows(
			pgxmock.NewRows([]string{"id", "tenant_id", "type", "state", "identity_id", "ui", "expires_at"}).
				AddRow(flowID, tenantID, string(TypeRecovery), string(StatePending), nil, validUIJSON, expiresAt),
		)

	// UpdateState fails — Get must still surface ErrExpired.
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateState)).
		WithArgs(tenantID, flowID, string(StateExpired)).
		WillReturnError(errors.New("db write error"))

	got, err := s.Get(context.Background(), tenantID, flowID)
	if err == nil {
		t.Fatal("Get: expected ErrExpired, got nil")
	}
	if got != nil {
		t.Errorf("Get: expected nil flow, got %+v", got)
	}
	if !errors.Is(err, ErrExpired) {
		t.Errorf("Get: expected ErrExpired in chain, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestStore_Update_Success(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	identityID := uuid.New()
	ui := UI{Method: "POST"}

	const sqlUpdate = `
			UPDATE self_service_flows
			SET state = $3, identity_id = $4, ui = $5
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(tenantID, flowID, string(StateSuccess), &identityID, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.Update(context.Background(), tenantID, flowID, StateSuccess, &identityID, ui)
	if err != nil {
		t.Fatalf("Update: unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Update_NotFound(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()

	const sqlUpdate = `
			UPDATE self_service_flows
			SET state = $3, identity_id = $4, ui = $5
			WHERE tenant_id = $1 AND id = $2
		`

	// 0 rows affected → ErrNotFound.
	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(tenantID, flowID, string(StateFailed), (*uuid.UUID)(nil), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := s.Update(context.Background(), tenantID, flowID, StateFailed, nil, UI{})
	if err == nil {
		t.Fatal("Update: expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Update: expected ErrNotFound in chain, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Update_DBError(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	dbErr := errors.New("constraint violation")

	const sqlUpdate = `
			UPDATE self_service_flows
			SET state = $3, identity_id = $4, ui = $5
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(tenantID, flowID, string(StateSuccess), (*uuid.UUID)(nil), pgxmock.AnyArg()).
		WillReturnError(dbErr)

	err := s.Update(context.Background(), tenantID, flowID, StateSuccess, nil, UI{})
	if err == nil {
		t.Fatal("Update: expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("Update: error chain does not contain dbErr: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UpdateState
// ---------------------------------------------------------------------------

func TestStore_UpdateState_Success(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()

	const sqlUpdateState = `
			UPDATE self_service_flows
			SET state = $3
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateState)).
		WithArgs(tenantID, flowID, string(StateExpired)).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.UpdateState(context.Background(), tenantID, flowID, StateExpired)
	if err != nil {
		t.Fatalf("UpdateState: unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_UpdateState_DBError(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	dbErr := errors.New("deadlock detected")

	const sqlUpdateState = `
			UPDATE self_service_flows
			SET state = $3
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdateState)).
		WithArgs(tenantID, flowID, string(StateFailed)).
		WillReturnError(dbErr)

	err := s.UpdateState(context.Background(), tenantID, flowID, StateFailed)
	if err == nil {
		t.Fatal("UpdateState: expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("UpdateState: error chain does not contain dbErr: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

// TestStore_Get_NonPendingExpiredFlow verifies that a flow whose state is not
// "pending" is NOT treated as expired, even if ExpiresAt is in the past.
func TestStore_Get_NonPendingExpiredFlow(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	// expiresAt in the past, but state is "success" — should not trigger ErrExpired.
	expiresAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)

	const sqlGet = `
			SELECT id, tenant_id, type, state, identity_id, ui, expires_at
			FROM self_service_flows
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectQuery(regexp.QuoteMeta(sqlGet)).
		WithArgs(tenantID, flowID).
		WillReturnRows(
			pgxmock.NewRows([]string{"id", "tenant_id", "type", "state", "identity_id", "ui", "expires_at"}).
				AddRow(flowID, tenantID, string(TypeLogin), string(StateSuccess), nil, validUIJSON, expiresAt),
		)

	got, err := s.Get(context.Background(), tenantID, flowID)
	if err != nil {
		t.Fatalf("Get: unexpected error for non-pending flow: %v", err)
	}
	if got == nil {
		t.Fatal("Get: expected non-nil flow")
	}
	if got.State != StateSuccess {
		t.Errorf("Get: State = %v, want %v", got.State, StateSuccess)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStore_Update_WithNilIdentityID verifies Update passes a nil *uuid.UUID
// correctly (e.g. when no identity has been bound to the flow yet).
func TestStore_Update_WithNilIdentityID(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()

	const sqlUpdate = `
			UPDATE self_service_flows
			SET state = $3, identity_id = $4, ui = $5
			WHERE tenant_id = $1 AND id = $2
		`

	mock.ExpectExec(regexp.QuoteMeta(sqlUpdate)).
		WithArgs(tenantID, flowID, string(StatePending), (*uuid.UUID)(nil), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.Update(context.Background(), tenantID, flowID, StatePending, nil, UI{Method: "GET"})
	if err != nil {
		t.Fatalf("Update (nil identityID): unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestStore_Create_RegistrationFlow verifies Create works for non-login flow types.
func TestStore_Create_RegistrationFlow(t *testing.T) {
	s, mock := newTestFlowStore(t)

	tenantID := uuid.New()
	flowID := uuid.New()
	expiresAt := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Microsecond)

	const sqlCreate = `
			INSERT INTO self_service_flows (tenant_id, type, state, ui, expires_at)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id, tenant_id, type, state, identity_id, ui, expires_at
		`

	mock.ExpectQuery(regexp.QuoteMeta(sqlCreate)).
		WithArgs(tenantID, string(TypeRegistration), string(StatePending), pgxmock.AnyArg(), expiresAt).
		WillReturnRows(
			pgxmock.NewRows([]string{"id", "tenant_id", "type", "state", "identity_id", "ui", "expires_at"}).
				AddRow(flowID, tenantID, string(TypeRegistration), string(StatePending), nil, validUIJSON, expiresAt),
		)

	got, err := s.Create(context.Background(), tenantID, TypeRegistration, UI{}, expiresAt)
	if err != nil {
		t.Fatalf("Create (registration): unexpected error: %v", err)
	}
	if got.Type != TypeRegistration {
		t.Errorf("Create: Type = %v, want %v", got.Type, TypeRegistration)
	}
	if got.ExpiresAt != expiresAt {
		t.Errorf("Create: ExpiresAt = %v, want %v", got.ExpiresAt, expiresAt)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
