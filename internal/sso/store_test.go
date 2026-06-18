package sso

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

// newTestSSOStore creates a pgxmock pool and a Store wired to it.
func newTestSSOStore(t *testing.T) (*Store, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	s := &Store{pool: mock}
	return s, mock
}

// sampleConfigBytes is the raw JSON returned by the mock DB for config columns.
var sampleConfigBytes = []byte(`{"client_id":"abc"}`)

// fixed UUIDs used across store tests
var (
	storeTenantID   = uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	storeProviderID = uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	storeProvider2ID = uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
)

// ---------------------------------------------------------------------------
// Store.Create
// ---------------------------------------------------------------------------

const createSQL = `
			INSERT INTO tenant_sso_providers (tenant_id, type, provider, config)
			VALUES ($1, $2, $3, $4)
			RETURNING id, tenant_id, type, provider, config, enabled
		`

func TestStoreCreate_Success(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	rows := pgxmock.NewRows([]string{"id", "tenant_id", "type", "provider", "config", "enabled"}).
		AddRow(storeProviderID, storeTenantID, "oidc", "google", sampleConfigBytes, true)

	mock.ExpectQuery(regexp.QuoteMeta(createSQL)).
		WithArgs(storeTenantID, "oidc", "google", pgxmock.AnyArg()).
		WillReturnRows(rows)

	p, err := s.Create(context.Background(), storeTenantID, "oidc", "google", sampleConfigBytes)
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if p.ID != storeProviderID {
		t.Errorf("ID: got %s, want %s", p.ID, storeProviderID)
	}
	if p.TenantID != storeTenantID {
		t.Errorf("TenantID: got %s, want %s", p.TenantID, storeTenantID)
	}
	if p.Type != "oidc" {
		t.Errorf("Type: got %s, want oidc", p.Type)
	}
	if p.Provider != "google" {
		t.Errorf("Provider: got %s, want google", p.Provider)
	}
	if !p.Enabled {
		t.Error("Enabled: got false, want true")
	}
	if string(p.Config) != string(sampleConfigBytes) {
		t.Errorf("Config: got %s, want %s", p.Config, sampleConfigBytes)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreCreate_DBError(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectQuery(regexp.QuoteMeta(createSQL)).
		WithArgs(storeTenantID, "oidc", "google", pgxmock.AnyArg()).
		WillReturnError(errors.New("db connection lost"))

	_, err := s.Create(context.Background(), storeTenantID, "oidc", "google", sampleConfigBytes)
	if err == nil {
		t.Fatal("Create: expected error, got nil")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Store.Get
// ---------------------------------------------------------------------------

const getSQL = `
			SELECT id, tenant_id, type, provider, config, enabled
			FROM tenant_sso_providers
			WHERE tenant_id = $1 AND id = $2
		`

func TestStoreGet_Success(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	rows := pgxmock.NewRows([]string{"id", "tenant_id", "type", "provider", "config", "enabled"}).
		AddRow(storeProviderID, storeTenantID, "oidc", "google", sampleConfigBytes, true)

	mock.ExpectQuery(regexp.QuoteMeta(getSQL)).
		WithArgs(storeTenantID, storeProviderID).
		WillReturnRows(rows)

	p, err := s.Get(context.Background(), storeTenantID, storeProviderID)
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if p.ID != storeProviderID {
		t.Errorf("ID: got %s, want %s", p.ID, storeProviderID)
	}
	if p.TenantID != storeTenantID {
		t.Errorf("TenantID: got %s, want %s", p.TenantID, storeTenantID)
	}
	if p.Type != "oidc" {
		t.Errorf("Type: got %s, want oidc", p.Type)
	}
	if p.Provider != "google" {
		t.Errorf("Provider: got %s, want google", p.Provider)
	}
	if !p.Enabled {
		t.Error("Enabled: got false, want true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreGet_NotFound(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	// Empty rows causes pgx.ErrNoRows on Scan, which the store maps to ErrNotFound.
	mock.ExpectQuery(regexp.QuoteMeta(getSQL)).
		WithArgs(storeTenantID, storeProviderID).
		WillReturnRows(pgxmock.NewRows([]string{"id", "tenant_id", "type", "provider", "config", "enabled"}))

	_, err := s.Get(context.Background(), storeTenantID, storeProviderID)
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: want ErrNotFound in error chain, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreGet_DBError(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectQuery(regexp.QuoteMeta(getSQL)).
		WithArgs(storeTenantID, storeProviderID).
		WillReturnError(errors.New("network timeout"))

	_, err := s.Get(context.Background(), storeTenantID, storeProviderID)
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("Get: DB error should not be wrapped as ErrNotFound")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// Ensure pgx.ErrNoRows is explicitly handled (not classified as a generic DB error).
func TestStoreGet_NotFound_ErrNoRows(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectQuery(regexp.QuoteMeta(getSQL)).
		WithArgs(storeTenantID, storeProviderID).
		WillReturnError(pgx.ErrNoRows)

	_, err := s.Get(context.Background(), storeTenantID, storeProviderID)
	if err == nil {
		t.Fatal("Get: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: pgx.ErrNoRows must map to ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Store.List
// ---------------------------------------------------------------------------

const listSQL = `
			SELECT id, tenant_id, type, provider, config, enabled
			FROM tenant_sso_providers
			WHERE tenant_id = $1
			ORDER BY type, provider
		`

func TestStoreList_SuccessWithTwoProviders(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	rows := pgxmock.NewRows([]string{"id", "tenant_id", "type", "provider", "config", "enabled"}).
		AddRow(storeProviderID, storeTenantID, "oidc", "google", sampleConfigBytes, true).
		AddRow(storeProvider2ID, storeTenantID, "saml", "okta", sampleConfigBytes, false)

	mock.ExpectQuery(regexp.QuoteMeta(listSQL)).
		WithArgs(storeTenantID).
		WillReturnRows(rows)

	providers, err := s.List(context.Background(), storeTenantID)
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("List: got %d providers, want 2", len(providers))
	}

	if providers[0].ID != storeProviderID {
		t.Errorf("providers[0].ID: got %s, want %s", providers[0].ID, storeProviderID)
	}
	if providers[0].Type != "oidc" {
		t.Errorf("providers[0].Type: got %s, want oidc", providers[0].Type)
	}
	if providers[0].Provider != "google" {
		t.Errorf("providers[0].Provider: got %s, want google", providers[0].Provider)
	}
	if !providers[0].Enabled {
		t.Error("providers[0].Enabled: got false, want true")
	}

	if providers[1].ID != storeProvider2ID {
		t.Errorf("providers[1].ID: got %s, want %s", providers[1].ID, storeProvider2ID)
	}
	if providers[1].Type != "saml" {
		t.Errorf("providers[1].Type: got %s, want saml", providers[1].Type)
	}
	if providers[1].Provider != "okta" {
		t.Errorf("providers[1].Provider: got %s, want okta", providers[1].Provider)
	}
	if providers[1].Enabled {
		t.Error("providers[1].Enabled: got true, want false")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreList_SuccessEmptyResult(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	rows := pgxmock.NewRows([]string{"id", "tenant_id", "type", "provider", "config", "enabled"})

	mock.ExpectQuery(regexp.QuoteMeta(listSQL)).
		WithArgs(storeTenantID).
		WillReturnRows(rows)

	providers, err := s.List(context.Background(), storeTenantID)
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	// nil or empty slice — both are acceptable; just verify zero length
	if len(providers) != 0 {
		t.Errorf("List: got %d providers, want 0", len(providers))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreList_DBError(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectQuery(regexp.QuoteMeta(listSQL)).
		WithArgs(storeTenantID).
		WillReturnError(errors.New("query execution failed"))

	_, err := s.List(context.Background(), storeTenantID)
	if err == nil {
		t.Fatal("List: expected error, got nil")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Store.ListByType
// ---------------------------------------------------------------------------

const listByTypeSQL = `
			SELECT id, tenant_id, type, provider, config, enabled
			FROM tenant_sso_providers
			WHERE tenant_id = $1 AND type = $2 AND enabled = true
			ORDER BY provider
		`

func TestStoreListByType_SuccessOneProvider(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	rows := pgxmock.NewRows([]string{"id", "tenant_id", "type", "provider", "config", "enabled"}).
		AddRow(storeProviderID, storeTenantID, "oidc", "google", sampleConfigBytes, true)

	mock.ExpectQuery(regexp.QuoteMeta(listByTypeSQL)).
		WithArgs(storeTenantID, "oidc").
		WillReturnRows(rows)

	providers, err := s.ListByType(context.Background(), storeTenantID, "oidc")
	if err != nil {
		t.Fatalf("ListByType: unexpected error: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("ListByType: got %d providers, want 1", len(providers))
	}
	if providers[0].Type != "oidc" {
		t.Errorf("providers[0].Type: got %s, want oidc", providers[0].Type)
	}
	if providers[0].Provider != "google" {
		t.Errorf("providers[0].Provider: got %s, want google", providers[0].Provider)
	}
	if !providers[0].Enabled {
		t.Error("providers[0].Enabled: got false, want true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreListByType_EmptyResult(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	rows := pgxmock.NewRows([]string{"id", "tenant_id", "type", "provider", "config", "enabled"})

	mock.ExpectQuery(regexp.QuoteMeta(listByTypeSQL)).
		WithArgs(storeTenantID, "saml").
		WillReturnRows(rows)

	providers, err := s.ListByType(context.Background(), storeTenantID, "saml")
	if err != nil {
		t.Fatalf("ListByType: unexpected error: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("ListByType: got %d providers, want 0", len(providers))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreListByType_DBError(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectQuery(regexp.QuoteMeta(listByTypeSQL)).
		WithArgs(storeTenantID, "oidc").
		WillReturnError(errors.New("db unavailable"))

	_, err := s.ListByType(context.Background(), storeTenantID, "oidc")
	if err == nil {
		t.Fatal("ListByType: expected error, got nil")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Store.Delete
// ---------------------------------------------------------------------------

const deleteSQL = `DELETE FROM tenant_sso_providers WHERE tenant_id = $1 AND id = $2`

func TestStoreDelete_Success(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectExec(regexp.QuoteMeta(deleteSQL)).
		WithArgs(storeTenantID, storeProviderID).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	err := s.Delete(context.Background(), storeTenantID, storeProviderID)
	if err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreDelete_NotFound(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectExec(regexp.QuoteMeta(deleteSQL)).
		WithArgs(storeTenantID, storeProviderID).
		WillReturnResult(pgxmock.NewResult("DELETE", 0))

	err := s.Delete(context.Background(), storeTenantID, storeProviderID)
	if err == nil {
		t.Fatal("Delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete: want ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreDelete_DBError(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectExec(regexp.QuoteMeta(deleteSQL)).
		WithArgs(storeTenantID, storeProviderID).
		WillReturnError(errors.New("lock timeout"))

	err := s.Delete(context.Background(), storeTenantID, storeProviderID)
	if err == nil {
		t.Fatal("Delete: expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("Delete: DB error should not be ErrNotFound")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Store.SetEnabled
// ---------------------------------------------------------------------------

const setEnabledSQL = `UPDATE tenant_sso_providers SET enabled = $3 WHERE tenant_id = $1 AND id = $2`

func TestStoreSetEnabled_SuccessEnabled(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectExec(regexp.QuoteMeta(setEnabledSQL)).
		WithArgs(storeTenantID, storeProviderID, true).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.SetEnabled(context.Background(), storeTenantID, storeProviderID, true)
	if err != nil {
		t.Fatalf("SetEnabled(true): unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreSetEnabled_SuccessDisabled(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectExec(regexp.QuoteMeta(setEnabledSQL)).
		WithArgs(storeTenantID, storeProviderID, false).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	err := s.SetEnabled(context.Background(), storeTenantID, storeProviderID, false)
	if err != nil {
		t.Fatalf("SetEnabled(false): unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreSetEnabled_NotFound(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectExec(regexp.QuoteMeta(setEnabledSQL)).
		WithArgs(storeTenantID, storeProviderID, true).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := s.SetEnabled(context.Background(), storeTenantID, storeProviderID, true)
	if err == nil {
		t.Fatal("SetEnabled: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("SetEnabled: want ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreSetEnabled_DBError(t *testing.T) {
	s, mock := newTestSSOStore(t)
	defer mock.Close()

	mock.ExpectExec(regexp.QuoteMeta(setEnabledSQL)).
		WithArgs(storeTenantID, storeProviderID, true).
		WillReturnError(errors.New("write conflict"))

	err := s.SetEnabled(context.Background(), storeTenantID, storeProviderID, true)
	if err == nil {
		t.Fatal("SetEnabled: expected error, got nil")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("SetEnabled: DB error should not be ErrNotFound")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
