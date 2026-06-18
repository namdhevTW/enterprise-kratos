package session

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
// helpers
// ---------------------------------------------------------------------------

func newTestSessionStore(t *testing.T) (*Store, pgxmock.PgxPoolIface) {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool: %v", err)
	}
	return &Store{pool: mock}, mock
}

// sessionColumns lists the columns returned by both INSERT RETURNING and SELECT.
var sessionColumns = []string{
	"id", "tenant_id", "identity_id", "token",
	"expires_at", "authenticator_assurance_level", "amr", "active",
}

const insertSQL = `
			INSERT INTO sessions (tenant_id, identity_id, token, expires_at, authenticator_assurance_level, amr)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, tenant_id, identity_id, token, expires_at, authenticator_assurance_level, amr, active
		`

const selectByTokenSQL = `
			SELECT id, tenant_id, identity_id, token, expires_at, authenticator_assurance_level, amr, active
			FROM sessions
			WHERE tenant_id = $1 AND token = $2
		`

const revokeByIDSQL = `UPDATE sessions SET active = false WHERE tenant_id = $1 AND id = $2`

const revokeByTokenSQL = `UPDATE sessions SET active = false WHERE tenant_id = $1 AND token = $2`

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestStore_Create_Success(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	identityID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	sessionID := uuid.MustParse("33333333-3333-3333-3333-333333333333")

	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	const returnedToken = "test-token-abc123"
	amrJSON := []byte(`["password"]`)

	mock.ExpectQuery(regexp.QuoteMeta(insertSQL)).
		WithArgs(
			tenantID,
			identityID,
			pgxmock.AnyArg(), // generated token
			pgxmock.AnyArg(), // computed expiresAt
			"aal1",
			pgxmock.AnyArg(), // marshalled AMR JSON
		).
		WillReturnRows(
			pgxmock.NewRows(sessionColumns).AddRow(
				sessionID, tenantID, identityID, returnedToken,
				expiresAt, "aal1", amrJSON, true,
			),
		)

	sess, err := s.Create(context.Background(), tenantID, identityID, "aal1", []string{"password"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create returned unexpected error: %v", err)
	}

	if sess.ID != sessionID {
		t.Errorf("expected ID %v, got %v", sessionID, sess.ID)
	}
	if sess.TenantID != tenantID {
		t.Errorf("expected TenantID %v, got %v", tenantID, sess.TenantID)
	}
	if sess.IdentityID != identityID {
		t.Errorf("expected IdentityID %v, got %v", identityID, sess.IdentityID)
	}
	if sess.Token != returnedToken {
		t.Errorf("expected Token %q, got %q", returnedToken, sess.Token)
	}
	if sess.AAL != "aal1" {
		t.Errorf("expected AAL aal1, got %q", sess.AAL)
	}
	if !sess.Active {
		t.Errorf("expected Active=true")
	}
	if len(sess.AMR) != 1 || sess.AMR[0] != "password" {
		t.Errorf("expected AMR [password], got %v", sess.AMR)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Create_NilAMR(t *testing.T) {
	// nil AMR must be coerced to an empty slice before marshalling; the DB
	// returns an empty JSON array which decodes back to an empty slice.
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	identityID := uuid.New()
	sessionID := uuid.New()
	expiresAt := time.Now().Add(time.Hour)
	amrJSON := []byte(`[]`)

	mock.ExpectQuery(regexp.QuoteMeta(insertSQL)).
		WithArgs(
			tenantID, identityID,
			pgxmock.AnyArg(), pgxmock.AnyArg(),
			"aal1",
			pgxmock.AnyArg(),
		).
		WillReturnRows(
			pgxmock.NewRows(sessionColumns).AddRow(
				sessionID, tenantID, identityID, "tok",
				expiresAt, "aal1", amrJSON, true,
			),
		)

	sess, err := s.Create(context.Background(), tenantID, identityID, "aal1", nil, time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.AMR == nil {
		t.Errorf("expected non-nil AMR slice, got nil")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Create_DBError(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	identityID := uuid.New()
	dbErr := errors.New("connection refused")

	mock.ExpectQuery(regexp.QuoteMeta(insertSQL)).
		WithArgs(
			tenantID, identityID,
			pgxmock.AnyArg(), pgxmock.AnyArg(),
			"aal2",
			pgxmock.AnyArg(),
		).
		WillReturnError(dbErr)

	_, err := s.Create(context.Background(), tenantID, identityID, "aal2", []string{"totp"}, time.Hour)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GetByToken
// ---------------------------------------------------------------------------

func TestStore_GetByToken_Success(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	identityID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	sessionID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	const token = "valid-token-xyz"
	expiresAt := time.Now().Add(1 * time.Hour)
	amrJSON := []byte(`["password","totp"]`)

	mock.ExpectQuery(regexp.QuoteMeta(selectByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnRows(
			pgxmock.NewRows(sessionColumns).AddRow(
				sessionID, tenantID, identityID, token,
				expiresAt, "aal2", amrJSON, true,
			),
		)

	sess, err := s.GetByToken(context.Background(), tenantID, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.ID != sessionID {
		t.Errorf("ID mismatch: want %v got %v", sessionID, sess.ID)
	}
	if sess.Token != token {
		t.Errorf("Token mismatch: want %q got %q", token, sess.Token)
	}
	if sess.AAL != "aal2" {
		t.Errorf("AAL mismatch: want aal2 got %q", sess.AAL)
	}
	if len(sess.AMR) != 2 {
		t.Errorf("expected 2 AMR entries, got %d", len(sess.AMR))
	}
	if !sess.Active {
		t.Errorf("expected Active=true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetByToken_NotFound(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	const token = "ghost-token"

	// Empty result set causes pgx.Row.Scan to return pgx.ErrNoRows.
	mock.ExpectQuery(regexp.QuoteMeta(selectByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnRows(pgxmock.NewRows(sessionColumns))

	_, err := s.GetByToken(context.Background(), tenantID, token)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetByToken_NotFound_ErrNoRows(t *testing.T) {
	// Verify that a raw pgx.ErrNoRows from the driver is also mapped to ErrNotFound.
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	const token = "ghost-token-2"

	mock.ExpectQuery(regexp.QuoteMeta(selectByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnError(pgx.ErrNoRows)

	_, err := s.GetByToken(context.Background(), tenantID, token)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetByToken_DBError(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	const token = "some-token"
	dbErr := errors.New("dial tcp: refused")

	mock.ExpectQuery(regexp.QuoteMeta(selectByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnError(dbErr)

	_, err := s.GetByToken(context.Background(), tenantID, token)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
	// Must NOT be ErrNotFound.
	if errors.Is(err, ErrNotFound) {
		t.Errorf("db error must not be ErrNotFound")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetByToken_Revoked(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	identityID := uuid.New()
	const token = "revoked-token"
	expiresAt := time.Now().Add(time.Hour) // still in the future

	mock.ExpectQuery(regexp.QuoteMeta(selectByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnRows(
			pgxmock.NewRows(sessionColumns).AddRow(
				sessionID, tenantID, identityID, token,
				expiresAt, "aal1", []byte(`[]`), false, // active = false
			),
		)

	_, err := s.GetByToken(context.Background(), tenantID, token)
	if err == nil {
		t.Fatal("expected ErrRevoked, got nil")
	}
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("expected ErrRevoked, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_GetByToken_Expired(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	identityID := uuid.New()
	const token = "expired-token"
	expiresAt := time.Now().Add(-1 * time.Hour) // one hour in the past

	mock.ExpectQuery(regexp.QuoteMeta(selectByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnRows(
			pgxmock.NewRows(sessionColumns).AddRow(
				sessionID, tenantID, identityID, token,
				expiresAt, "aal1", []byte(`[]`), true, // active = true, but expired
			),
		)

	_, err := s.GetByToken(context.Background(), tenantID, token)
	if err == nil {
		t.Fatal("expected ErrExpired, got nil")
	}
	if !errors.Is(err, ErrExpired) {
		t.Errorf("expected ErrExpired, got: %v", err)
	}
	// Must not be ErrRevoked.
	if errors.Is(err, ErrRevoked) {
		t.Errorf("expired session should not be ErrRevoked")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

func TestStore_Revoke_Success(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")
	sessionID := uuid.MustParse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")

	mock.ExpectExec(regexp.QuoteMeta(revokeByIDSQL)).
		WithArgs(tenantID, sessionID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	if err := s.Revoke(context.Background(), tenantID, sessionID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Revoke_NotFound(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	sessionID := uuid.New()

	mock.ExpectExec(regexp.QuoteMeta(revokeByIDSQL)).
		WithArgs(tenantID, sessionID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0)) // 0 rows affected

	err := s.Revoke(context.Background(), tenantID, sessionID)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_Revoke_DBError(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	sessionID := uuid.New()
	dbErr := errors.New("deadlock detected")

	mock.ExpectExec(regexp.QuoteMeta(revokeByIDSQL)).
		WithArgs(tenantID, sessionID).
		WillReturnError(dbErr)

	err := s.Revoke(context.Background(), tenantID, sessionID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RevokeByToken
// ---------------------------------------------------------------------------

func TestStore_RevokeByToken_Success(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	const token = "token-to-revoke"

	mock.ExpectExec(regexp.QuoteMeta(revokeByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	if err := s.RevokeByToken(context.Background(), tenantID, token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_RevokeByToken_NotFound(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	const token = "nonexistent-token"

	mock.ExpectExec(regexp.QuoteMeta(revokeByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := s.RevokeByToken(context.Background(), tenantID, token)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStore_RevokeByToken_DBError(t *testing.T) {
	s, mock := newTestSessionStore(t)

	tenantID := uuid.New()
	const token = "any-token"
	dbErr := errors.New("network timeout")

	mock.ExpectExec(regexp.QuoteMeta(revokeByTokenSQL)).
		WithArgs(tenantID, token).
		WillReturnError(dbErr)

	err := s.RevokeByToken(context.Background(), tenantID, token)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ---------------------------------------------------------------------------
// decodeAMR (pure function)
// ---------------------------------------------------------------------------

func TestDecodeAMR_EmptyRaw(t *testing.T) {
	var dst []string
	if err := decodeAMR(nil, &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(dst) != 0 {
		t.Errorf("expected empty slice, got %v", dst)
	}
}

func TestDecodeAMR_ZeroLengthSlice(t *testing.T) {
	var dst []string
	if err := decodeAMR([]byte{}, &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dst) != 0 {
		t.Errorf("expected empty slice, got %v", dst)
	}
}

func TestDecodeAMR_NullJSON(t *testing.T) {
	var dst []string
	if err := decodeAMR([]byte("null"), &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst == nil {
		t.Error("expected non-nil empty slice for null JSON, got nil")
	}
	if len(dst) != 0 {
		t.Errorf("expected empty slice, got %v", dst)
	}
}

func TestDecodeAMR_EmptyJSONArray(t *testing.T) {
	var dst []string
	if err := decodeAMR([]byte(`[]`), &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dst) != 0 {
		t.Errorf("expected empty slice, got %v", dst)
	}
}

func TestDecodeAMR_ValidJSON(t *testing.T) {
	var dst []string
	if err := decodeAMR([]byte(`["password","totp"]`), &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dst) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(dst), dst)
	}
	if dst[0] != "password" {
		t.Errorf("expected dst[0]=\"password\", got %q", dst[0])
	}
	if dst[1] != "totp" {
		t.Errorf("expected dst[1]=\"totp\", got %q", dst[1])
	}
}

func TestDecodeAMR_SingleEntry(t *testing.T) {
	var dst []string
	if err := decodeAMR([]byte(`["passkey"]`), &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dst) != 1 || dst[0] != "passkey" {
		t.Errorf("expected [passkey], got %v", dst)
	}
}

func TestDecodeAMR_InvalidJSON(t *testing.T) {
	var dst []string
	err := decodeAMR([]byte(`not-valid-json`), &dst)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestDecodeAMR_MalformedJSON_Truncated(t *testing.T) {
	var dst []string
	err := decodeAMR([]byte(`["password"`), &dst) // missing closing bracket
	if err == nil {
		t.Fatal("expected error for truncated JSON, got nil")
	}
}

func TestDecodeAMR_WrongType(t *testing.T) {
	// JSON object instead of array: should fail to unmarshal into []string.
	var dst []string
	err := decodeAMR([]byte(`{"method":"password"}`), &dst)
	if err == nil {
		t.Fatal("expected error when JSON is not an array, got nil")
	}
}

// ---------------------------------------------------------------------------
// generateToken
// ---------------------------------------------------------------------------

func TestGenerateToken_NonEmpty(t *testing.T) {
	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}
	if tok == "" {
		t.Error("expected non-empty token, got empty string")
	}
}

func TestGenerateToken_ExpectedLength(t *testing.T) {
	// 32 random bytes → base64.RawURLEncoding → ceil(32*4/3) = 43 characters.
	tok, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken returned error: %v", err)
	}
	if len(tok) != 43 {
		t.Errorf("expected token length 43, got %d (token: %q)", len(tok), tok)
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	// Two successive calls must not return the same token.
	tok1, err := generateToken()
	if err != nil {
		t.Fatalf("first generateToken error: %v", err)
	}
	tok2, err := generateToken()
	if err != nil {
		t.Fatalf("second generateToken error: %v", err)
	}
	if tok1 == tok2 {
		t.Errorf("generateToken returned the same token twice: %q", tok1)
	}
}

func TestGenerateToken_URLSafeCharacters(t *testing.T) {
	// base64.RawURLEncoding must not produce +, /, or = characters.
	for i := 0; i < 50; i++ {
		tok, err := generateToken()
		if err != nil {
			t.Fatalf("generateToken error: %v", err)
		}
		for _, ch := range tok {
			if ch == '+' || ch == '/' || ch == '=' {
				t.Errorf("token contains non-URL-safe character %q: %s", ch, tok)
			}
		}
	}
}
