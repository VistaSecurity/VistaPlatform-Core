package service_accounts

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// bcryptHash hashes a plaintext token at the package's configured cost, for
// building fixture rows without going through CreateServiceAccount.
func bcryptHash(t *testing.T, token string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(token), tokenBcryptCost)
	if err != nil {
		t.Fatalf("bcrypt hash fixture token: %v", err)
	}
	return string(h)
}

var accountCols = []string{
	"id", "service_name", "token_hash", "token_lookup", "description",
	"is_active", "created_at", "updated_at", "last_used_at",
}

// TestValidateToken_LookupFastPath: a token whose account was created after
// SEC-3 (token_lookup populated) resolves via the single indexed SELECT —
// the legacy full-scan query must never run.
func TestValidateToken_LookupFastPath(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	token := "fast-path-token"
	lookup := hashLookup(token)
	hash := bcryptHash(t, token)
	id := uuid.New()
	desc := "svc"

	mock.ExpectQuery(`SELECT id, service_name, token_hash, token_lookup, description, is_active, created_at, updated_at, last_used_at\s+FROM service_accounts\s+WHERE token_lookup = \$1 AND is_active = true`).
		WithArgs(lookup).
		WillReturnRows(sqlmock.NewRows(accountCols).AddRow(
			id, "svcname", hash, lookup, desc, true, time.Now(), time.Now(), nil,
		))
	mock.ExpectExec(`UPDATE service_accounts SET last_used_at = \$1, updated_at = \$1 WHERE id = \$2`).
		WithArgs(sqlmock.AnyArg(), id).
		WillReturnResult(sqlmock.NewResult(0, 1))

	svc := NewService(db)
	sa, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("expected valid token to resolve via lookup, got err: %v", err)
	}
	if sa.ID != id {
		t.Fatalf("got account %s, want %s", sa.ID, id)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations (legacy scan should not have run): %v", err)
	}
}

// Mutation test: flip one character in the presented token so it hashes to
// a different lookup digest than any stored row. The indexed query returns
// no rows, and — because there ARE no legacy (token_lookup IS NULL) rows in
// this fixture — the fallback scan also finds nothing. Confirms a
// non-matching token is rejected outright rather than accidentally matching.
func TestValidateToken_WrongToken_NoLookupMatch(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	wrongToken := "not-the-right-token"
	wrongLookup := hashLookup(wrongToken)

	mock.ExpectQuery(`WHERE token_lookup = \$1 AND is_active = true`).
		WithArgs(wrongLookup).
		WillReturnRows(sqlmock.NewRows(accountCols)) // no match

	mock.ExpectQuery(`FROM service_accounts\s+WHERE is_active = true AND token_lookup IS NULL`).
		WillReturnRows(sqlmock.NewRows(accountCols)) // no legacy rows either

	svc := NewService(db)
	if _, err := svc.ValidateToken(wrongToken); err != ErrTokenNotFound {
		t.Fatalf("expected ErrTokenNotFound for a non-matching token, got %v", err)
	}
}

// TestValidateToken_LegacyFallback: a pre-SEC-3 row (token_lookup IS NULL)
// still validates via the original full bcrypt scan, restricted to
// token_lookup IS NULL rows. Confirms the migration story doesn't strand
// already-issued tokens.
func TestValidateToken_LegacyFallback(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	token := "legacy-token-issued-before-sec3"
	lookup := hashLookup(token)
	hash := bcryptHash(t, token)
	id := uuid.New()
	desc := "legacy-svc"

	// Fast path: no row carries this lookup digest (legacy rows have
	// token_lookup = NULL, so they can never match here).
	mock.ExpectQuery(`WHERE token_lookup = \$1 AND is_active = true`).
		WithArgs(lookup).
		WillReturnRows(sqlmock.NewRows(accountCols))

	// Legacy fallback scan returns the un-migrated row; token_lookup is NULL
	// in the row itself too.
	mock.ExpectQuery(`FROM service_accounts\s+WHERE is_active = true AND token_lookup IS NULL`).
		WillReturnRows(sqlmock.NewRows(accountCols).AddRow(
			id, "legacy-svc", hash, nil, desc, true, time.Now(), time.Now(), nil,
		))
	mock.ExpectExec(`UPDATE service_accounts SET last_used_at = \$1, updated_at = \$1 WHERE id = \$2`).
		WithArgs(sqlmock.AnyArg(), id).
		WillReturnResult(sqlmock.NewResult(0, 1))

	svc := NewService(db)
	sa, err := svc.ValidateToken(token)
	if err != nil {
		t.Fatalf("expected legacy token to validate via fallback scan, got err: %v", err)
	}
	if sa.ID != id {
		t.Fatalf("got account %s, want %s", sa.ID, id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

// Empty-token guard: unchanged behavior, no query issued.
func TestValidateToken_EmptyToken(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	svc := NewService(db)
	if _, err := svc.ValidateToken(""); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for empty token, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("empty-token path issued unexpected queries: %v", err)
	}
}
