package auth

import (
	"errors"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func setupRefreshTokenService(t *testing.T) (*RefreshTokenService, sqlmock.Sqlmock, func()) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	svc := NewRefreshTokenService(db)
	cleanup := func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet SQL expectations: %v", err)
		}
		_ = db.Close()
	}

	return svc, mock, cleanup
}

func TestStoreRefreshTokenCreatesFamily(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	tokenID := uuid.New()
	expires := time.Now().Add(24 * time.Hour)

	mock.ExpectQuery(regexp.QuoteMeta(`
		INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, created_from_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`)).
		WithArgs(userID, sqlmock.AnyArg(), sqlmock.AnyArg(), expires, "127.0.0.1", "test-agent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(tokenID))

	familyID, err := svc.StoreRefreshToken(userID, "refresh-token", nil, expires, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if familyID == nil {
		t.Fatalf("expected familyID to be set")
	}
}

const rotateClaimSQL = `
		UPDATE refresh_tokens
		SET last_used_at = NOW(), is_revoked = true, revoked_at = NOW()
		WHERE token_hash = $1 AND user_id = $2 AND is_revoked = false AND expires_at > NOW()
		RETURNING id, family_id
	`

const classifySQL = `
		SELECT id, family_id, expires_at, is_revoked, revoked_at, last_used_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`

var classifyCols = []string{"id", "family_id", "expires_at", "is_revoked", "revoked_at", "last_used_at"}

func TestValidateAndRotateTokenSuccess(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	tokenID := uuid.New()
	familyID := uuid.New()
	now := time.Now()

	// Claim + successor insert + commit are ONE transaction.
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(rotateClaimSQL)).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "family_id"}).AddRow(tokenID, familyID))
	mock.ExpectQuery(regexp.QuoteMeta(`
		INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, created_from_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`)).
		WithArgs(userID, sqlmock.AnyArg(), familyID, sqlmock.AnyArg(), "127.0.0.1", "test-agent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock.ExpectCommit()

	_, err := svc.ValidateAndRotateToken("old-token", userID, "new-token", now.Add(time.Hour), "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

// A replay of a token that was rotated LONG ago is reuse: the family dies.
func TestValidateAndRotateTokenReuseDetected(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	tokenID := uuid.New()
	familyID := uuid.New()
	rotatedAt := time.Now().Add(-time.Hour)

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(rotateClaimSQL)).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "family_id"})) // zero rows: already revoked
	mock.ExpectRollback()
	mock.ExpectQuery(regexp.QuoteMeta(classifySQL)).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnRows(sqlmock.NewRows(classifyCols).
			AddRow(tokenID, familyID, time.Now().Add(time.Hour), true, rotatedAt, rotatedAt))
	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE family_id = $1 AND user_id = $2 AND is_revoked = false
	`)).
		WithArgs(familyID, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, err := svc.ValidateAndRotateToken("stolen-rotated-token", userID, "new-token", time.Now().Add(time.Hour), "ip", "ua")
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("expected ErrTokenReuseDetected on revoked-token replay, got %v", err)
	}
}

// A token revoked by something other than a rotation (logout, family revoke:
// last_used_at older than revoked_at) is reuse even inside the grace window.
func TestValidateAndRotateTokenReuseDetectedWhenRevokedByLogout(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	familyID := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(rotateClaimSQL)).WillReturnRows(sqlmock.NewRows([]string{"id", "family_id"}))
	mock.ExpectRollback()
	mock.ExpectQuery(regexp.QuoteMeta(classifySQL)).
		WillReturnRows(sqlmock.NewRows(classifyCols).
			AddRow(uuid.New(), familyID, now.Add(time.Hour), true, now.Add(-time.Second), now.Add(-time.Hour)))
	mock.ExpectExec("UPDATE refresh_tokens").WillReturnResult(sqlmock.NewResult(0, 1))

	_, err := svc.ValidateAndRotateToken("logged-out-token", userID, "new-token", now.Add(time.Hour), "ip", "ua")
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("expected ErrTokenReuseDetected, got %v", err)
	}
}

// The loser of a parallel refresh (the old token rotated a moment ago) is
// refused WITHOUT revoking the family: no family-revoke UPDATE is expected, so
// sqlmock fails the test if one is issued.
func TestValidateAndRotateTokenRaceLoserKeepsFamily(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	familyID := uuid.New()
	rotatedAt := time.Now().Add(-500 * time.Millisecond)

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(rotateClaimSQL)).WillReturnRows(sqlmock.NewRows([]string{"id", "family_id"}))
	mock.ExpectRollback()
	mock.ExpectQuery(regexp.QuoteMeta(classifySQL)).
		WillReturnRows(sqlmock.NewRows(classifyCols).
			AddRow(uuid.New(), familyID, time.Now().Add(time.Hour), true, rotatedAt, rotatedAt))

	_, err := svc.ValidateAndRotateToken("just-rotated", userID, "new-token", time.Now().Add(time.Hour), "ip", "ua")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for the race loser, got %v", err)
	}
}

func TestValidateAndRotateTokenUnknownAndExpired(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()
	userID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(rotateClaimSQL)).WillReturnRows(sqlmock.NewRows([]string{"id", "family_id"}))
	mock.ExpectRollback()
	mock.ExpectQuery(regexp.QuoteMeta(classifySQL)).WillReturnRows(sqlmock.NewRows(classifyCols))
	if _, err := svc.ValidateAndRotateToken("nope", userID, "n", time.Now().Add(time.Hour), "ip", "ua"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown token: got %v, want ErrInvalidToken", err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(rotateClaimSQL)).WillReturnRows(sqlmock.NewRows([]string{"id", "family_id"}))
	mock.ExpectRollback()
	mock.ExpectQuery(regexp.QuoteMeta(classifySQL)).
		WillReturnRows(sqlmock.NewRows(classifyCols).
			AddRow(uuid.New(), uuid.New(), time.Now().Add(-time.Hour), false, nil, time.Now().Add(-2*time.Hour)))
	if _, err := svc.ValidateAndRotateToken("old", userID, "n", time.Now().Add(time.Hour), "ip", "ua"); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expired token: got %v, want ErrExpiredToken", err)
	}
}

func TestCleanupExpiredTokens(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	mock.ExpectExec(regexp.QuoteMeta(`
		DELETE FROM refresh_tokens
		WHERE expires_at < $1 AND is_revoked = true
	`)).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 3))

	if err := svc.CleanupExpiredTokens(30); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
