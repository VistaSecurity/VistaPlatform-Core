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

func TestValidateAndRotateTokenSuccess(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	tokenID := uuid.New()
	familyID := uuid.New()
	now := time.Now()

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT id, family_id, expires_at, is_revoked, last_used_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`)).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "family_id", "expires_at", "is_revoked", "last_used_at", "created_at"}).
			AddRow(tokenID, familyID, now.Add(time.Hour), false, now, now))

	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE refresh_tokens
		SET last_used_at = NOW(), is_revoked = true, revoked_at = NOW()
		WHERE id = $1
	`)).WithArgs(tokenID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectQuery(regexp.QuoteMeta(`
		INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, created_from_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`)).
		WithArgs(userID, sqlmock.AnyArg(), familyID, sqlmock.AnyArg(), "127.0.0.1", "test-agent").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	_, err := svc.ValidateAndRotateToken("old-token", userID, "new-token", now.Add(time.Hour), "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestValidateAndRotateTokenReuseDetected(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	tokenID := uuid.New()
	familyID := uuid.New()
	created := time.Now().Add(-2 * time.Hour)
	lastUsed := created.Add(5 * time.Minute)

	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT id, family_id, expires_at, is_revoked, last_used_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`)).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "family_id", "expires_at", "is_revoked", "last_used_at", "created_at"}).
			AddRow(tokenID, familyID, time.Now().Add(time.Hour), false, lastUsed, created))

	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE family_id = $1 AND user_id = $2 AND is_revoked = false
	`)).
		WithArgs(familyID, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, err := svc.ValidateAndRotateToken("old-token", userID, "new-token", time.Now().Add(time.Hour), "ip", "ua")
	if err == nil {
		t.Fatalf("expected ErrTokenReuseDetected")
	}
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("expected ErrTokenReuseDetected, got %v", err)
	}
}

// TestValidateAndRotateTokenReuseDetectedOnRevokedReplay covers the real
// path: a token that was already rotated (and therefore marked is_revoked=true)
// is replayed. The lookup must still FIND the row (no is_revoked filter), detect
// it as reuse, and revoke the whole family — previously this row matched zero
// rows and silently returned ErrInvalidToken, so the breach signal never fired.
func TestValidateAndRotateTokenReuseDetectedOnRevokedReplay(t *testing.T) {
	svc, mock, cleanup := setupRefreshTokenService(t)
	defer cleanup()

	userID := uuid.New()
	tokenID := uuid.New()
	familyID := uuid.New()
	now := time.Now()

	// The replayed token is already revoked (it was rotated once). Crucially it
	// is NOT expired — reuse detection must still fire ahead of the expiry check.
	mock.ExpectQuery(regexp.QuoteMeta(`
		SELECT id, family_id, expires_at, is_revoked, last_used_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`)).
		WithArgs(sqlmock.AnyArg(), userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "family_id", "expires_at", "is_revoked", "last_used_at", "created_at"}).
			AddRow(tokenID, familyID, now.Add(time.Hour), true, now, now))

	mock.ExpectExec(regexp.QuoteMeta(`
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE family_id = $1 AND user_id = $2 AND is_revoked = false
	`)).
		WithArgs(familyID, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	_, err := svc.ValidateAndRotateToken("stolen-rotated-token", userID, "new-token", now.Add(time.Hour), "ip", "ua")
	if !errors.Is(err, ErrTokenReuseDetected) {
		t.Fatalf("expected ErrTokenReuseDetected on revoked-token replay, got %v", err)
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
