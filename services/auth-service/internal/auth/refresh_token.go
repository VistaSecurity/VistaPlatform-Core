package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var (
	ErrTokenReuseDetected = errors.New("token reuse detected - potential security breach")
	ErrInvalidTokenFamily = errors.New("invalid token family")
)

// RefreshTokenService handles refresh token operations with rotation and reuse detection.
//
// RLS NOTE (Phase 3): the refresh_tokens table is GLOBAL — it has NO
// <table>_tenant_isolation policy in scripts/database/schema.sql (it carries no
// tenant_id column; rows are keyed by user_id). All methods here therefore stay
// on the plain *sql.DB handle: there is no app.tenant_id to set, and these are
// session-bootstrap lookups (token-hash / user-id keyed) where the tenant is not
// an input anyway. Nothing to wrap.
type RefreshTokenService struct {
	db *sql.DB
}

// NewRefreshTokenService creates a new refresh token service
func NewRefreshTokenService(db *sql.DB) *RefreshTokenService {
	return &RefreshTokenService{db: db}
}

// hashToken creates a SHA-256 hash of the refresh token for secure storage
func (r *RefreshTokenService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// rotationGrace is how long after a token was rotated a second presentation of
// the OLD token is treated as a lost race rather than a theft. Two tabs (or a
// client retry after a dropped response) legitimately present the same token
// within milliseconds of each other; killing the whole family for that logs the
// real user out everywhere. Beyond the window a replay is reuse and revokes the
// family. The window never helps a thief obtain a session: the loser of the race
// is refused (ErrInvalidToken), it only avoids punishing the legitimate holder.
const rotationGrace = 10 * time.Second

// queryRower is the subset of *sql.DB and *sql.Tx the token INSERT needs, so
// the rotation can store the successor inside its transaction.
type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

// StoreRefreshToken stores a refresh token in the database with device fingerprint
// If familyID is nil, creates a new token family
func (r *RefreshTokenService) StoreRefreshToken(
	userID uuid.UUID,
	token string,
	familyID *uuid.UUID,
	expiresAt time.Time,
	clientIP string,
	userAgent string,
) (*uuid.UUID, error) {
	return r.storeRefreshToken(r.db, userID, token, familyID, expiresAt, clientIP, userAgent)
}

func (r *RefreshTokenService) storeRefreshToken(
	q queryRower,
	userID uuid.UUID,
	token string,
	familyID *uuid.UUID,
	expiresAt time.Time,
	clientIP string,
	userAgent string,
) (*uuid.UUID, error) {
	tokenHash := r.hashToken(token)

	// If no family ID provided, create a new family
	if familyID == nil {
		newFamilyID := uuid.New()
		familyID = &newFamilyID
	}

	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, created_from_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`

	var tokenID uuid.UUID
	err := q.QueryRow(query, userID, tokenHash, familyID, expiresAt, clientIP, userAgent).Scan(&tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return familyID, nil
}

// ValidateAndRotateToken validates a refresh token and rotates it
// Returns: newRefreshToken, newFamilyID, error
// If reuse is detected, returns ErrTokenReuseDetected and revokes the entire family
//
// Rotation is ATOMIC. The old token is claimed with a single
// `UPDATE ... WHERE token_hash = $1 AND is_revoked = false ... RETURNING`, and
// its successor is inserted in the same transaction. The previous
// SELECT-then-UPDATE-by-id-then-INSERT let two parallel refreshes both pass the
// check and both mint a live successor (a thief got a second branch), and a
// failure between the UPDATE and the INSERT left the user with no token at all.
// Now the row lock serialises the claimants: exactly one UPDATE matches, the rest
// match zero rows and are classified by classifyRejectedRefresh.
func (r *RefreshTokenService) ValidateAndRotateToken(
	oldToken string,
	userID uuid.UUID,
	newRefreshToken string,
	expiresAt time.Time,
	clientIP string,
	userAgent string,
) (*uuid.UUID, error) {
	oldTokenHash := r.hashToken(oldToken)

	tx, err := r.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin refresh rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	var tokenID, familyID uuid.UUID
	err = tx.QueryRow(`
		UPDATE refresh_tokens
		SET last_used_at = NOW(), is_revoked = true, revoked_at = NOW()
		WHERE token_hash = $1 AND user_id = $2 AND is_revoked = false AND expires_at > NOW()
		RETURNING id, family_id
	`, oldTokenHash, userID).Scan(&tokenID, &familyID)
	if err == sql.ErrNoRows {
		_ = tx.Rollback()
		return nil, r.classifyRejectedRefresh(oldTokenHash, userID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Create new token in the same family (rotation), in the same transaction.
	newFamilyID, err := r.storeRefreshToken(tx, userID, newRefreshToken, &familyID, expiresAt, clientIP, userAgent)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit refresh rotation: %w", err)
	}
	return newFamilyID, nil
}

// classifyRejectedRefresh explains why the claiming UPDATE matched no row.
//
//   - no such token for this user            -> ErrInvalidToken
//   - live but expired                       -> ErrExpiredToken
//   - revoked by a rotation within rotationGrace
//     (last_used_at == revoked_at, i.e. the
//     rotation statement set both)           -> ErrInvalidToken, family untouched:
//     this is the loser of a parallel refresh / a client retry
//   - revoked any other time or way          -> reuse: revoke the family,
// ErrTokenReuseDetected (the breach signal)
//
// Reuse detection runs BEFORE the expiry check for revoked rows, as before: a
// replayed already-rotated token outranks "expired".
func (r *RefreshTokenService) classifyRejectedRefresh(oldTokenHash string, userID uuid.UUID) error {
	var tokenID, familyID uuid.UUID
	var storedExpiresAt, lastUsedAt time.Time
	var revokedAt sql.NullTime
	var isRevoked bool
	err := r.db.QueryRow(`
		SELECT id, family_id, expires_at, is_revoked, revoked_at, last_used_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`, oldTokenHash, userID).Scan(&tokenID, &familyID, &storedExpiresAt, &isRevoked, &revokedAt, &lastUsedAt)
	if err == sql.ErrNoRows {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("failed to query refresh token: %w", err)
	}

	if !isRevoked {
		if time.Now().After(storedExpiresAt) {
			return ErrExpiredToken
		}
		// Live and unexpired yet unclaimed: only possible if a concurrent
		// rotation committed between the two statements. Treat as the race loser.
		return ErrInvalidToken
	}

	rotatedRecently := revokedAt.Valid &&
		!lastUsedAt.Before(revokedAt.Time) && // a rotation sets both to the same NOW()
		time.Since(revokedAt.Time) <= rotationGrace
	if rotatedRecently {
		logrus.WithFields(logrus.Fields{
			"event":     "refresh_token_rotation_race",
			"user_id":   userID,
			"family_id": familyID,
			"token_id":  tokenID,
		}).Info("Refresh token presented again within the rotation grace window — refused without revoking the family")
		return ErrInvalidToken
	}

	// Revoke the entire family as a security measure.
	if err := r.revokeTokenFamily(familyID, userID); err != nil {
		return fmt.Errorf("failed to revoke token family after reuse detection: %w", err)
	}
	logrus.WithFields(logrus.Fields{
		"event":     "refresh_token_reuse_detected",
		"user_id":   userID,
		"family_id": familyID,
		"token_id":  tokenID,
	}).Warn("Refresh-token reuse detected — revoked the entire token family")
	return ErrTokenReuseDetected
}

// revokeTokenFamily revokes all tokens in a token family (used when reuse is detected)
func (r *RefreshTokenService) revokeTokenFamily(familyID, userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE family_id = $1 AND user_id = $2 AND is_revoked = false
	`

	_, err := r.db.Exec(query, familyID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke token family: %w", err)
	}

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user (used on logout or security event)
func (r *RefreshTokenService) RevokeAllUserTokens(userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE user_id = $1 AND is_revoked = false
	`

	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}

	return nil
}

// RevokeToken revokes a specific refresh token by ID
func (r *RefreshTokenService) RevokeToken(userID, tokenID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE id = $1 AND user_id = $2 AND is_revoked = false
	`

	result, err := r.db.Exec(query, tokenID, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

// CleanupExpiredTokens removes expired tokens older than the retention period
func (r *RefreshTokenService) CleanupExpiredTokens(retentionDays int) error {
	retentionDate := time.Now().AddDate(0, 0, -retentionDays)

	query := `
		DELETE FROM refresh_tokens
		WHERE expires_at < $1 AND is_revoked = true
	`

	_, err := r.db.Exec(query, retentionDate)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	return nil
}
