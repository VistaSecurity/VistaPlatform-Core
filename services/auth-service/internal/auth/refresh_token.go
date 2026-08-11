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
	err := r.db.QueryRow(query, userID, tokenHash, familyID, expiresAt, clientIP, userAgent).Scan(&tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return familyID, nil
}

// ValidateAndRotateToken validates a refresh token and rotates it
// Returns: newRefreshToken, newFamilyID, error
// If reuse is detected, returns ErrTokenReuseDetected and revokes the entire family
func (r *RefreshTokenService) ValidateAndRotateToken(
	oldToken string,
	userID uuid.UUID,
	newRefreshToken string,
	expiresAt time.Time,
	clientIP string,
	userAgent string,
) (*uuid.UUID, error) {
	oldTokenHash := r.hashToken(oldToken)

	// Find the refresh token in database.
	//
	// SECURITY: the lookup is intentionally NOT filtered by
	// `is_revoked = false`. A successful rotation marks the old token revoked, so
	// when a stolen-then-rotated token is replayed it must still be FOUND here —
	// otherwise it matches zero rows, returns a generic ErrInvalidToken, and the
	// reuse-detection branch below never runs (the breach signal never fires).
	query := `
		SELECT id, family_id, expires_at, is_revoked, last_used_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND user_id = $2
	`

	var tokenID uuid.UUID
	var familyID uuid.UUID
	var storedExpiresAt time.Time
	var isRevoked bool
	var lastUsedAt time.Time
	var createdAt time.Time

	err := r.db.QueryRow(query, oldTokenHash, userID).Scan(&tokenID, &familyID, &storedExpiresAt, &isRevoked, &lastUsedAt, &createdAt)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query refresh token: %w", err)
	}

	// Reuse detection runs BEFORE the expiry check: a replayed token that is
	// already revoked — or whose last_used_at has advanced past created_at —
	// means the same refresh token was presented twice. That is the classic
	// stolen-token signal and outranks "expired".
	//
	//   - reuseByRevoked: the token was already rotated/revoked once. Replaying
	//     it is the real attack path this fix restores (previously unreachable).
	//   - reuseByTiming:  last_used_at moved past created_at (allowing 1s of
	//     clock skew) — the original synthetic check, kept as a backstop.
	reuseByRevoked := isRevoked
	reuseByTiming := !lastUsedAt.IsZero() && lastUsedAt.After(createdAt.Add(1*time.Second))
	if reuseByRevoked || reuseByTiming {
		// Revoke the entire family as a security measure.
		if err := r.revokeTokenFamily(familyID, userID); err != nil {
			return nil, fmt.Errorf("failed to revoke token family after reuse detection: %w", err)
		}
		logrus.WithFields(logrus.Fields{
			"event":       "refresh_token_reuse_detected",
			"user_id":     userID,
			"family_id":   familyID,
			"token_id":    tokenID,
			"via_revoked": reuseByRevoked,
			"via_timing":  reuseByTiming,
		}).Warn("Refresh-token reuse detected — revoked the entire token family")
		return nil, ErrTokenReuseDetected
	}

	// Not a reuse — enforce expiry on the live token.
	if time.Now().After(storedExpiresAt) {
		return nil, ErrExpiredToken
	}

	// Update last_used_at to mark this token as used (for reuse detection)
	// Then mark as revoked (instead of deleting, we keep it for audit)
	updateQuery := `
		UPDATE refresh_tokens
		SET last_used_at = NOW(), is_revoked = true, revoked_at = NOW()
		WHERE id = $1
	`

	_, err = r.db.Exec(updateQuery, tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Create new token in the same family (rotation)
	newFamilyID, err := r.StoreRefreshToken(userID, newRefreshToken, &familyID, expiresAt, clientIP, userAgent)
	if err != nil {
		return nil, err
	}

	return newFamilyID, nil
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
