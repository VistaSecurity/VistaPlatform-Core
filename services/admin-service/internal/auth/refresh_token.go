package auth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrTokenReuseDetected = errors.New("token reuse detected - potential security breach")
	ErrInvalidTokenFamily = errors.New("invalid token family")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("expired token")
	ErrSessionNotFound    = errors.New("session not found")
)

// PlatformRefreshTokenService handles refresh token operations for platform admins
// Provides the same security features as tenant users: rotation, reuse detection, device fingerprinting
type PlatformRefreshTokenService struct {
	db *sql.DB
}

// NewPlatformRefreshTokenService creates a new platform refresh token service
func NewPlatformRefreshTokenService(db *sql.DB) *PlatformRefreshTokenService {
	return &PlatformRefreshTokenService{db: db}
}

// hashToken creates a SHA-256 hash of the refresh token for secure storage
func (r *PlatformRefreshTokenService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// HashToken exposes hashToken for use in handlers
func (r *PlatformRefreshTokenService) HashToken(token string) string {
	return r.hashToken(token)
}

// StoreRefreshToken stores a refresh token in the database with device fingerprint
// If familyID is nil, creates a new token family
func (r *PlatformRefreshTokenService) StoreRefreshToken(
	platformUserID uuid.UUID,
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
		INSERT INTO platform_refresh_tokens (platform_user_id, token_hash, family_id, expires_at, created_from_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`

	var tokenID uuid.UUID
	err := r.db.QueryRow(query, platformUserID, tokenHash, familyID, expiresAt, clientIP, userAgent).Scan(&tokenID)
	if err != nil {
		// Check if it's a duplicate key error - this shouldn't happen with proper token generation
		// but if it does (e.g., clock skew causing identical JWT claims), we handle it gracefully
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, fmt.Errorf("token hash already exists - duplicate token generated (likely due to identical JWT claims)")
		}
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return familyID, nil
}

// ValidateAndRotateToken validates a refresh token and rotates it
// Returns: newFamilyID, error
// If reuse is detected, returns ErrTokenReuseDetected and revokes the entire family
func (r *PlatformRefreshTokenService) ValidateAndRotateToken(
	oldToken string,
	platformUserID uuid.UUID,
	newRefreshToken string,
	expiresAt time.Time,
	clientIP string,
	userAgent string,
) (*uuid.UUID, error) {
	oldTokenHash := r.hashToken(oldToken)

	// Find the refresh token in database
	query := `
		SELECT id, family_id, expires_at, is_revoked, last_used_at, created_at
		FROM platform_refresh_tokens
		WHERE token_hash = $1 AND platform_user_id = $2 AND is_revoked = false
	`

	var tokenID uuid.UUID
	var familyID uuid.UUID
	var storedExpiresAt time.Time
	var isRevoked bool
	var lastUsedAt time.Time
	var createdAt time.Time

	err := r.db.QueryRow(query, oldTokenHash, platformUserID).Scan(&tokenID, &familyID, &storedExpiresAt, &isRevoked, &lastUsedAt, &createdAt)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query refresh token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(storedExpiresAt) {
		return nil, ErrExpiredToken
	}

	// Check if token is already revoked
	if isRevoked {
		return nil, ErrInvalidToken
	}

	// Check for reuse: if this token was already used, last_used_at will be after created_at
	// Since last_used_at defaults to NOW() on creation, we check if it's been updated
	// If last_used_at is significantly different from created_at, it was already used
	// We allow a small difference (1 second) for clock skew
	if !lastUsedAt.IsZero() && lastUsedAt.After(createdAt.Add(1*time.Second)) {
		// Token reuse detected! Revoke entire family as security measure
		err := r.revokeTokenFamily(familyID, platformUserID)
		if err != nil {
			return nil, fmt.Errorf("failed to revoke token family after reuse detection: %w", err)
		}
		return nil, ErrTokenReuseDetected
	}

	// Update last_used_at to mark this token as used (for reuse detection)
	// Then mark as revoked (instead of deleting, we keep it for audit)
	updateQuery := `
		UPDATE platform_refresh_tokens
		SET last_used_at = NOW(), is_revoked = true, revoked_at = NOW()
		WHERE id = $1
	`

	_, err = r.db.Exec(updateQuery, tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Create new token in the same family (rotation)
	newFamilyID, err := r.StoreRefreshToken(platformUserID, newRefreshToken, &familyID, expiresAt, clientIP, userAgent)
	if err != nil {
		return nil, err
	}

	return newFamilyID, nil
}

// revokeTokenFamily revokes all tokens in a token family (used when reuse is detected)
func (r *PlatformRefreshTokenService) revokeTokenFamily(familyID, platformUserID uuid.UUID) error {
	query := `
		UPDATE platform_refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE family_id = $1 AND platform_user_id = $2 AND is_revoked = false
	`

	_, err := r.db.Exec(query, familyID, platformUserID)
	if err != nil {
		return fmt.Errorf("failed to revoke token family: %w", err)
	}

	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a platform user (used on logout or security event)
func (r *PlatformRefreshTokenService) RevokeAllUserTokens(platformUserID uuid.UUID) error {
	query := `
		UPDATE platform_refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE platform_user_id = $1 AND is_revoked = false
	`

	_, err := r.db.Exec(query, platformUserID)
	if err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}

	return nil
}

// RevokeToken revokes a specific refresh token by ID
func (r *PlatformRefreshTokenService) RevokeToken(platformUserID, tokenID uuid.UUID) error {
	query := `
		UPDATE platform_refresh_tokens
		SET is_revoked = true, revoked_at = NOW()
		WHERE id = $1 AND platform_user_id = $2 AND is_revoked = false
	`

	result, err := r.db.Exec(query, tokenID, platformUserID)
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
func (r *PlatformRefreshTokenService) CleanupExpiredTokens(retentionDays int) error {
	retentionDate := time.Now().AddDate(0, 0, -retentionDays)

	query := `
		DELETE FROM platform_refresh_tokens
		WHERE expires_at < $1 AND is_revoked = true
	`

	_, err := r.db.Exec(query, retentionDate)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	return nil
}
