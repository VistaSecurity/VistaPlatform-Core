package service_accounts

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidToken is returned when a token is invalid
	ErrInvalidToken = fmt.Errorf("invalid service account token")
	// ErrInactiveAccount is returned when a service account is inactive
	ErrInactiveAccount = fmt.Errorf("service account is inactive")
	// ErrTokenNotFound is returned when a token doesn't match any service account
	ErrTokenNotFound = fmt.Errorf("service account token not found")
)

// Service handles service account operations
type Service struct {
	db *sql.DB
}

// NewService creates a new service account service
func NewService(db *sql.DB) *Service {
	return &Service{
		db: db,
	}
}

// GenerateToken generates a secure random token for a service account
// Returns the plaintext token that should be stored securely
func GenerateToken() (string, error) {
	// Generate 32 random bytes (256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	// Encode as base64 URL-safe string
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

// HashToken hashes a service account token using bcrypt.
// Cost=12 (~320ms on modern CPUs) — service-account token creation is rare;
// the extra cost meaningfully raises offline-brute-force cost of a stolen
// token database.
const tokenBcryptCost = 12

func HashToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), tokenBcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash token: %w", err)
	}
	return string(hash), nil
}

// hashLookup returns the hex SHA-256 digest of a plaintext token. This is
// NOT a substitute for the bcrypt token_hash — it's an indexed narrowing
// key so ValidateToken doesn't have to bcrypt-compare against every active
// account (see the SEC-3 schema comment on service_accounts.token_lookup in
// scripts/database/schema.sql). SHA-256 is safe here specifically because
// the input is a high-entropy generated token (32 random bytes, base64), not
// a human-chosen secret — there's nothing for a rainbow table to target.
func hashLookup(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ValidateToken validates a service account token against the database.
// Returns the service account if valid, or an error if invalid.
//
// Lookup strategy (SEC-3): tokens created after the token_lookup column was
// added carry an indexed SHA-256 digest, so the common case is a single
// indexed row fetch followed by one bcrypt confirm. bcrypt is one-way, so
// pre-existing rows (created before this column existed) have
// token_lookup = NULL and cannot be backfilled; for those, ValidateToken
// falls back to the original full bcrypt scan, restricted to
// `token_lookup IS NULL` so it only ever considers not-yet-migrated rows.
// That legacy set shrinks every time an operator rotates a service account
// token (CreateServiceAccount always populates token_lookup on new rows).
func (s *Service) ValidateToken(token string) (*models.ServiceAccount, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	if sa, err := s.validateTokenByLookup(token); err == nil {
		return sa, nil
	} else if !errors.Is(err, ErrTokenNotFound) {
		return nil, err
	}

	return s.validateTokenLegacyScan(token)
}

// validateTokenByLookup is the fast path: one indexed row by SHA-256 digest,
// then a single bcrypt confirm. Returns ErrTokenNotFound (not a hard error)
// when no active row has a matching token_lookup, so the caller knows to
// fall back to the legacy scan rather than failing outright.
func (s *Service) validateTokenByLookup(token string) (*models.ServiceAccount, error) {
	lookup := hashLookup(token)

	query := `
		SELECT id, service_name, token_hash, token_lookup, description, is_active, created_at, updated_at, last_used_at
		FROM service_accounts
		WHERE token_lookup = $1 AND is_active = true
	`
	var sa models.ServiceAccount
	err := s.db.QueryRow(query, lookup).Scan(
		&sa.ID,
		&sa.ServiceName,
		&sa.TokenHash,
		&sa.TokenLookup,
		&sa.Description,
		&sa.IsActive,
		&sa.CreatedAt,
		&sa.UpdatedAt,
		&sa.LastUsedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to query service account by lookup: %w", err)
	}

	// The indexed digest already narrowed to this one row; bcrypt still
	// confirms it against the credential of record. A lookup hit that fails
	// this confirm is an anomaly (corruption/collision), not a case to fall
	// through to the legacy scan for — the digest match already proves
	// possession of the exact same 256-bit token, so no other row could
	// legitimately match either.
	if err := bcrypt.CompareHashAndPassword([]byte(sa.TokenHash), []byte(token)); err != nil {
		return nil, ErrTokenNotFound
	}

	s.touchLastUsed(sa.ID)
	now := time.Now()
	sa.LastUsedAt = &now
	return &sa, nil
}

// validateTokenLegacyScan is the pre-SEC-3 O(N) fallback, narrowed to rows
// that have never been migrated to carry a token_lookup digest.
func (s *Service) validateTokenLegacyScan(token string) (*models.ServiceAccount, error) {
	query := `
		SELECT id, service_name, token_hash, token_lookup, description, is_active, created_at, updated_at, last_used_at
		FROM service_accounts
		WHERE is_active = true AND token_lookup IS NULL
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query service accounts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var sa models.ServiceAccount
		err := rows.Scan(
			&sa.ID,
			&sa.ServiceName,
			&sa.TokenHash,
			&sa.TokenLookup,
			&sa.Description,
			&sa.IsActive,
			&sa.CreatedAt,
			&sa.UpdatedAt,
			&sa.LastUsedAt,
		)
		if err != nil {
			continue
		}

		if bcrypt.CompareHashAndPassword([]byte(sa.TokenHash), []byte(token)) == nil {
			s.touchLastUsed(sa.ID)
			now := time.Now()
			sa.LastUsedAt = &now
			return &sa, nil
		}
	}

	return nil, ErrTokenNotFound
}

func (s *Service) touchLastUsed(id uuid.UUID) {
	now := time.Now()
	_, _ = s.db.Exec(`UPDATE service_accounts SET last_used_at = $1, updated_at = $1 WHERE id = $2`, now, id) // Ignore update errors
}

// GetServiceAccountByName retrieves a service account by service name
func (s *Service) GetServiceAccountByName(serviceName string) (*models.ServiceAccount, error) {
	query := `
		SELECT id, service_name, token_hash, token_lookup, description, is_active, created_at, updated_at, last_used_at
		FROM service_accounts
		WHERE service_name = $1
	`
	var sa models.ServiceAccount
	err := s.db.QueryRow(query, serviceName).Scan(
		&sa.ID,
		&sa.ServiceName,
		&sa.TokenHash,
		&sa.TokenLookup,
		&sa.Description,
		&sa.IsActive,
		&sa.CreatedAt,
		&sa.UpdatedAt,
		&sa.LastUsedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("service account not found: %s", serviceName)
		}
		return nil, fmt.Errorf("failed to get service account: %w", err)
	}
	return &sa, nil
}

// CreateServiceAccount creates a new service account with a generated token
// Returns both the service account and the plaintext token
func (s *Service) CreateServiceAccount(serviceName, description string) (*models.ServiceAccount, string, error) {
	// Generate token
	token, err := GenerateToken()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Hash token
	tokenHash, err := HashToken(token)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash token: %w", err)
	}

	// SEC-3: populate the indexed lookup digest so ValidateToken can resolve
	// this account in O(1) instead of the legacy full bcrypt scan.
	lookup := hashLookup(token)

	// Create service account
	sa := &models.ServiceAccount{
		ID:          uuid.New(),
		ServiceName: serviceName,
		TokenHash:   tokenHash,
		TokenLookup: &lookup,
		Description: &description,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	query := `
		INSERT INTO service_accounts (id, service_name, token_hash, token_lookup, description, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, service_name, description, is_active, created_at, updated_at, last_used_at
	`
	err = s.db.QueryRow(
		query,
		sa.ID,
		sa.ServiceName,
		sa.TokenHash,
		sa.TokenLookup,
		sa.Description,
		sa.IsActive,
		sa.CreatedAt,
		sa.UpdatedAt,
	).Scan(
		&sa.ID,
		&sa.ServiceName,
		&sa.Description,
		&sa.IsActive,
		&sa.CreatedAt,
		&sa.UpdatedAt,
		&sa.LastUsedAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create service account: %w", err)
	}

	return sa, token, nil
}
