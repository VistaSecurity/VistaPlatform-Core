// Package apitokens implements tenant-scoped personal access tokens (PATs).
//
// A token is a bearer credential a tenant user mints for programmatic
// access — the v1 consumer is the MCP service, which exchanges a PAT for a
// short-lived user JWT via the HMAC-guarded /internal/api-tokens/exchange
// endpoint and then calls platform read APIs as that user.
//
// Tokens are 256-bit CSPRNG values prefixed "qvpat_" and stored as hex
// SHA-256 (O(1) indexed lookup; no KDF needed for high-entropy secrets —
// see the schema comment on public.api_tokens). The plaintext is returned
// exactly once at creation.
package apitokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

const (
	// TokenPrefix namespaces VistaPlatform PATs so leaked-credential scanners
	// and humans can recognize them on sight.
	TokenPrefix = "qvpat_"

	// MaxActiveTokensPerUser bounds abuse and accidental token sprawl.
	MaxActiveTokensPerUser = 25

	// DefaultExpiryDays applies when the caller doesn't pick an expiry.
	DefaultExpiryDays = 90
	// MaxExpiryDays caps how far out a token may live.
	MaxExpiryDays = 365
)

var (
	ErrTokenNotFound  = errors.New("api token not found")
	ErrTokenRevoked   = errors.New("api token has been revoked")
	ErrTokenExpired   = errors.New("api token has expired")
	ErrTooManyTokens  = fmt.Errorf("active token limit reached (%d per user)", MaxActiveTokensPerUser)
	ErrInvalidPerm    = errors.New("permission not allowed on api tokens")
	ErrInvalidExpiry  = fmt.Errorf("expires_in_days must be between 1 and %d", MaxExpiryDays)
	ErrEmptyName      = errors.New("token name is required")
	ErrMalformedToken = errors.New("malformed api token")
	ErrNotTokenOwner  = errors.New("token does not belong to the caller")
)

// AllowedPermissions is the closed set of permission strings a PAT may
// carry in v1. Read-only by design: the MCP surface is read-only, and
// keeping writes off tokens entirely means a leaked PAT cannot mutate
// tenant state through any consumer.
var AllowedPermissions = []string{
	"assets.read",
	"compliance.read",
	"reports.read",
	"discovery.read",
	"sensors.read",
	"settings.read",
}

// DefaultPermissions is what a token gets when the caller doesn't choose.
var DefaultPermissions = []string{"assets.read", "compliance.read", "reports.read"}

// Token is the persisted shape (plaintext never stored).
type Token struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	UserID      uuid.UUID  `json:"user_id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Service provides api_tokens persistence and validation.
type Service struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the
	// cross-tenant PAT paths (Validate resolves the tenant FROM the presented
	// token hash; TouchLastUsed is keyed by token id only). Pre-flip it
	// resolves to the same connection as db.
	bypassDB *sql.DB
}

func NewService(db *sql.DB, bypassDB *sql.DB) *Service {
	return &Service{db: db, bypassDB: bypassDB}
}

// GenerateToken returns a new plaintext token: "qvpat_" + 32 CSPRNG bytes,
// base64url without padding.
func GenerateToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// HashToken returns the hex SHA-256 of the full plaintext token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// displayPrefix is the leading fragment stored for UI identification
// ("qvpat_AbCd…"). Long enough to recognize, far too short to brute-force
// the remaining 256-bit body.
func displayPrefix(token string) string {
	const n = 10 // "qvpat_" + 4 chars
	if len(token) < n {
		return token
	}
	return token[:n]
}

// ValidatePermissions checks every requested permission against the
// allowed closed set. Returns the (possibly defaulted) normalized list.
func ValidatePermissions(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return append([]string(nil), DefaultPermissions...), nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(requested))
	for _, p := range requested {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		allowed := false
		for _, a := range AllowedPermissions {
			if p == a {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: %q", ErrInvalidPerm, p)
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return append([]string(nil), DefaultPermissions...), nil
	}
	return out, nil
}

// Create mints a token for (tenantID, userID). Returns the record and the
// plaintext — the only time the plaintext ever exists outside the caller.
func (s *Service) Create(tenantID, userID uuid.UUID, name string, permissions []string, expiresInDays int) (*Token, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", ErrEmptyName
	}
	if len(name) > 255 {
		name = name[:255]
	}

	perms, err := ValidatePermissions(permissions)
	if err != nil {
		return nil, "", err
	}

	if expiresInDays == 0 {
		expiresInDays = DefaultExpiryDays
	}
	if expiresInDays < 1 || expiresInDays > MaxExpiryDays {
		return nil, "", ErrInvalidExpiry
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiresInDays) * 24 * time.Hour)

	// RLS-scoped: api_tokens carries a tenant_isolation policy. The tenant is
	// known, so the active-token count runs inside WithTenantTx.
	var active int
	err = shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM api_tokens
			 WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
			   AND (expires_at IS NULL OR expires_at > now())`,
			userID, tenantID,
		).Scan(&active)
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to count active tokens: %w", err)
	}
	if active >= MaxActiveTokensPerUser {
		return nil, "", ErrTooManyTokens
	}

	plaintext, err := GenerateToken()
	if err != nil {
		return nil, "", err
	}

	permsJSON, err := json.Marshal(perms)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal permissions: %w", err)
	}

	t := &Token{
		ID:          uuid.New(),
		TenantID:    tenantID,
		UserID:      userID,
		Name:        name,
		TokenPrefix: displayPrefix(plaintext),
		Permissions: perms,
		ExpiresAt:   &expiresAt,
		CreatedAt:   time.Now().UTC(),
	}

	// RLS-scoped write: WithTenantTx sets app.tenant_id so the INSERT satisfies
	// the api_tokens policy WITH CHECK on tenant_id.
	err = shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(context.Background(),
			`INSERT INTO api_tokens (id, tenant_id, user_id, name, token_hash, token_prefix, permissions, expires_at, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)`,
			t.ID, t.TenantID, t.UserID, t.Name, HashToken(plaintext), t.TokenPrefix, permsJSON, t.ExpiresAt, t.CreatedAt,
		)
		return e
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to insert api token: %w", err)
	}

	return t, plaintext, nil
}

// List returns the caller's own tokens (newest first), revoked included —
// the row is the audit record of the credential.
func (s *Service) List(tenantID, userID uuid.UUID) ([]Token, error) {
	// RLS-scoped read over api_tokens (tenant_isolation policy); tenant is known.
	tokens := []Token{}
	err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(context.Background(),
			`SELECT id, tenant_id, user_id, name, token_prefix, permissions,
			        expires_at, last_used_at, revoked_at, created_at
			 FROM api_tokens
			 WHERE tenant_id = $1 AND user_id = $2
			 ORDER BY created_at DESC`,
			tenantID, userID,
		)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			t, scanErr := scanToken(rows)
			if scanErr != nil {
				return scanErr
			}
			tokens = append(tokens, *t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list api tokens: %w", err)
	}
	return tokens, nil
}

// Revoke marks the token revoked. Only the owning user may revoke.
func (s *Service) Revoke(tenantID, userID, tokenID uuid.UUID) error {
	// RLS-scoped: the UPDATE + the follow-up EXISTS disambiguation both run on
	// api_tokens (tenant_isolation policy) for a known tenant, inside one
	// WithTenantTx. The sentinel result (ErrTokenRevoked / ErrTokenNotFound) is
	// surfaced via a typed error returned from fn.
	err := shareddatabase.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sql.Tx) error {
		res, e := tx.ExecContext(context.Background(),
			`UPDATE api_tokens SET revoked_at = now(), updated_at = now()
			 WHERE id = $1 AND tenant_id = $2 AND user_id = $3 AND revoked_at IS NULL`,
			tokenID, tenantID, userID,
		)
		if e != nil {
			return fmt.Errorf("failed to revoke api token: %w", e)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			// Distinguish "not yours / missing" from "already revoked" for the handler.
			var exists bool
			if qe := tx.QueryRowContext(context.Background(),
				`SELECT EXISTS(SELECT 1 FROM api_tokens WHERE id = $1 AND tenant_id = $2 AND user_id = $3)`,
				tokenID, tenantID, userID,
			).Scan(&exists); qe == nil && exists {
				return ErrTokenRevoked
			}
			return ErrTokenNotFound
		}
		return nil
	})
	return err
}

// Validate resolves a plaintext token to its active record, enforcing
// prefix shape, revocation, and expiry. Used by the exchange endpoint.
func (s *Service) Validate(plaintext string) (*Token, error) {
	if !strings.HasPrefix(plaintext, TokenPrefix) || len(plaintext) < len(TokenPrefix)+32 {
		return nil, ErrMalformedToken
	}
	hash := HashToken(plaintext)

	// RLS: cross-tenant — runs on the bypass role (Phase 4). PAT validation
	// resolves the tenant FROM the presented token's hash; the tenant is the
	// query OUTPUT. Wrapping would fail closed.
	row := s.bypassDB.QueryRow(
		`SELECT id, tenant_id, user_id, name, token_prefix, permissions,
		        expires_at, last_used_at, revoked_at, created_at, token_hash
		 FROM api_tokens
		 WHERE token_hash = $1`,
		hash,
	)
	var storedHash string
	t := &Token{}
	var permsJSON []byte
	err := row.Scan(&t.ID, &t.TenantID, &t.UserID, &t.Name, &t.TokenPrefix, &permsJSON,
		&t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.CreatedAt, &storedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to look up api token: %w", err)
	}
	// The indexed equality already matched; constant-time re-compare keeps
	// the comparison hygiene explicit and guards collation surprises.
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(hash)) != 1 {
		return nil, ErrTokenNotFound
	}
	if err := json.Unmarshal(permsJSON, &t.Permissions); err != nil {
		return nil, fmt.Errorf("failed to parse token permissions: %w", err)
	}
	if t.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	return t, nil
}

// TouchLastUsed records usage, throttled to once a minute per token so the
// exchange hot path doesn't write on every request.
func (s *Service) TouchLastUsed(tokenID uuid.UUID) {
	// RLS: cross-tenant — runs on the bypass role (Phase 4). On the exchange hot
	// path the token id is known but the tenant is not threaded here (the caller
	// just validated by hash). Wrapping would fail closed.
	_, _ = s.bypassDB.Exec(
		`UPDATE api_tokens SET last_used_at = now(), updated_at = now()
		 WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds')`,
		tokenID,
	)
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanToken(r rowScanner) (*Token, error) {
	t := &Token{}
	var permsJSON []byte
	err := r.Scan(&t.ID, &t.TenantID, &t.UserID, &t.Name, &t.TokenPrefix, &permsJSON,
		&t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to scan api token: %w", err)
	}
	if err := json.Unmarshal(permsJSON, &t.Permissions); err != nil {
		return nil, fmt.Errorf("failed to parse token permissions: %w", err)
	}
	return t, nil
}
