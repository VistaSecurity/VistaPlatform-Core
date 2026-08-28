package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
	Type     string    `json:"type"` // "access" or "refresh"

	// TokenType + Scopes mark a PAT-derived, scope-narrowed access token.
	// Empty on normal login tokens. Mirrors shared/models.JWTClaims.
	TokenType string   `json:"token_type,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`

	// PasswordChangeRequired marks a limited session issued until the user
	// rotates an admin-forced or seeded default password. Mirrors
	// shared/models.JWTClaims so auth-service local middleware enforces it too.
	PasswordChangeRequired bool `json:"pwd_change_required,omitempty"`

	// CSRF carries the session's double-submit value. It used to be
	// derived as HMAC(jti) keyed by the shared JWT secret, which meant every
	// VERIFYING service needed that secret — defeating the point of moving
	// signing to asymmetric keys. Carrying it inside the token instead makes it
	// unforgeable without forging the token, and needs no shared secret at all.
	// Empty on refresh tokens, which are never presented from a browser form.
	CSRF string `json:"csrf,omitempty"`

	jwt.RegisteredClaims
}

// ActorClaims represents the acting admin context for impersonation tokens
// Per RFC 8693 (OAuth 2.0 Token Exchange), the "act" claim identifies the acting party
type ActorClaims struct {
	Sub    string `json:"sub"`    // Admin user ID
	Email  string `json:"email"`  // Admin email
	Reason string `json:"reason"` // Impersonation reason
	IP     string `json:"ip"`     // Admin IP address
	UA     string `json:"ua"`     // Admin user agent (truncated)
}

// ImpersonationClaims extends JWTClaims with actor context for impersonation tokens
type ImpersonationClaims struct {
	UserID   uuid.UUID    `json:"user_id"`
	TenantID uuid.UUID    `json:"tenant_id"`
	Email    string       `json:"email"`
	Role     string       `json:"role"`
	Type     string       `json:"type"`
	Actor    *ActorClaims `json:"act,omitempty"` // Actor context for impersonation
	// CSRF mirrors JWTClaims.CSRF: an impersonation token is an access
	// token presented from a browser, so it needs the same binding.
	CSRF string `json:"csrf,omitempty"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token operations.
//
// Signing: when signer is non-nil, tokens are ES256 carrying a `kid`
// header and only auth-service holds the private key. When it is nil — no key
// material provisioned — it falls back to legacy shared-secret HS256 so an
// existing deployment keeps working across the upgrade. Verification accepts
// both generations for as long as secretKey is set.
type JWTService struct {
	secretKey     []byte
	signer        *jwtkeys.Signer
	verifier      *jwtkeys.Verifier
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// NewJWTService creates a JWT service using only the legacy shared secret.
// Retained for tests and callers with no key material.
func NewJWTService(secretKey string, accessExpiry, refreshExpiry time.Duration) *JWTService {
	return NewJWTServiceWithKeys(secretKey, nil, accessExpiry, refreshExpiry)
}

// NewJWTServiceWithKeys creates a JWT service that signs asymmetrically when a
// signer is supplied, and verifies both generations during the migration.
func NewJWTServiceWithKeys(secretKey string, signer *jwtkeys.Signer, accessExpiry, refreshExpiry time.Duration) *JWTService {
	return &JWTService{
		secretKey:     []byte(secretKey),
		signer:        signer,
		verifier:      sharedmw.VerifierFromEnv(secretKey),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

// SigningKID reports the key currently signing, or "" on the legacy HS256 path.
// Logged at startup so "which key is this pod signing with" — the first
// question during a rotation — needs no pod exec to answer.
func (j *JWTService) SigningKID() string { return j.signer.ActiveKID() }

// sign emits ES256 when a signing key is configured and legacy HS256 otherwise.
// Every mint in this file goes through here, so the algorithm is decided in
// exactly one place.
func (j *JWTService) sign(claims jwt.Claims) (string, error) {
	if j.signer != nil {
		return j.signer.Sign(claims)
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(j.secretKey)
}

// newCSRF mints the per-session double-submit value embedded in access tokens.
// A failure is not fatal: an empty claim routes CSRF validation back to the
// legacy HMAC(jti) path, which still works while the shared secret exists.
// csrfIfAccess returns a fresh CSRF value for access tokens and "" for refresh
// tokens, which are exchanged server-side and never carry a double-submit.
func csrfIfAccess(tokenType string) string {
	if tokenType != "access" {
		return ""
	}
	return newCSRF()
}

func newCSRF() string {
	v, err := sharedmw.NewCSRFClaim()
	if err != nil {
		return ""
	}
	return v
}

// GenerateTokens generates both access and refresh tokens
func (j *JWTService) GenerateTokens(userID, tenantID uuid.UUID, email, role string) (string, string, error) {
	return j.GenerateTokensWithRefreshExpiry(userID, tenantID, email, role, j.refreshExpiry)
}

// GenerateTokensWithRefreshExpiry generates both access and refresh tokens,
// using a caller-resolved refresh lifetime for policy-controlled sessions.
func (j *JWTService) GenerateTokensWithRefreshExpiry(userID, tenantID uuid.UUID, email, role string, refreshExpiry time.Duration) (string, string, error) {
	// Generate access token
	accessToken, err := j.generateToken(userID, tenantID, email, role, "access", j.accessExpiry)
	if err != nil {
		return "", "", err
	}

	// Generate refresh token
	refreshToken, err := j.generateToken(userID, tenantID, email, role, "refresh", refreshExpiry)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// generateToken generates a JWT token with the given parameters
func (j *JWTService) generateToken(userID, tenantID uuid.UUID, email, role, tokenType string, expiry time.Duration) (string, error) {
	now := time.Now()
	jti := uuid.NewString()
	claims := JWTClaims{
		UserID:   userID,
		TenantID: tenantID,
		Email:    email,
		Role:     role,
		Type:     tokenType,
		// Only access tokens are ever presented from a browser, so only they
		// need a double-submit value.
		CSRF: csrfIfAccess(tokenType),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "crypto-inventory-auth",
			Audience:  jwt.ClaimStrings{"crypto-inventory"},
			ID:        jti,
		},
	}

	return j.sign(claims)
}

// GenerateAccessTokenWithTTL generates an access token with a custom TTL and returns token, expiry, and jti
func (j *JWTService) GenerateAccessTokenWithTTL(userID, tenantID uuid.UUID, email, role string, ttl time.Duration) (string, time.Time, string, error) {
	now := time.Now()
	jti := uuid.NewString()
	claims := JWTClaims{
		UserID:   userID,
		TenantID: tenantID,
		Email:    email,
		Role:     role,
		Type:     "access",
		CSRF:     newCSRF(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "crypto-inventory-auth",
			Audience:  jwt.ClaimStrings{"crypto-inventory"},
			ID:        jti,
		},
	}

	signed, err := j.sign(claims)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return signed, now.Add(ttl), jti, nil
}

// GenerateScopedAccessTokenWithTTL mints an access token narrowed to a PAT's
// scopes. It is a normal access token (Type "access", so existing
// token-type checks pass) additionally carrying token_type "pat" + the scope
// list, which the shared middleware intersects with the user's role
// permissions on every request. Returns token, expiry, and jti.
func (j *JWTService) GenerateScopedAccessTokenWithTTL(userID, tenantID uuid.UUID, email, role string, scopes []string, ttl time.Duration) (string, time.Time, string, error) {
	now := time.Now()
	jti := uuid.NewString()
	claims := JWTClaims{
		UserID:    userID,
		TenantID:  tenantID,
		Email:     email,
		Role:      role,
		Type:      "access",
		TokenType: "pat",
		Scopes:    scopes,
		CSRF:      newCSRF(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "crypto-inventory-auth",
			Audience:  jwt.ClaimStrings{"crypto-inventory"},
			ID:        jti,
		},
	}

	signed, err := j.sign(claims)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return signed, now.Add(ttl), jti, nil
}

// GenerateImpersonationToken generates an access token for impersonation with actor claims
// The token represents the target user but includes actor context identifying the admin
func (j *JWTService) GenerateImpersonationToken(
	targetUserID, targetTenantID uuid.UUID,
	targetEmail, targetRole string,
	actorID, actorEmail, reason, actorIP, actorUA string,
	ttl time.Duration,
) (string, time.Time, string, error) {
	now := time.Now()
	jti := uuid.NewString()

	// Truncate user agent to prevent token bloat
	if len(actorUA) > 100 {
		actorUA = actorUA[:100] + "..."
	}

	claims := ImpersonationClaims{
		UserID:   targetUserID,
		TenantID: targetTenantID,
		Email:    targetEmail,
		Role:     targetRole,
		Type:     "impersonation",
		CSRF:     newCSRF(),
		Actor: &ActorClaims{
			Sub:    actorID,
			Email:  actorEmail,
			Reason: reason,
			IP:     actorIP,
			UA:     actorUA,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   targetUserID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "crypto-inventory-auth",
			Audience:  jwt.ClaimStrings{"crypto-inventory"},
			ID:        jti,
		},
	}

	signed, err := j.sign(claims)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return signed, now.Add(ttl), jti, nil
}

// ValidateToken validates and parses a JWT token
func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Key selection is by algorithm CLASS: an ES256 token resolves its
	// `kid` against the trusted public keys, an HS256 token gets the legacy
	// shared secret while one is configured, and neither can reach the other's
	// key material. See shared/security/jwtkeys.Verifier.
	opts := append(j.verifier.ParserOptions(),
		jwt.WithIssuer("crypto-inventory-auth"), jwt.WithAudience("crypto-inventory"))
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, j.verifier.Keyfunc(), opts...)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GetAccessExpiry returns the access token expiry duration
func (j *JWTService) GetAccessExpiry() time.Duration {
	return j.accessExpiry
}

// GetRefreshExpiry returns the refresh token expiry duration
func (j *JWTService) GetRefreshExpiry() time.Duration {
	return j.refreshExpiry
}
