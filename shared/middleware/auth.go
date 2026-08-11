package middleware

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// RevokedTokenKeyPrefix is the Redis key prefix for the JWT revocation denylist.
// It is the single source of truth for the key format and is shared verbatim
// with auth-service (see services/auth-service/internal/middleware/revocation.go
// and auth.AuthService.RevokeJTI) so a jti revoked by auth-service is honored by
// every service that validates JWTs through this middleware.
const RevokedTokenKeyPrefix = "revoked_token:"

// RevokedTokenKey builds the denylist Redis key for a token's jti.
func RevokedTokenKey(jti string) string { return RevokedTokenKeyPrefix + jti }

// RevocationChecker reports whether a token (identified by its jti) is on the
// revocation denylist. Implementations must fail OPEN (return false) on backend
// errors so a Redis outage degrades to "not revoked" rather than locking
// everyone out.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) bool
}

// AuthConfig configures the shared JWT authentication middleware.
type AuthConfig struct {
	// JWTSecret is the LEGACY shared HMAC secret.
	//
	// It is no longer how tokens ought to be verified — see Verifier — but it is
	// still needed for two things during the migration: verifying HS256 tokens
	// issued before the cutover, and the legacy HMAC(jti) CSRF derivation for
	// those same tokens. Once every pre-cutover session has expired and
	// JWT_PUBLIC_KEYS / JWT_JWKS_URL are in place this can be left empty, at
	// which point a leaked JWT_SECRET forges nothing.
	JWTSecret string

	// Verifier resolves a token's signing key from the trusted PUBLIC key set,
	// falling back to the legacy shared secret while one is configured.
	//
	// When nil, RequireJWTAuth builds one from the environment
	// (JWT_PUBLIC_KEYS / JWT_JWKS_URL, with JWTSecret as the legacy fallback),
	// so every service that already uses this middleware gains asymmetric
	// verification with no per-service wiring — the same pattern the revocation
	// checker uses.
	Verifier *jwtkeys.Verifier

	// RequireIssuer validates the "iss" claim if non-empty. Recommended: "crypto-inventory-auth".
	RequireIssuer string

	// RequireAudience validates the "aud" claim if non-empty. Recommended: "crypto-inventory".
	RequireAudience string

	// InternalSecret enables HMAC-signed service-to-service call bypass when non-empty.
	// Internal calls are verified via shared/serviceauth and skip JWT validation.
	InternalSecret string

	// SkipPaths lists URL paths that bypass authentication entirely (e.g., "/health", "/ready").
	SkipPaths []string

	// SkipAuthIf, when non-nil, skips JWT validation when it returns true (path, method, etc.).
	// Use for method-specific public routes instead of adding those paths to SkipPaths.
	SkipAuthIf func(c *gin.Context) bool

	// AllowedTokenTypes restricts which token types are accepted.
	// Defaults to ["access"] if empty. Set to ["access", "impersonation"] for services
	// that support admin impersonation.
	AllowedTokenTypes []string

	// AccessTokenCookie overrides the httpOnly access-token cookie name.
	// Defaults to "access_token" when empty. Set to "platform_access_token" for the
	// admin-service, which must use distinct cookie names to avoid colliding with the
	// tenant auth-service cookies that share the same domain.
	AccessTokenCookie string

	// CSRFCookie overrides the CSRF cookie name used for the double-submit check.
	// Defaults to "csrf_token" when empty. Must match the non-httpOnly cookie that
	// the server sets alongside the access token.
	CSRFCookie string

	// StrictCookiePair, when true, restricts cookie auth to the configured
	// (AccessTokenCookie, CSRFCookie) pair ONLY — the well-known alternate pair is
	// NOT appended as a fallback. Use this for platform-admin routes: on a shared
	// parent domain the browser sends BOTH the platform and tenant cookie sets, and
	// the fallback would authenticate an expired platform session as the still-valid
	// tenant identity (→ a confusing 403 with a tenant_id instead of a clean 401
	// that lets the UI refresh/re-login). Bearer tokens are unaffected. Leave false
	// for tenant-default services so admin-ui (carrying platform cookies) can still
	// reach them via the fallback.
	StrictCookiePair bool

	// RevocationChecker, when non-nil, is consulted after a token validates: if
	// it reports the token's jti revoked, the request is rejected with 401. When
	// nil, RequireJWTAuth auto-builds a Redis-backed checker from the REDIS_URL
	// environment variable, so every service that uses this middleware honors
	// the revocation denylist with no extra wiring. If REDIS_URL is unset
	// the check is skipped (fail-open — same posture as a Redis outage).
	RevocationChecker RevocationChecker
}

// RequireJWTAuth returns Gin middleware that validates JWT tokens and sets
// standardized user context. It supports Bearer tokens, httpOnly cookies with
// CSRF validation, and optional HMAC-verified internal service calls.
//
// Context keys set (see context.go for helpers):
//
//	userID (uuid.UUID), tenantID (uuid.UUID), email (string), role (string),
//	userType ("platform"|"tenant"), tokenType (string), isInternalCall (bool)
func RequireJWTAuth(cfg AuthConfig) gin.HandlerFunc {
	// Pre-compute skip path set for O(1) lookup
	skipSet := make(map[string]bool, len(cfg.SkipPaths))
	for _, p := range cfg.SkipPaths {
		skipSet[p] = true
	}

	// Default allowed token types
	allowedTypes := cfg.AllowedTokenTypes
	if len(allowedTypes) == 0 {
		allowedTypes = []string{"access"}
	}

	// Cookie name defaults
	accessTokenCookie := cfg.AccessTokenCookie
	if accessTokenCookie == "" {
		accessTokenCookie = "access_token"
	}
	csrfCookie := cfg.CSRFCookie
	if csrfCookie == "" {
		csrfCookie = "csrf_token"
	}

	// Build the ordered list of (access, csrf) cookie pairs to try. The
	// explicitly-configured pair is preferred; the well-known alternate is
	// appended as a fallback so that a request carrying the "other" cookie set
	// still authenticates. This is what lets admin-ui (which holds the platform
	// cookie pair) reach services wired with the tenant default, and vice versa,
	// without a forced logout — the JWT signature/type still gates access, the
	// distinct names exist only to avoid clobbering each other on a shared domain.
	cookiePairs := []cookiePair{{access: accessTokenCookie, csrf: csrfCookie}}
	if !cfg.StrictCookiePair {
		for _, wk := range wellKnownCookiePairs {
			if wk.access != accessTokenCookie {
				cookiePairs = append(cookiePairs, wk)
			}
		}
	}
	allowedSet := make(map[string]bool, len(allowedTypes))
	for _, t := range allowedTypes {
		allowedSet[t] = true
	}

	// Pre-create internal auth verifier if configured
	var internalVerifier *serviceauth.Verifier
	if cfg.InternalSecret != "" {
		internalVerifier = serviceauth.NewVerifier(cfg.InternalSecret)
	}

	// Resolve the revocation checker once. An explicit checker (used by tests)
	// wins; otherwise build a Redis-backed one from REDIS_URL so every service
	// honors the denylist with no extra wiring. nil → check skipped.
	revocation := cfg.RevocationChecker
	if revocation == nil {
		revocation = redisRevocationCheckerFromEnv()
	}

	// Resolve the signing-key verifier once. An explicit one (tests, or a
	// service with bespoke key sources) wins; otherwise build it from the
	// environment so every service verifies asymmetrically with no extra wiring.
	verifier := cfg.Verifier
	if verifier == nil {
		verifier = VerifierFromEnv(cfg.JWTSecret)
	}

	// Build JWT parser options
	parserOpts := verifier.ParserOptions()
	if cfg.RequireIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(cfg.RequireIssuer))
	}
	if cfg.RequireAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(cfg.RequireAudience))
	}

	return func(c *gin.Context) {
		// Skip auth for configured paths
		if skipSet[c.Request.URL.Path] {
			c.Next()
			return
		}

		if cfg.SkipAuthIf != nil && cfg.SkipAuthIf(c) {
			c.Next()
			return
		}

		// Skip OPTIONS (CORS preflight)
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// Check for internal service-to-service call
		if internalVerifier != nil {
			internalHeader := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Internal-Call")))
			if internalHeader == "true" || internalHeader == "1" {
				if internalVerifier.Verify(c) {
					c.Set(CtxKeyIsInternalCall, true)
					c.Set(CtxKeyUserID, "system")
					// Allow tenant ID from header for internal calls
					if tenantIDHeader := c.GetHeader("X-Tenant-ID"); tenantIDHeader != "" {
						if tenantUUID, err := uuid.Parse(tenantIDHeader); err == nil {
							c.Set(CtxKeyTenantID, tenantUUID)
						}
					}
					c.Next()
					return
				}
			}
		}

		// Extract token from Bearer header or httpOnly cookie
		tokenString := extractTokenWithCookies(c, cookiePairs, cfg.JWTSecret)
		if c.IsAborted() {
			// A cookie was present but its CSRF check failed; the response is
			// already written. Don't fall through to the 401 below.
			return
		}
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
			c.Abort()
			return
		}

		// Parse and validate JWT. The keyfunc picks the key by algorithm CLASS —
		// an ES256 token resolves its `kid` against the trusted public keys, an
		// HS256 token gets the legacy shared secret if one is still configured,
		// and neither can reach the other's key material (see jwtkeys.Verifier).
		claims := &models.JWTClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, verifier.Keyfunc(), parserOpts...)

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Validate token type
		if !allowedSet[claims.Type] {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
			c.Abort()
			return
		}

		// Reject tokens whose jti is on the revocation denylist. This is
		// what makes "Stop impersonation" (and any access-token revocation) take
		// effect on the DATA PLANE, not just on auth-service's own /admin routes:
		// previously a still-valid impersonation token kept full tenant access
		// until its TTL even after the admin clicked Stop.
		if revocation != nil && claims.ID != "" && revocation.IsRevoked(c.Request.Context(), claims.ID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
			c.Abort()
			return
		}

		// Enforce the force_password_change gate server-side. A token
		// carrying pwd_change_required is a LIMITED session: the holder proved
		// knowledge of a password that must be rotated (e.g. the published
		// seeded default admin password), so nothing but the change-password
		// flow (plus session introspection and logout) is allowed until a new
		// password is set. The change-password handler re-issues clean tokens
		// on success. Normal tokens never carry the claim, so this is a no-op
		// for every existing session.
		if claims.PasswordChangeRequired && !IsPasswordChangeAllowedPath(c.Request.URL.Path) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Password change required before this action is allowed",
				"code":  "password_change_required",
			})
			c.Abort()
			return
		}

		// Determine user type based on tenant_id
		userType := UserTypePlatform
		if claims.TenantID != uuid.Nil {
			userType = UserTypeTenant
		}

		// Set standardized context
		c.Set(CtxKeyUserID, claims.UserID)
		c.Set(CtxKeyTenantID, claims.TenantID)
		c.Set(CtxKeyEmail, claims.Email)
		c.Set(CtxKeyRole, claims.Role)
		c.Set(CtxKeyUserType, userType)
		c.Set(CtxKeyTokenType, claims.Type)

		// PAT scope narrowing: when the token carries scopes (a PAT-derived
		// access token), surface them so the RBAC permission checks authorize each
		// request against intersect(role permissions, token scopes).
		if len(claims.Scopes) > 0 {
			c.Set(CtxKeyTokenScopes, append([]string(nil), claims.Scopes...))
		}

		// Extract impersonation actor claims if present
		if claims.Type == "impersonation" {
			extractImpersonationContext(c, tokenString)
		}

		c.Next()
	}
}

// passwordChangeAllowedPath matches the only routes a pwd_change_required
// (limited) token may reach: completing the forced password change,
// reading the own-session shape the UI needs to render the change-password
// interstitial, and signing out.
//
// The route prefix varies, which is why this is a pattern and not a set of
// exact strings. Both real shapes must match:
//
//	/api/v1/auth-service/auth/{me,logout,change-password}
//	/api/v1/admin-service/admin/auth/{me,logout,change-password}
//
// ...as must the un-prefixed form a service sees when called directly rather
// than through the gateway (/auth/me, /admin/auth/me).
//
// Anchored at both ends, with the prefix capped at two segments. This was a
// strings.HasSuffix test, which authorizes ANY path ending in "/auth/me"
// however deep — so a future route that happened to end that way would become
// silently reachable from a limited session. No such route exists today; the
// anchoring keeps it that way by construction rather than by luck.
var passwordChangeAllowedPath = regexp.MustCompile(
	`^(?:/api/v\d+/[A-Za-z0-9._-]+)?(?:/[A-Za-z0-9._-]+)?/auth/(?:change-password|me|logout)$`,
)

// IsPasswordChangeAllowedPath reports whether a limited (pwd_change_required)
// token may reach the given request path.
//
// Exported and shared: auth-service, audit-service and inventory-service each
// carried a byte-identical private copy of this gate and its route list. Four
// copies of one security allowlist is a drift hazard — they had not diverged
// yet, and nothing prevented it.
func IsPasswordChangeAllowedPath(path string) bool {
	return passwordChangeAllowedPath.MatchString(path)
}

// cookiePair names an httpOnly access-token cookie and its paired
// (non-httpOnly) CSRF cookie for the double-submit check.
type cookiePair struct {
	access string
	csrf   string
}

// wellKnownCookiePairs are the two cookie sets the platform issues: the tenant
// auth-service pair and the platform admin-service pair. RequireJWTAuth tries
// the configured pair first, then any of these that differ, so a request
// carrying either set authenticates regardless of which service it lands on.
var wellKnownCookiePairs = []cookiePair{
	{access: "access_token", csrf: "csrf_token"},
	{access: "platform_access_token", csrf: "platform_csrf_token"},
}

// extractTokenWithCookies gets a JWT token from the Authorization header or one of
// the named httpOnly cookies, tried in priority order. Cookie-based tokens require
// CSRF validation (against the matching CSRF cookie) for state-mutating methods.
// If a cookie is found but its CSRF check fails, the request is aborted with 403
// and the empty string is returned; callers should check c.IsAborted().
func extractTokenWithCookies(c *gin.Context, pairs []cookiePair, jwtSecret string) string {
	// Try Authorization header first
	authHeader := c.GetHeader("Authorization")
	if len(authHeader) >= 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}

	// Fall back to httpOnly cookies, in the configured-then-alternate order.
	for _, p := range pairs {
		cookie, err := c.Cookie(p.access)
		if err != nil || cookie == "" {
			continue
		}

		// Cookie-based requests must pass CSRF validation for state-mutating
		// methods, using the CSRF cookie paired with the access cookie we matched.
		// The token must also be SESSION-BOUND: it must equal
		// HMAC(this access token's jti), not just match the cookie — so a CSRF
		// token minted for another session can't be replayed here.
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions {
			csrfHeader := c.GetHeader("X-CSRF-Token")
			csrfCookieVal, _ := c.Cookie(p.csrf)
			if csrfHeader == "" || csrfCookieVal == "" || csrfHeader != csrfCookieVal ||
				!ValidCSRFForToken(jwtSecret, cookie, csrfHeader) {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token missing or invalid"})
				c.Abort()
				return ""
			}
		}

		return cookie
	}

	return ""
}

// extractImpersonationContext parses actor claims from the raw JWT payload.
// The "act" claim is a custom claim not in RegisteredClaims, so we parse the
// token payload as a generic map to extract it.
func extractImpersonationContext(c *gin.Context, tokenString string) {
	// Parse as MapClaims to access the "act" claim
	mapClaims := jwt.MapClaims{}
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, mapClaims)
	if err != nil || token == nil {
		return
	}

	actClaims, ok := mapClaims["act"].(map[string]interface{})
	if !ok || actClaims == nil {
		return
	}

	if sub, ok := actClaims["sub"].(string); ok {
		c.Set(CtxKeyActorID, sub)
	}
	if email, ok := actClaims["email"].(string); ok {
		c.Set(CtxKeyActorEmail, email)
	}
	if reason, ok := actClaims["reason"].(string); ok {
		c.Set(CtxKeyImpersonationReason, reason)
	}
}

// redisRevocationChecker is the production RevocationChecker, backed by Redis.
type redisRevocationChecker struct{ rdb *redis.Client }

func (c redisRevocationChecker) IsRevoked(ctx context.Context, jti string) bool {
	n, err := c.rdb.Exists(ctx, RevokedTokenKey(jti)).Result()
	if err != nil {
		// Fail open: a Redis outage must not lock every request out.
		logrus.WithError(err).Warn("JWT revocation denylist check failed; allowing request (fail-open)")
		return false
	}
	return n > 0
}

// NewRedisRevocationChecker wraps a Redis client as a RevocationChecker. Returns
// nil when rdb is nil (so callers can pass it straight into AuthConfig).
func NewRedisRevocationChecker(rdb *redis.Client) RevocationChecker {
	if rdb == nil {
		return nil
	}
	return redisRevocationChecker{rdb: rdb}
}

// RedisRevocationCheckerFromEnv builds a RevocationChecker from the REDIS_URL
// environment variable. Returns nil when REDIS_URL is unset or unparseable, in
// which case the revocation check is skipped (fail-open). Exposed so services
// with their own (non-shared) JWT middleware — e.g. inventory-service — can
// reuse the exact same denylist key + Redis wiring.
func RedisRevocationCheckerFromEnv() RevocationChecker {
	return redisRevocationCheckerFromEnv()
}

func redisRevocationCheckerFromEnv() RevocationChecker {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		logrus.WithError(err).Warn("REDIS_URL is unparseable; JWT revocation denylist disabled")
		return nil
	}
	return redisRevocationChecker{rdb: redis.NewClient(opt)}
}

// TokenScopesFromContext returns the PAT scope list when the request's token is
// scope-narrowed, and ok=false for a normal (unscoped) token. Set by
// RequireJWTAuth.
func TokenScopesFromContext(c *gin.Context) (scopes []string, ok bool) {
	v, exists := c.Get(CtxKeyTokenScopes)
	if !exists {
		return nil, false
	}
	s, isSlice := v.([]string)
	if !isSlice || len(s) == 0 {
		return nil, false
	}
	return s, true
}

// PermissionWithinTokenScope reports whether the given permission is allowed by
// the request's token scope. Normal (unscoped) tokens always pass. A
// scope-narrowed PAT token passes only when permission is in its scope set —
// this is the "token scopes" half of intersect(role permissions, token scopes);
// the RBAC checks supply the "role permissions" half. Callers should treat a
// false result as 403.
func PermissionWithinTokenScope(c *gin.Context, permission string) bool {
	scopes, scoped := TokenScopesFromContext(c)
	if !scoped {
		return true
	}
	for _, s := range scopes {
		if s == permission {
			return true
		}
	}
	return false
}

// RequireTenant ensures the authenticated user has a valid (non-nil) tenant ID.
// Must be used after RequireJWTAuth.
func RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := GetTenantIDFromContext(c); !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant ID required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequirePlatformAdmin ensures the authenticated user has a platform admin role.
// Accepted roles: super_admin, platform_admin, support_admin.
// Must be used after RequireJWTAuth.
func RequirePlatformAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := GetRoleFromContext(c)
		switch role {
		case "super_admin", "platform_admin", "support_admin":
			c.Next()
		default:
			c.JSON(http.StatusForbidden, gin.H{"error": "Platform admin access required"})
			c.Abort()
		}
	}
}
