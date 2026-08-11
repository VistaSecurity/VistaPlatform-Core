package middleware

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RequestID adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		c.Header("X-Request-ID", requestID)
		c.Set("requestID", requestID)
		c.Next()
	}
}

// Logging provides structured logging for all requests
func Logging() gin.HandlerFunc {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Build log entry
		entry := logger.WithFields(logrus.Fields{
			"status":     c.Writer.Status(),
			"method":     c.Request.Method,
			"path":       path,
			"query":      raw,
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
			"latency":    latency,
			"request_id": c.GetString("requestID"),
		})

		if len(c.Errors) > 0 {
			entry.Error(c.Errors.String())
		} else {
			entry.Info("Request completed")
		}
	}
}

// internalVerifier validates HMAC-signed internal service calls.
var (
	internalVerifier     *serviceauth.Verifier
	internalVerifierOnce sync.Once
)

func getInternalVerifier() *serviceauth.Verifier {
	internalVerifierOnce.Do(func() {
		if secret := os.Getenv("INTERNAL_AUTH_SECRET"); secret != "" {
			internalVerifier = serviceauth.NewVerifier(secret)
		}
	})
	return internalVerifier
}

// isInternalServiceCall checks if the request is from an internal service.
// Requires HMAC-SHA256 signature verification via INTERNAL_AUTH_SECRET.
func isInternalServiceCall(c *gin.Context) bool {
	internalHeader := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Internal-Call")))
	if internalHeader != "true" && internalHeader != "1" {
		return false
	}

	// Require HMAC verification
	if v := getInternalVerifier(); v != nil {
		return v.Verify(c)
	}

	return false
}

// AuthOption configures optional RequireAuth behaviour. Default behaviour
// (no options) is the security-first one: access tokens only, internal
// HMAC-signed service calls accepted.
type AuthOption func(*authOpts)

type authOpts struct {
	allowImpersonation bool
}

// AllowImpersonation extends a route's accepted token-type allowlist from
// the default {"access"} to {"access", "impersonation"}. Use only on
// routes where a platform admin's impersonation session legitimately
// needs to act on behalf of the impersonated user.
//
// Rule of thumb: opt-in is appropriate for *read* operations and the
// impersonation-stop endpoint (so the platform admin can exit the
// impersonation cleanly). Opt-in is NOT appropriate for password change,
// account-settings writes, EULA acceptance, session revocation, or
// anything else that mutates the impersonated user's identity-bearing
// state — the impersonator's audit trail can't honestly attribute those
// changes. for the underlying audit context.
func AllowImpersonation() AuthOption {
	return func(o *authOpts) { o.allowImpersonation = true }
}

// authCookiePairs lists the two httpOnly cookie sets that may carry a session on
// a shared domain: the tenant pair (web-ui) and the platform pair (admin-ui).
// RequireAuth tries them in this order so a request authenticates regardless of
// which UI issued it. for why the platform fallback is required here.
var authCookiePairs = []struct{ access, csrf string }{
	{access: "access_token", csrf: "csrf_token"},
	{access: "platform_access_token", csrf: "platform_csrf_token"},
}

// RequireInternalOnly accepts ONLY HMAC-signed service-to-service calls
// (shared/serviceauth, INTERNAL_AUTH_SECRET). Unlike RequireAuth there is no
// JWT fallback — use it for endpoints that must never be reachable with a
// user credential, e.g. the PAT→JWT exchange consumed by mcp-service.
func RequireInternalOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isInternalServiceCall(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Internal service authorization required"})
			c.Abort()
			return
		}
		c.Set("userID", "system")
		c.Set("isInternalCall", true)
		c.Next()
	}
}

// RequireAuth validates JWT tokens and sets user context.
//
// Default accepted token types: {"access"}. Pass AllowImpersonation()
// to additionally accept {"impersonation"} — for why this is
// opt-in rather than the previous permissive default.
//
// Internal service-to-service calls (HMAC-signed via INTERNAL_AUTH_SECRET)
// are accepted without a JWT independent of these options.
func RequireAuth(cfg *config.Config, jwtService *auth.JWTService, options ...AuthOption) gin.HandlerFunc {
	opts := authOpts{}
	for _, fn := range options {
		fn(&opts)
	}
	return func(c *gin.Context) {
		// Allow internal service-to-service calls without auth
		if isInternalServiceCall(c) {
			c.Set("userID", "system")
			c.Set("isInternalCall", true)
			c.Next()
			return
		}

		// Get token from Authorization header, falling back to httpOnly cookies.
		// Both the tenant pair (access_token / csrf_token) and the platform pair
		// (platform_access_token / platform_csrf_token) are accepted so admin-ui —
		// which carries only the platform pair — can reach auth-service endpoints
		// (e.g. impersonation, platform ui-config) without a spurious 401 that the
		// frontend would misread as session-expiry and force a logout. The
		// tenant pair is tried first, so tenant (web-ui) behaviour is unchanged.
		var token string
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) >= 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		} else {
			for _, p := range authCookiePairs {
				cookie, err := c.Cookie(p.access)
				if err != nil || cookie == "" {
					continue
				}
				token = cookie

				// Cookie-based requests must pass CSRF validation for state-mutating
				// methods, using the CSRF cookie paired with the matched access
				// cookie. The token must also be SESSION-BOUND:
				// HMAC(this access token's jti), not just header == cookie.
				if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions {
					csrfHeader := c.GetHeader("X-CSRF-Token")
					csrfCookie, _ := c.Cookie(p.csrf)
					if csrfHeader == "" || csrfCookie == "" || csrfHeader != csrfCookie ||
						!sharedmw.ValidCSRFForToken(cfg.JWTSecret, cookie, csrfHeader) {
						c.JSON(http.StatusForbidden, gin.H{
							"error": "CSRF token missing or invalid",
						})
						c.Abort()
						return
					}
				}
				break
			}
		}

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization required",
			})
			c.Abort()
			return
		}

		// Validate JWT token
		claims, err := jwtService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Default: access tokens only. Routes that legitimately need
		// impersonation tokens must pass AllowImpersonation() — see
		// the option's doc comment above.
		if claims.Type != "access" && (!opts.allowImpersonation || claims.Type != "impersonation") {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token type",
			})
			c.Abort()
			return
		}

		if claims.PasswordChangeRequired && !sharedmw.IsPasswordChangeAllowedPath(c.Request.URL.Path) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Password change required before this action is allowed",
				"code":  "password_change_required",
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("userID", claims.UserID.String())
		c.Set("tenantID", claims.TenantID.String())
		c.Set("role", claims.Role)
		c.Set("email", claims.Email)
		if claims.ID != "" {
			c.Set("jti", claims.ID)
		}

		// Extract actor claims if present (for impersonation tokens)
		extractActorClaims(c, token)

		c.Next()
	}
}

// extractActorClaims parses the raw JWT token to extract actor claims for impersonation
func extractActorClaims(c *gin.Context, token string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	// Parse as generic map to extract actor claims
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(payload, &rawClaims); err != nil {
		return
	}

	// Check for actor claims
	actClaims, ok := rawClaims["act"].(map[string]interface{})
	if !ok || actClaims == nil {
		return
	}

	// Set impersonation flag and actor context
	c.Set("is_impersonation", true)

	if sub, ok := actClaims["sub"].(string); ok {
		c.Set("act.sub", sub)
	}
	if email, ok := actClaims["email"].(string); ok {
		c.Set("act.email", email)
	}
	if reason, ok := actClaims["reason"].(string); ok {
		c.Set("act.reason", reason)
	}
	if ip, ok := actClaims["ip"].(string); ok {
		c.Set("act.ip", ip)
	}
	if ua, ok := actClaims["ua"].(string); ok {
		c.Set("act.ua", ua)
	}
}

// RequireRole ensures the user has the required role
func RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "User role not found",
			})
			c.Abort()
			return
		}

		if userRole != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole ensures the user has one of the required roles.
// Internal service-to-service calls (HMAC-signed via shared INTERNAL_AUTH_SECRET)
// bypass the role check: the shared secret is itself a service-mesh credential,
// and the prior RequireAuth/JWTMiddleware step has already verified the signature.
func RequireAnyRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if internal, _ := c.Get("isInternalCall"); internal == true {
			c.Next()
			return
		}

		userRole, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "User role not found",
			})
			c.Abort()
			return
		}

		roleStr, ok := userRole.(string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid user role",
			})
			c.Abort()
			return
		}

		for _, role := range requiredRoles {
			if roleStr == role {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient permissions",
		})
		c.Abort()
	}
}

// RequireTenant ensures the user belongs to a tenant
func RequireTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, exists := c.Get("tenantID")
		if !exists || tenantID == "" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Tenant ID not found",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimiting applies rate limiting using Redis-backed token bucket.
//
// Failure semantics on Redis errors are endpoint-class-dependent:
//   - Login / password-reset / register endpoints fail CLOSED (503). A silent
//     bypass of brute-force protection during a Redis blip is exactly the
//     class of bug this middleware exists to prevent.
//   - All other endpoints fail OPEN — a transient Redis outage shouldn't
//     wedge the whole platform for everyone.
func RateLimiting(limiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant ID from context (set by RequireAuth or RequireTenant)
		// For unauthenticated requests, use client IP to avoid a single shared
		// pool that gets exhausted by any burst of anonymous traffic.
		tenantID := c.GetString("tenantID")
		if tenantID == "" {
			tenantID = "anon:" + c.ClientIP()
		}

		// Get endpoint path
		endpoint := c.Request.URL.Path

		// Check rate limit
		allowed, retryAfter, err := limiter.Allow(c.Request.Context(), tenantID, endpoint)
		if err != nil {
			if isLoginEndpoint(endpoint) {
				logrus.WithError(err).WithField("endpoint", endpoint).
					Error("Rate limiter error on auth endpoint — failing closed")
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"error": "Authentication is temporarily unavailable. Please try again shortly.",
				})
				c.Abort()
				return
			}
			logrus.WithError(err).Warn("Rate limiter error, allowing request (non-auth endpoint)")
			c.Next()
			return
		}

		if !allowed {
			// Rate limit exceeded
			c.Header("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": retryAfter.Seconds(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
