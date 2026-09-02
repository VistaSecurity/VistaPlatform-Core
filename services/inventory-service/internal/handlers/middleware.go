package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTClaims represents the claims in a JWT token (matching auth service)
type JWTClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
	Type     string    `json:"type"` // "access", "refresh", or "impersonation"

	// PasswordChangeRequired marks a limited session issued until the user
	// rotates an admin-forced or seeded default password. Mirrors
	// shared/models.JWTClaims + auth-service/audit-service local middleware
	// so inventory-service's own local JWT middleware enforces it
	// too — inventory-service has its own JWT middleware, not the shared one.
	PasswordChangeRequired bool `json:"pwd_change_required,omitempty"`

	jwt.RegisteredClaims
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

// internalVerifier validates HMAC-signed internal service calls.
var internalVerifier *serviceauth.Verifier

func getInternalVerifier() *serviceauth.Verifier {
	if internalVerifier == nil {
		if secret := os.Getenv("INTERNAL_AUTH_SECRET"); secret != "" {
			internalVerifier = serviceauth.NewVerifier(secret)
		}
	}
	return internalVerifier
}

var revocationCheckerFromEnv = sharedmw.RedisRevocationCheckerFromEnv

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

func JWTMiddleware(cfg *config.Config, db *database.DB) gin.HandlerFunc {
	// inventory-service has its own JWT middleware (not the shared one), so wire
	// the SAME revocation denylist here using the shared key + Redis
	// helper. nil when REDIS_URL is unset → check skipped (fail-open).
	revocation := revocationCheckerFromEnv()

	// Same reasoning for signing keys: resolved once, not per request.
	// The keyfunc picks by algorithm class — ES256 tokens resolve their `kid`
	// against the trusted public keys, HS256 tokens get the legacy shared
	// secret while one is configured.
	verifier := sharedmw.VerifierFromEnv(cfg.JWT.Secret)

	return func(c *gin.Context) {
		// Skip JWT validation for OPTIONS requests (CORS preflight)
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Allow internal service-to-service calls without auth
		if isInternalServiceCall(c) {
			c.Set("userID", "system")
			c.Set("isInternalCall", true)
			// For internal calls, tenant ID can be passed via header
			if tenantIDHeader := c.GetHeader("X-Tenant-ID"); tenantIDHeader != "" {
				if tenantUUID, err := uuid.Parse(tenantIDHeader); err == nil {
					c.Set("tenantID", tenantUUID)
				}
			}
			c.Next()
			return
		}

		// Get token from Authorization header, falling back to httpOnly cookie
		var tokenString string
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) >= 7 && authHeader[:7] == "Bearer " {
			tokenString = authHeader[7:]
		} else if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
			tokenString = cookie
			// Cookie-based requests must pass CSRF validation for state-mutating
			// methods, and the token must be SESSION-BOUND:
			// HMAC(this access token's jti), not just header == cookie.
			if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions {
				csrfHeader := c.GetHeader("X-CSRF-Token")
				csrfCookie, _ := c.Cookie("csrf_token")
				if csrfHeader == "" || csrfCookie == "" || csrfHeader != csrfCookie ||
					!sharedmw.ValidCSRFForToken(cfg.JWT.Secret, cookie, csrfHeader) {
					c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token missing or invalid"})
					c.Abort()
					return
				}
			}
		} else if pcookie, err := c.Cookie("platform_access_token"); err == nil && pcookie != "" {
			// Platform-admin cookie session (set by admin-service, distinct from the
			// tenant access_token). Lets platform admins reach the global,
			// non-tenant-scoped routes here (e.g. the algorithm source-of-truth
			// editor) — per-route RequirePlatformPermission still gates writes, and
			// tenant-scoped routes remain protected by RequireTenantPermission (a
			// platform token carries no tenant). Mirrors the platform-cookie-auth
			// pattern already in admin/artifact/auth/compliance/monitoring/etc.
			tokenString = pcookie
			if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions {
				csrfHeader := c.GetHeader("X-CSRF-Token")
				csrfCookie, _ := c.Cookie("platform_csrf_token")
				if csrfHeader == "" || csrfCookie == "" || csrfHeader != csrfCookie ||
					!sharedmw.ValidCSRFForToken(cfg.JWT.Secret, pcookie, csrfHeader) {
					c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token missing or invalid"})
					c.Abort()
					return
				}
			}
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization required"})
			c.Abort()
			return
		}

		// Parse token with structured claims (matching auth service approach)
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, verifier.Keyfunc(),
			append(verifier.ParserOptions(),
				jwt.WithIssuer("crypto-inventory-auth"), jwt.WithAudience("crypto-inventory"))...)

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Ensure it's an access or impersonation token
		if claims.Type != "access" && claims.Type != "impersonation" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
			c.Abort()
			return
		}

		// Reject tokens whose jti is on the revocation denylist — e.g. an
		// impersonation token the admin has "stopped".
		if revocation != nil && claims.ID != "" && revocation.IsRevoked(c.Request.Context(), claims.ID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
			c.Abort()
			return
		}
		if userRevocation, ok := revocation.(sharedmw.UserRevocationChecker); ok &&
			claims.UserID != uuid.Nil &&
			userRevocation.IsUserRevoked(c.Request.Context(), claims.UserID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
			c.Abort()
			return
		}

		// Limited session (forced/seeded default password not yet rotated) may
		// only reach the password-change allowlist.
		if claims.PasswordChangeRequired && !sharedmw.IsPasswordChangeAllowedPath(c.Request.URL.Path) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Password change required before this action is allowed",
				"code":  "password_change_required",
			})
			c.Abort()
			return
		}

		// Validate tenant ID exists in database — only for tenant tokens. Platform
		// tokens (admin-service) carry no tenant_id; they reach the global,
		// non-tenant-scoped routes (gated per-route by RequirePlatformPermission)
		// and must not be rejected by a tenant lookup on an empty id.
		if db != nil && claims.TenantID != uuid.Nil {
			var tenantExists bool
			query := `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1 AND deleted_at IS NULL)`
			err := db.DB.QueryRow(query, claims.TenantID).Scan(&tenantExists)
			if err != nil {
				log.Printf("[JWTMiddleware] Error checking tenant ID %s: %v", claims.TenantID, err)
				// Don't fail on DB errors, just log them
			} else if !tenantExists {
				log.Printf("[JWTMiddleware] Invalid tenant ID in token: %s (tenant does not exist)", claims.TenantID)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant"})
				c.Abort()
				return
			}
		}

		// Set context with structured claims
		c.Set("userID", claims.UserID)
		c.Set("tenantID", claims.TenantID)
		c.Set("role", claims.Role)
		c.Set("email", claims.Email)
		if claims.ID != "" {
			c.Set("jti", claims.ID)
		}

		// Extract actor claims if present (for impersonation tokens)
		extractActorClaims(c, tokenString)

		c.Next()
	}
}
