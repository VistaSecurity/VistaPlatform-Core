package middleware

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// UserType constants for distinguishing platform vs tenant users
const (
	UserTypePlatform = "platform"
	UserTypeTenant   = "tenant"
)

func RequireAuth(cfg *config.Config) gin.HandlerFunc {
	// Signing keys are resolved once, not per request: the keyfunc picks
	// by algorithm class — ES256 tokens resolve their `kid` against the trusted
	// public keys, HS256 tokens get the legacy shared secret while one is
	// configured. See shared/security/jwtkeys.
	verifier := sharedmw.VerifierFromEnv(cfg.JWT.Secret)

	return func(c *gin.Context) {
		// Skip auth for health check
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/ready" {
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
			// tenant access_token). The platform Audit section in admin-ui-v2 reads
			// the audit trail with this; downstream this middleware already defaults
			// userType=platform and skips tenant scoping for no-tenant tokens.
			// Mirrors the platform-cookie-auth pattern in the other platform services.
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

		// Use MapClaims for flexible parsing (handles both platform and tenant tokens)
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, verifier.Keyfunc(),
			append(verifier.ParserOptions(),
				jwt.WithIssuer("crypto-inventory-auth"), jwt.WithAudience("crypto-inventory"))...)

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Validate token type (must be "access" or "impersonation")
		tokenType, _ := claims["type"].(string)
		if tokenType != "access" && tokenType != "impersonation" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
			c.Abort()
			return
		}

		if passwordChangeRequired, _ := claims["pwd_change_required"].(bool); passwordChangeRequired && !sharedmw.IsPasswordChangeAllowedPath(c.Request.URL.Path) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Password change required before this action is allowed",
				"code":  "password_change_required",
			})
			c.Abort()
			return
		}

		// Extract user_id (required)
		userIDStr, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing user_id"})
			c.Abort()
			return
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: invalid user_id"})
			c.Abort()
			return
		}

		// Extract email and role
		email, _ := claims["email"].(string)
		role, _ := claims["role"].(string)

		// Determine user type based on tenant_id
		// Platform users have uuid.Nil or no tenant_id
		var tenantID uuid.UUID
		userType := UserTypePlatform // default to platform

		if tenantIDStr, ok := claims["tenant_id"].(string); ok && tenantIDStr != "" {
			if parsed, err := uuid.Parse(tenantIDStr); err == nil {
				// Check if it's uuid.Nil (all zeros)
				if parsed != uuid.Nil {
					tenantID = parsed
					userType = UserTypeTenant
				}
			}
		}

		// Set user context
		c.Set("userID", userID)
		c.Set("email", email)
		c.Set("role", role)
		c.Set("userType", userType)
		c.Set("tokenType", tokenType)

		// Only set tenantID for tenant users
		if userType == UserTypeTenant {
			c.Set("tenantID", tenantID)
		}

		// Check for impersonation context
		if tokenType == "impersonation" {
			if actorClaims, ok := claims["act"].(map[string]interface{}); ok {
				c.Set("actorID", actorClaims["sub"])
				c.Set("actorEmail", actorClaims["email"])
				c.Set("impersonationReason", actorClaims["reason"])
			}
		}

		c.Next()
	}
}

// RequirePermission gates a route on a permission.
//
// TENANT users resolve through the platform's real RBAC store: the check is
// delegated to sharedrbac.RequireTenantPermission, which asks
// user_has_permission(user, tenant, permission) — i.e. the grants in
// tenant_role_permissions. Until this middleware ran a private permission
// system: a hardcoded switch on the ROLE NAME granting any `audit.*` by prefix
// to tenant_admin, and `audit.read`/`audit.security`/`audit.export` to
// security_admin. Those four strings existed in no registry (seed.sql
// tenant_permissions, shared/rbac/permissions.go,
// packages/primitives/src/rbac/constants.ts) and never touched
// tenant_role_permissions, so no tenant could grant audit access to anyone, the
// permission-parity audit could not see these routes, and tenant custom roles
// would have had zero effect here. The permissions are now
// rbac.PermissionAuditRead / rbac.PermissionAuditManage, seeded and granted like
// every other tenant permission.
//
// PLATFORM users stay ROLE-BASED, deliberately. The platform Audit section in
// admin-ui-v2 authenticates with a no-tenant token, so there is no tenant to
// resolve tenant_role_permissions against — RequireTenantPermission would 401
// on the missing tenantID for every platform admin. platform_permissions has no
// audit.* rows either, so there is nothing to check against on that side yet.
// The branch below is byte-for-byte the pre- platform logic, so the
// platform half of this middleware is unchanged in behaviour.
func RequirePermission(db *sql.DB, permission string) gin.HandlerFunc {
	// Built once, not per request: it opens no connections, it only closes over
	// the pool. Nil db yields a 503 gate (see sharedrbac), which is the correct
	// fail-closed answer for a service that cannot reach its RBAC store.
	tenantGate := sharedrbac.RequireTenantPermission(db, permission)

	return func(c *gin.Context) {
		userType, exists := c.Get("userType")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		if userType != UserTypePlatform {
			tenantGate(c)
			return
		}

		role, _ := c.Get("role")
		roleStr, _ := role.(string)

		allowed := false
		switch roleStr {
		case "super_admin":
			allowed = true // Super admins have all permissions
		case "platform_admin":
			// Platform admins have platform.audit and related permissions
			allowed = strings.HasPrefix(permission, "platform.") ||
				strings.HasPrefix(permission, "audit.") ||
				permission == "platform_users.manage"
		case "support_admin":
			// Support admins have read-only audit access
			allowed = permission == "platform.audit" ||
				permission == rbac.PermissionAuditRead ||
				permission == "platform.audit.read"
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":      "Permission denied",
				"permission": permission,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetUserType retrieves the user type from context
func GetUserType(c *gin.Context) string {
	if userType, exists := c.Get("userType"); exists {
		if ut, ok := userType.(string); ok {
			return ut
		}
	}
	return ""
}

// GetTenantID retrieves the tenant ID from context (only for tenant users).
// Delegates to shared middleware for type-safe extraction.
func GetTenantID(c *gin.Context) *uuid.UUID {
	if tid, ok := sharedmw.GetTenantIDFromContext(c); ok {
		return &tid
	}
	return nil
}

// GetUserID retrieves the user ID from context
func GetUserID(c *gin.Context) uuid.UUID {
	if userID, exists := c.Get("userID"); exists {
		if uid, ok := userID.(uuid.UUID); ok {
			return uid
		}
	}
	return uuid.Nil
}

// RequireInternalAuth validates HMAC-signed service-to-service requests.
// Requires the caller to sign requests using shared/serviceauth with INTERNAL_AUTH_SECRET.
func RequireInternalAuth(internalSecret string) gin.HandlerFunc {
	var verifier *serviceauth.Verifier
	if internalSecret != "" {
		verifier = serviceauth.NewVerifier(internalSecret)
	}

	return func(c *gin.Context) {
		if verifier == nil {
			// No secret configured — reject all requests in production
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Internal auth not configured"})
			c.Abort()
			return
		}

		if !verifier.Verify(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid internal service signature"})
			c.Abort()
			return
		}

		c.Set("isInternalCall", true)
		c.Next()
	}
}
