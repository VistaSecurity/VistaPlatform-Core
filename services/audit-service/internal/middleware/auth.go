package middleware

import (
	"database/sql"
	"net/http"

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

var revocationCheckerFromEnv = sharedmw.RedisRevocationCheckerFromEnv

// tenantStateCheckerFromEnv resolves the tenant-state check (RC-4 /) the
// same way shared RequireJWTAuth does: from DATABASE_URL. A var so tests can
// substitute a stub.
var tenantStateCheckerFromEnv = func() sharedmw.TenantStateChecker {
	return sharedmw.ResolveTenantStateChecker(nil, "audit-service")
}

func RequireAuth(cfg *config.Config) gin.HandlerFunc {
	revocation := revocationCheckerFromEnv()
	tenantState := tenantStateCheckerFromEnv()

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

		if revocation != nil {
			if jti, _ := claims["jti"].(string); jti != "" && revocation.IsRevoked(c.Request.Context(), jti) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
				c.Abort()
				return
			}
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
		if userRevocation, ok := revocation.(sharedmw.UserRevocationChecker); ok &&
			userRevocation.IsUserRevoked(c.Request.Context(), userID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked"})
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
		var tenantSessionVersion int64
		if v, ok := claims["tenant_session_version"].(float64); ok {
			tenantSessionVersion = int64(v)
		}

		// A suspended, canceled or deleted tenant is not usable (RC-4 /):
		// same check, response and exemptions as shared RequireJWTAuth.
		if !sharedmw.EnforceTenantSession(c, tenantState, tenantID, tokenType, tenantSessionVersion) {
			return
		}

		// Set user context
		c.Set("userID", userID)
		c.Set("email", email)
		c.Set("role", role)
		c.Set("userType", userType)
		c.Set("tokenType", tokenType)
		if scopes := tokenScopesFromClaims(claims); len(scopes) > 0 {
			c.Set(sharedmw.CtxKeyTokenScopes, scopes)
		}

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

func tokenScopesFromClaims(claims jwt.MapClaims) []string {
	raw, exists := claims["scopes"]
	if !exists {
		return nil
	}

	switch v := raw.(type) {
	case []string:
		return nonEmptyScopes(v)
	case []interface{}:
		scopes := make([]string, 0, len(v))
		for _, item := range v {
			scope, ok := item.(string)
			if ok && scope != "" {
				scopes = append(scopes, scope)
			}
		}
		return scopes
	default:
		return nil
	}
}

func nonEmptyScopes(in []string) []string {
	scopes := make([]string, 0, len(in))
	for _, scope := range in {
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// platformAuditGates is the platform half of RequirePermission: for each
// audit-service permission, the PLATFORM permission that answers it, asked
// through platform_user_has_permission().
//
// Until RC-3 of the admin-ui data review this branch switched on the role
// NAME — super_admin passed everything, platform_admin passed any "audit.*"
// by string prefix, and a "support_admin" that has never been seeded got read
// access. The seeded support_agent role holds platform.audit and was refused
// every read; a custom role granted platform.audit in Staff & Access ▸ Roles
// was refused too; and any role called platform_admin passed whatever its
// grants said. The answer now comes from platform_role_permissions, like
// every admin-service route.
//
// The mapping keeps the two roles the switch admitted exactly where they were:
// super_admin holds every platform permission, and platform_admin is seeded
// both platform.audit and platform.audit.manage.
//
// A permission missing from this map refuses platform callers outright — a new
// audit permission must decide what its platform counterpart is before any
// operator can reach it.
var platformAuditGates = map[string]func(db *sql.DB) gin.HandlerFunc{
	rbac.PermissionAuditRead: func(db *sql.DB) gin.HandlerFunc {
		return sharedrbac.RequirePlatformPermission(db, rbac.PermissionPlatformAudit)
	},
	rbac.PermissionAuditManage: func(db *sql.DB) gin.HandlerFunc {
		return sharedrbac.RequirePlatformPermission(db, rbac.PermissionPlatformAuditManage)
	},
}

// RequirePermission gates a route on an audit permission, for either kind of
// caller.
//
// TENANT users resolve through the platform's real RBAC store: the check is
// delegated to sharedrbac.RequireTenantPermission, which asks
// user_has_permission(user, tenant, permission) — i.e. the grants in
// tenant_role_permissions. Until this middleware ran a private permission
// system for tenants too (a role-name switch inventing audit.* strings no
// registry held); the permissions are now rbac.PermissionAuditRead /
// rbac.PermissionAuditManage, seeded and granted like every other tenant
// permission.
//
// PLATFORM users carry a no-tenant token, so there is no tenant to resolve
// tenant_role_permissions against. They resolve the platform counterpart in
// platformAuditGates through platform_user_has_permission() instead — never
// through the role name on the token.
func RequirePermission(db *sql.DB, permission string) gin.HandlerFunc {
	// Built once, not per request: they open no connections, they only close
	// over the pool. Nil db yields a 503 gate (see sharedrbac), which is the
	// correct fail-closed answer for a service that cannot reach its RBAC store.
	tenantGate := sharedrbac.RequireTenantPermission(db, permission)
	platformGate := func(c *gin.Context) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":      "Permission denied",
			"permission": permission,
		})
		c.Abort()
	}
	if mk, ok := platformAuditGates[permission]; ok {
		platformGate = mk(db)
	}

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
		platformGate(c)
	}
}

// RequirePlatformIdentity restricts a route to a PLATFORM token.
//
// SECURITY (C4/H2, v1.0.0 audit): audit.retention_policies and
// audit.siem_integrations are platform-GLOBAL configuration — neither carries a
// usable tenant scope (retention_policies has no tenant_id column at all, and
// siem_integrations' is nullable and never read), and both drive cross-tenant
// effects: the retention sweep deletes from audit.activity_logs with no tenant
// predicate on the BYPASSRLS handle, and the SIEM tee fans EVERY tenant's audit
// event out to every enabled integration.
//
// Gating them on a tenant permission therefore gated nothing that mattered:
// audit.manage is held by tenant_admin by default, so any tenant admin could
// set total_retention_days=0 and destroy every tenant's audit history within a
// day, or register a SIEM receiver for every tenant's events. Identity, not
// permission, is the axis that separates those callers — so this runs BEFORE
// the permission gate on every such route.
//
// Deliberately mirrors auth-service's middleware.RequirePlatformIdentity rather
// than inventing a second rule: an internal (HMAC-signed S2S) call passes, a
// platform token passes, anything else is refused with a message distinct from
// the permission gate's so a test can tell WHICH gate answered.
func RequirePlatformIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		if internal, _ := c.Get("isInternalCall"); internal == true {
			c.Next()
			return
		}
		if c.GetString(sharedmw.CtxKeyUserType) != sharedmw.UserTypePlatform {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Platform user required",
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
