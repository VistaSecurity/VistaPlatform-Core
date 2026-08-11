package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// AuthMiddleware delegates JWT validation to the shared middleware.
// It reads from platform_access_token / platform_csrf_token — distinct cookie names
// that prevent collisions with the tenant auth-service cookies sharing the same domain.
//
// StrictCookiePair is set so platform routes accept ONLY the platform cookie pair:
// on a shared parent domain (e.g. admin.<host> + <host> both scoped to .<host>) the
// browser sends the tenant cookie set too, and the shared fallback would otherwise
// authenticate an expired platform session as the still-valid tenant identity — a
// 403-with-tenant_id that silently breaks admin writes (e.g. Settings → Email save)
// instead of a clean 401 that lets admin-ui refresh via platform_refresh_token or
// bounce to login. Tenant-facing admin routes use TenantAuthMiddleware (below),
// which keeps the fallback.
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:         jwtSecret,
		SkipPaths:         []string{"/health", "/ready"},
		AccessTokenCookie: "platform_access_token",
		CSRFCookie:        "platform_csrf_token",
		StrictCookiePair:  true,
	})
}

// TenantAuthMiddleware validates tenant JWTs presented via the auth-service
// cookies (access_token / csrf_token). Use it for admin-service routes that are
// called by web-ui (tenant) users rather than platform admins — e.g. the
// tenant-scoped billing endpoints. The default AuthMiddleware reads the distinct
// platform_* cookie names, which tenant sessions never carry.
func TenantAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret: jwtSecret,
		SkipPaths: []string{"/health", "/ready"},
		// AccessTokenCookie/CSRFCookie left empty → default to access_token / csrf_token
	})
}

// StringifyUserID is a compatibility shim for handlers that type-assert userID/tenantID as string.
// Place this middleware immediately after AuthMiddleware in the chain.
func StringifyUserID() gin.HandlerFunc {
	return sharedmw.StringifyContextIDs()
}

// PlatformAdminMiddleware delegates to the shared RequirePlatformAdmin.
func PlatformAdminMiddleware() gin.HandlerFunc {
	return sharedmw.RequirePlatformAdmin()
}

// Authorize allows only the provided platform roles to access a specific route.
// If the user's role is not in the allowed set, it returns 403.
func Authorize(allowedRoles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, r := range allowedRoles {
		allowed[r] = struct{}{}
	}
	return func(c *gin.Context) {
		roleVal, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Role not found in token"})
			c.Abort()
			return
		}
		role, ok := roleVal.(string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid role type"})
			c.Abort()
			return
		}
		if _, ok := allowed[role]; !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions for this operation"})
			c.Abort()
			return
		}
		c.Next()
	}
}
