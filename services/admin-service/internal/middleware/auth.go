package middleware

import (
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
