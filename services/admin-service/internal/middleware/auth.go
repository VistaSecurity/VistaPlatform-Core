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

// RequirePlatformIdentity admits a PLATFORM session and nothing else: a token
// carrying a tenant id (userType=tenant) is refused with 403 "Platform user
// required", whatever its role claim says.
//
// AuthMiddleware proves the token is a valid access JWT; it does not say whose.
// Both token families are signed by the same key set, and a Bearer header is
// not restricted by StrictCookiePair (that only narrows the cookie fallback), so
// a tenant user's token authenticates here. Every per-route gate layered on
// protected asks "does this PLATFORM user hold permission X" and refuses a
// tenant token itself -- but the handful of routes registered on the parent
// group had nothing, and were safe only because each handler happens to look
// the caller up in platform_users by id. This puts the identity decision in one
// place, in front of everything, so a handler added to the group tomorrow does
// not inherit "any valid JWT".
func RequirePlatformIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		if sharedmw.GetUserType(c) != sharedmw.UserTypePlatform {
			c.JSON(http.StatusForbidden, gin.H{"error": "Platform user required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
