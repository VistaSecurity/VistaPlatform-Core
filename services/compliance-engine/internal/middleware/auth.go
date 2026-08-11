package middleware

import (
	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RequireAuth delegates JWT validation to the shared middleware. It reads the
// tenant cookie pair (access_token / csrf_token) by default — use it for the
// tenant-facing /compliance-engine routes called by web-ui users.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret: jwtSecret,
		SkipPaths: []string{"/health", "/ready"},
	})
}

// RequirePlatformAuth validates platform-admin JWTs presented via the
// admin-service cookies (platform_access_token / platform_csrf_token). Use it
// for the /compliance-engine/admin routes called by admin-ui (platform) users.
//
// This MUST prefer the platform cookie: when a browser holds both the tenant
// (access_token) and platform (platform_access_token) cookies on a shared
// domain — the normal local-dev case where web-ui and admin-ui share localhost —
// the default tenant-first resolution order would authenticate an admin request
// as the tenant, and RequirePlatformAdmin would then 403 it.
func RequirePlatformAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:         jwtSecret,
		SkipPaths:         []string{"/health", "/ready"},
		AccessTokenCookie: "platform_access_token",
		CSRFCookie:        "platform_csrf_token",
	})
}

// StringifyUserID is a compatibility shim for handlers that type-assert userID/tenantID as string.
// Place this middleware immediately after RequireAuth in the chain.
func StringifyUserID() gin.HandlerFunc {
	return sharedmw.StringifyContextIDs()
}

// RequirePlatformAdmin delegates to the shared RequirePlatformAdmin middleware.
func RequirePlatformAdmin() gin.HandlerFunc {
	return sharedmw.RequirePlatformAdmin()
}
