package middleware

import (
	"os"

	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RequireAuth validates JWT tokens and sets user context.
// Delegates to the shared middleware with monitoring-service-specific configuration.
// Used for tenant-facing routes (reads the default access_token cookie).
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:      jwtSecret,
		InternalSecret: os.Getenv("INTERNAL_AUTH_SECRET"),
		SkipPaths:      []string{"/health", "/ready"},
	})
}

// RequirePlatformAuth validates platform admin JWT tokens.
// Used for platform-admin-only routes (reads platform_access_token / platform_csrf_token
// set by the admin-service, rather than the tenant access_token set by auth-service).
func RequirePlatformAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:         jwtSecret,
		InternalSecret:    os.Getenv("INTERNAL_AUTH_SECRET"),
		SkipPaths:         []string{"/health", "/ready"},
		AccessTokenCookie: "platform_access_token",
		CSRFCookie:        "platform_csrf_token",
	})
}

// RequireTenant ensures the user belongs to a tenant.
// Delegates to the shared middleware.
func RequireTenant() gin.HandlerFunc {
	return sharedmw.RequireTenant()
}

// StringifyUserID is a compatibility shim for handlers that type-assert userID/tenantID as string.
func StringifyUserID() gin.HandlerFunc {
	return sharedmw.StringifyContextIDs()
}
