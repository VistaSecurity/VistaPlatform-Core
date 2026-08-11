package middleware

import (
	"os"

	"github.com/gin-gonic/gin"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RequireAuth validates JWT tokens and sets user context.
// Delegates to the shared middleware with device-interrogation-service-specific configuration.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:      jwtSecret,
		InternalSecret: os.Getenv("INTERNAL_AUTH_SECRET"),
		SkipPaths:      []string{"/health", "/ready"},
	})
}

// RequirePlatformAuth validates platform-admin JWTs presented via the
// admin-service cookies (platform_access_token / platform_csrf_token). The
// /admin routes nest under the tenant-default parent auth, so they layer this
// on top to re-resolve the request preferring the platform cookie — otherwise a
// tenant access_token held alongside the platform cookie on a shared domain wins
// and RequirePlatformAdmin 403's a legitimate platform admin.
func RequirePlatformAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:         jwtSecret,
		InternalSecret:    os.Getenv("INTERNAL_AUTH_SECRET"),
		SkipPaths:         []string{"/health", "/ready"},
		AccessTokenCookie: "platform_access_token",
		CSRFCookie:        "platform_csrf_token",
	})
}
