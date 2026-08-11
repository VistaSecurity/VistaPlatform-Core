package middleware

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RequireAuth validates JWT tokens and sets user context.
// Delegates to the shared middleware with sensor-manager-specific configuration.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:      jwtSecret,
		InternalSecret: os.Getenv("INTERNAL_AUTH_SECRET"),
		SkipPaths: []string{
			"/health",
			"/ready",
		},
		SkipAuthIf: func(c *gin.Context) bool {
			return c.Request.Method == http.MethodPost && c.Request.URL.Path == "/api/v1/sensor-manager/sensors/register"
		},
	})
}

// RequirePlatformAuth validates platform-admin JWTs presented via the
// admin-service cookies (platform_access_token / platform_csrf_token). Use it
// for the /sensor-manager/admin fleet routes. Preferring the platform cookie
// prevents a tenant access_token — held alongside the platform cookie on a
// shared domain — from being resolved first and then 403'd by
// RequirePlatformAdmin.
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

// RequirePlatformAdmin ensures the caller has a platform-admin role
// (super_admin / platform_admin / support_admin). Delegates to the shared
// middleware, mirroring device-interrogation-service's platform-admin gate.
// Must be used after RequireAuth.
func RequirePlatformAdmin() gin.HandlerFunc {
	return sharedmw.RequirePlatformAdmin()
}

// RequireInternalHMAC verifies HMAC-signed service-to-service requests (INTERNAL_AUTH_SECRET).
func RequireInternalHMAC() gin.HandlerFunc {
	secret := os.Getenv("INTERNAL_AUTH_SECRET")
	if secret == "" {
		return func(c *gin.Context) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "internal authentication not configured"})
			c.Abort()
		}
	}
	verifier := serviceauth.NewVerifier(secret)
	return func(c *gin.Context) {
		if !verifier.Verify(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid internal service signature"})
			c.Abort()
			return
		}
		c.Next()
	}
}
