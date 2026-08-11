package middleware

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// RequireAuth validates JWT tokens and sets user context.
// Supports internal service-to-service calls via HMAC verification.
// Delegates to the shared middleware with standard configuration.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:      jwtSecret,
		InternalSecret: os.Getenv("INTERNAL_AUTH_SECRET"),
		SkipPaths:      []string{"/health", "/ready"},
	})
}

// StringifyUserID is a compat middleware for handlers that type-assert userID/tenantID as string.
func StringifyUserID() gin.HandlerFunc {
	return sharedmw.StringifyContextIDs()
}

// RequireTenant ensures the user belongs to a tenant.
// Delegates to the shared middleware.
func RequireTenant() gin.HandlerFunc {
	return sharedmw.RequireTenant()
}

// GetTenantIDFromContext retrieves the tenant UUID from the Gin context.
func GetTenantIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	return sharedmw.GetTenantIDFromContext(c)
}

// GetUserIDFromContext retrieves the user UUID from the Gin context.
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	return sharedmw.GetUserIDFromContext(c)
}

// RequireInternalHMAC verifies HMAC-signed service-to-service requests
// (INTERNAL_AUTH_SECRET). HMAC-only: a user JWT does not pass. Mirrors
// sensor-manager's internal-endpoint middleware.
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
