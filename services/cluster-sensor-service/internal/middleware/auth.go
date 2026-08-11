package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RequireAuth validates JWT tokens and sets user context.
// Delegates to the shared middleware with standard configuration.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret: jwtSecret,
		SkipPaths: []string{"/health", "/ready"},
	})
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
