package middleware

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// RequireAuth validates JWT tokens and sets user context.
// Delegates to the shared middleware with standard configuration.
//
// InternalSecret enables the HMAC-signed service-to-service path every other
// peer already uses (sensor-manager, monitoring-service, notification-service,
// device-interrogation-service, resource-tracker-service). Without it this
// service is reachable ONLY by a request carrying a person's JWT — which is
// fine while every discovery job is something a person pressed a button for,
// and is exactly what blocks the automatic active scan: the sweep runs in
// inventory-service with no browser and no user behind it.
//
// It fails CLOSED. When INTERNAL_AUTH_SECRET is unset the shared middleware
// builds no verifier at all, so an unsigned `X-Internal-Call: true` header
// authenticates nothing.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:      jwtSecret,
		InternalSecret: os.Getenv("INTERNAL_AUTH_SECRET"),
		SkipPaths:      []string{"/health", "/ready"},
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
