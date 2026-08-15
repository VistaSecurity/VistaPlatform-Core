package main

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/config"
	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/handlers"
	rtmiddleware "github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/middleware"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// newRouter builds the service's API router: middleware, audit logging and
// every route group. main() serves exactly what this returns.
//
// It exists as a function so a test can exercise the REAL router rather than a
// hand-built stand-in. That distinction is the whole point: the audit tests
// used to assemble their own gin.Engine and call attachAuditLogging on it, so
// deleting the mount from main() left every test — and the source-scanning
// parity guard, which still found the mount defined in audit.go — green while
// the running service audited nothing. Now the mount lives inside the same
// function that registers the routes, so a router with routes and no audit
// middleware is not a state main() can reach by deletion.
func newRouter(
	cfg *config.Config,
	resourceHandlers *handlers.ResourceHandlers,
	auditMiddleware *auditmiddleware.Middleware,
) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// CORS with origin checking.
	corsOrigins := sharedconfig.GetEnv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5174,http://localhost:3006")
	allowedOrigins := make(map[string]bool)
	for _, origin := range strings.Split(corsOrigins, ",") {
		allowedOrigins[strings.TrimSpace(origin)] = true
	}
	router.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if allowedOrigins[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Audit logging. Mounted before the route groups so it wraps every handler
	// registered below. Which surfaces are audited (and which one is not) is
	// decided in audit.go — see attachAuditLogging.
	attachAuditLogging(router, auditMiddleware)

	// Health check endpoint
	router.GET("/health", resourceHandlers.HealthCheck)

	// Internal routes (HMAC-only, for service-to-service metrics ingestion)
	internal := router.Group("/api/v1/resource-tracker")
	internal.Use(rtmiddleware.RequireInternalAuth(cfg.InternalAuthSecret))
	{
		internal.POST("/metrics", resourceHandlers.RecordResourceMetrics)
	}

	// Authenticated API routes (JWT auth required)
	api := router.Group("/api/v1/resource-tracker")
	api.Use(rtmiddleware.RequireAuth(cfg.JWTSecret, cfg.InternalAuthSecret))
	{
		// Tenant-specific endpoints
		api.GET("/tenants/:tenantId/usage", resourceHandlers.GetTenantResourceUsage)
		api.GET("/tenants/:tenantId/trend", resourceHandlers.GetTenantResourceTrend)
		api.GET("/tenants/:tenantId/cost-trend", resourceHandlers.GetTenantCostTrend)
		api.GET("/tenants/:tenantId/cost-analysis", resourceHandlers.GenerateCostAnalysis)

		// Platform-wide endpoints (accessible by platform admins only via handler checks)
		api.GET("/tenants/usage", resourceHandlers.GetAllTenantsResourceUsage)
		api.GET("/stats", resourceHandlers.GetResourceUsageStats)
	}

	// Resource-tracker-service namespace routes (for gateway routing)
	// Internal endpoint for tenant-health-service (HMAC auth)
	serviceInternal := router.Group("/api/v1/resource-tracker-service")
	serviceInternal.Use(rtmiddleware.RequireAuth(cfg.JWTSecret, cfg.InternalAuthSecret))
	{
		// Tenant resource health endpoints - accessible via internal calls or JWT
		serviceInternal.GET("/tenant/:id/resource-summary", resourceHandlers.GetTenantResourceHealthSummary)

		// Platform-wide endpoints - MUST come before parameterized routes to avoid route conflicts
		serviceInternal.GET("/stats", resourceHandlers.GetResourceUsageStats)
		serviceInternal.GET("/tenants/usage", resourceHandlers.GetAllTenantsResourceUsage)

		// Tenant-specific endpoints - Exposed through gateway (after non-parameterized routes)
		serviceInternal.GET("/tenants/:tenantId/usage", resourceHandlers.GetTenantResourceUsage)
		serviceInternal.GET("/tenants/:tenantId/trend", resourceHandlers.GetTenantResourceTrend)
		serviceInternal.GET("/tenants/:tenantId/cost-trend", resourceHandlers.GetTenantCostTrend)
		serviceInternal.GET("/tenants/:tenantId/cost-analysis", resourceHandlers.GenerateCostAnalysis)
	}

	return router
}
