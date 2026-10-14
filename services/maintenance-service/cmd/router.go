package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/handlers"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// apiPrefix is the route prefix the registry assigns this service
// (standards/service-registry.yaml route_prefix, under /api/v1).
const apiPrefix = "/api/v1/" + handlers.ServiceName

// adminPrefix is the platform-admin surface. /maintenance-service/admin/ is on
// the registry's admin plane, so the edge serves it on the admin host only.
const adminPrefix = apiPrefix + "/admin/maintenance"

// newAuthMiddleware is the platform-admin session gate — the same shared
// middleware and the same platform cookie pair monitoring-service's
// /admin-service/status routes use (internal/middleware.RequirePlatformAuth
// there), with two deliberate tightenings for a surface that can rewrite the
// cluster and export the database:
//
//   - no InternalSecret: an HMAC service call is NOT a session here. No service
//     calls these routes, and the rbac gate below waives its permission check
//     for internal calls, so honouring HMAC would let any holder of the one
//     shared INTERNAL_AUTH_SECRET start an update.
//   - StrictCookiePair, as admin-service sets it: an expired platform session
//     must not fall back to a tenant cookie on a shared parent domain.
//
// Revocation is read from REDIS_URL by the shared middleware, which is why the
// registry gives this service a redis dependency (the class of bug).
func newAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:         jwtSecret,
		SkipPaths:         []string{"/health", "/ready"},
		AccessTokenCookie: "platform_access_token",
		CSRFCookie:        "platform_csrf_token",
		StrictCookiePair:  true,
	})
}

// newRouter builds the router main() serves: audit logging, probes, and the
// authenticated platform-admin group.
//
// It takes the auth middleware and the RBAC database as arguments so a test
// drives the REAL router and the REAL permission gate (router_test.go) — the
// wiring, not a helper, is what the tests pin.
//
// Reads are under platform.health, as System Health's are; every write verb is
// under platform.maintenance (spec §1 Actor + RBAC).
func newRouter(h *handlers.Handlers, auditMW *auditmiddleware.Middleware, auth gin.HandlerFunc, rbacDB *sql.DB, ops *maintenanceOps) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(sharedmw.SecurityHeaders())
	attachAuditLogging(router, auditMW)

	router.GET("/health", h.Health)
	router.GET("/ready", h.Ready)

	read := sharedrbac.RequirePlatformPermission(rbacDB, rbac.PermissionPlatformHealth)
	write := sharedrbac.RequirePlatformPermission(rbacDB, rbac.PermissionPlatformMaintenance)

	admin := router.Group(adminPrefix)
	admin.Use(auth)

	admin.GET("/status", read, h.Status)

	admin.GET("/updates", read, h.UpdateStatus)
	admin.POST("/updates/check", write, h.CheckForUpdates)
	mountUpgradeRoutes(admin, read, write, ops)
	mountBackupRoutes(admin, read, write, ops)

	return router
}

// newProbeRouter serves the plaintext :8080 listener kubelet probes when the
// API listener is mTLS-only (kubelet cannot present a client certificate). It
// is a separate engine so the plaintext port never exposes the API group.
func newProbeRouter(h *handlers.Handlers) *gin.Engine {
	probe := gin.New()
	probe.Use(gin.Recovery())
	probe.GET("/health", h.Health)
	probe.GET("/ready", h.Ready)
	return probe
}
