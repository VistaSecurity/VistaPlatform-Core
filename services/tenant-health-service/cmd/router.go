package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/services/tenant-health-service/internal/handlers"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// newRouter builds the router main() serves: audit logging plus every route.
//
// It exists as a function so a test can drive the REAL router instead of a
// hand-built stand-in. The audit tests in audit_test.go assemble their own
// gin.Engine and call attachAuditLogging on it, so they stayed green even with
// the mount deleted from main() — the wiring, not the helper, is what has to be
// under test. Mounting inside the same function that registers the routes means
// "routes but no audit middleware" is not a state main() can reach by deleting
// a line.
func newRouter(
	healthHandlers *handlers.HealthHandlers,
	auditMiddleware *auditmiddleware.Middleware,
	jwtSecret, internalSecret string,
	db *sql.DB,
) *gin.Engine {
	router := gin.Default()

	// Audit logging — mounted before the routes so it wraps every handler.
	// See attachAuditLogging in audit.go for what is and is not recorded.
	attachAuditLogging(router, auditMiddleware)

	// Routes (auth wired inside: platform-admin JWT + platform.health gate)
	healthHandlers.RegisterRoutes(router, jwtSecret, internalSecret, db)

	return router
}
