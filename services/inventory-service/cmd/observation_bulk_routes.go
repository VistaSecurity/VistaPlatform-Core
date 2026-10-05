package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// observationBulkChain is the middleware + handler chain of
// POST /discovery/observations/bulk: assets.update, the same bar as the
// single confirm and dismiss routes beside it, since a bulk decision is those
// decisions repeated. It is a function so main() and the route test build the
// identical chain — observation_bulk_routes_integration_test.go drives this
// against a real database, and observation_bulk_routes_test.go pins that
// main.go mounts it.
func observationBulkChain(rawDB *sql.DB, h *handlers.IdentityObservationHandler) []gin.HandlerFunc {
	return []gin.HandlerFunc{sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), h.Bulk}
}
