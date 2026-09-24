package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/middleware"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// registerAdminFleetRoutes mounts the platform operator's cross-tenant Fleet
// view. No tenant context: it rolls up sensors across ALL tenants and
// deliberately omits the tenant filter that isolates the tenant-scoped
// /sensors list, so it must never be reachable by a tenant token.
//
// Gated on a PLATFORM identity holding platform.health — the permission
// admin-ui-v2 gates the Fleet section on, resolved through
// platform_user_has_permission() rather than the role name on the token (the
// old role-name check admitted a "support_admin" that has never been seeded,
// and refused the real support_agent whose grants include platform.health).
// device-interrogation-service's /admin/agents, the other half of the Fleet
// page, carries the same permission.
//
// main() and the gate tests both call this, so the tests drive the real route
// table rather than a copy of it.
func registerAdminFleetRoutes(api *gin.RouterGroup, jwtSecret string, db *sql.DB, listSensors gin.HandlerFunc) {
	adminFleet := api.Group("/sensor-manager/admin")
	adminFleet.Use(middleware.RequirePlatformAuth(jwtSecret))
	adminFleet.Use(sharedmw.RequirePlatformAdmin(db, rbac.PermissionPlatformHealth))
	adminFleet.GET("/sensors", listSensors)
}
