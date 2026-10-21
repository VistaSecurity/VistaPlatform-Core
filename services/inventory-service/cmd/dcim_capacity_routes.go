package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimCapacityRoutes mounts the facilities capacity roll-up (the
// Facilities dashboard's one read) under /inventory-service/dcim on the
// JWT-authenticated v2 group, behind dcim.read. It is a read of caches and
// counts, so there is no write and no change recording.
//
// main() calls this; dcim_capacity_routes_test.go drives the same function.
func mountDcimCapacityRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.CapacityHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)

	d := v2.Group("/inventory-service/dcim")
	d.GET("/capacity", read, h.Get)
}
