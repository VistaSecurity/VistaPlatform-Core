package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimSparesRoutes mounts DCIM gap 8's spares and RMA routes — the
// install / remove / rma transitions of an inventory item and the RMA cases —
// under /inventory-service/dcim on the JWT-authenticated v2 group: reads behind
// dcim.read, writes behind dcim.manage, with changes.Middleware putting the
// actor and request id on the context for the change record. The inventory
// item CRUD itself (stock rows included) is dcim_hardware_routes.go's.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// dcim_spares_routes_test.go drives the same function over every route.
func mountDcimSparesRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.SparesHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.POST("/inventory-items/:id/install", manage, h.Install)
	d.POST("/inventory-items/:id/remove", manage, h.Remove)
	d.POST("/inventory-items/:id/rma", manage, h.OpenRMA)
	d.GET("/rma-cases", read, h.ListRMACases)
	d.GET("/rma-cases/:id", read, h.GetRMACase)
	d.PATCH("/rma-cases/:id", manage, h.UpdateRMACase)
}
