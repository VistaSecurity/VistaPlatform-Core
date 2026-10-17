package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimInterfaceRoutes mounts interfaces (DCIM BUILD_PLAN row 1.2) under
// /inventory-service/dcim on the JWT-authenticated v2 group: reads behind
// dcim.read, writes behind dcim.manage (row 0.6's permissions).
// changes.Middleware puts the actor and a request id on the request context so
// every change the service records is attributed.
//
// main() calls this; dcim_interface_routes_test.go drives the same function,
// so deleting a gate fails a test.
func mountDcimInterfaceRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.InterfaceHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/interfaces", read, h.ListInterfaces)
	d.POST("/interfaces", manage, h.CreateInterface)
	d.POST("/interfaces/bulk", manage, h.BulkCreateInterfaces)
	d.GET("/interfaces/:id", read, h.GetInterface)
	d.PATCH("/interfaces/:id", manage, h.PatchInterface)
	d.DELETE("/interfaces/:id", manage, h.DeleteInterface)
	d.GET("/assets/:id/interfaces", read, h.ListAssetInterfaces)
}
