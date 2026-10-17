package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimSubstrateRoutes mounts the DCIM object substrate (BUILD_PLAN row
// 0.3) under /inventory-service/dcim on the JWT-authenticated v2 group: reads
// behind dcim.read, writes behind dcim.manage (row 0.6's permissions).
// changes.Middleware puts the actor and a request id on the request context so
// the service layer can attribute every change it records.
//
// main() calls this; dcim_substrate_routes_test.go drives the same function,
// so deleting a gate — or the whole group's actor middleware — fails a test.
func mountDcimSubstrateRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.DcimSubstrateHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/changes", read, h.ListChanges)
	d.GET("/changes/:id", read, h.GetChange)
	d.GET("/objects/:kind/:id/journal", read, h.ListJournal)
	d.POST("/objects/:kind/:id/journal", manage, h.AddJournal)
	d.GET("/objects/:kind/:id/tags", read, h.GetObjectTags)
	d.PUT("/objects/:kind/:id/tags", manage, h.SetObjectTags)
	d.GET("/tags", read, h.ListTags)
	d.POST("/tags", manage, h.CreateTag)
	d.PATCH("/tags/:id", manage, h.UpdateTag)
	d.DELETE("/tags/:id", manage, h.DeleteTag)
}
