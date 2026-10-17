package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimExportTemplateRoutes mounts export templates (DCIM BUILD_PLAN row
// 5.5) under /inventory-service/dcim on the JWT-authenticated v2 group: reads
// behind dcim.read (anyone who can export can list the templates), writes
// behind dcim.manage, with changes.Middleware attributing every change. The
// rendering routes (/export?format=template, /export/preview) are in
// dcim_bulk_routes.go. One literal registration per route (shared/api/spectest).
func mountDcimExportTemplateRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.ExportTemplateHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/export-templates", read, h.List)
	d.POST("/export-templates", manage, h.Create)
	d.GET("/export-templates/:id", read, h.Get)
	d.PATCH("/export-templates/:id", manage, h.Update)
	d.DELETE("/export-templates/:id", manage, h.Delete)
}
