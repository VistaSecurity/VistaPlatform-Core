package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimBulkRoutes mounts bulk CSV import and export (DCIM BUILD_PLAN row
// 2.7) under /inventory-service/dcim on the JWT-authenticated v2 group. The
// kinds list and the template are behind dcim.read. An import needs the
// kind's own write permission and an export its read permission, so those
// are asked of the gate per request by the handler: a person who may not edit
// IPAM cannot import prefixes.
//
// Export templates (row 5.5): GET /export?format=template&template_id= renders a
// stored template over the rows, gated like any export; POST /export/preview
// renders an unsaved body over five rows and needs dcim.manage.
//
// main() calls this; dcim_bulk_routes_test.go drives the same function.
func mountDcimBulkRoutes(v2 gin.IRouter, rawDB *sql.DB, store handlers.BulkStore, tpl handlers.ExportTemplateStore) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	gates := map[string]gin.HandlerFunc{}
	authorize := func(c *gin.Context, perm string) bool {
		g, ok := gates[perm]
		if !ok {
			g = sharedrbac.RequireTenantPermission(rawDB, perm)
			gates[perm] = g
		}
		g(c)
		return !c.IsAborted()
	}
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)
	h := handlers.NewBulkHandler(store, authorize).WithTemplates(tpl)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/import/kinds", read, h.Kinds)
	d.GET("/import/template", read, h.Template)
	d.POST("/import", h.Import)
	d.GET("/export", h.Export)
	d.POST("/export/preview", manage, h.Preview)
}
