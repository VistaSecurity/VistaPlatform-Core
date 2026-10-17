package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimConfigContextRoutes mounts config contexts (DCIM BUILD_PLAN row 5.3)
// under /inventory-service/dcim on the JWT-authenticated v2 group: reads behind
// dcim.read, writes behind dcim.manage, with changes.Middleware attributing
// every change. One literal registration per route (shared/api/spectest).
func mountDcimConfigContextRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.ConfigContextHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/config-contexts", read, h.List)
	d.POST("/config-contexts", manage, h.Create)
	d.GET("/config-contexts/:id", read, h.Get)
	d.PATCH("/config-contexts/:id", manage, h.Update)
	d.DELETE("/config-contexts/:id", manage, h.Delete)
	d.GET("/assets/:id/config-context", read, h.Render)
}
