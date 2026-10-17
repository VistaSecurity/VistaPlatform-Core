package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimCableRoutes mounts cables and cable traces (DCIM BUILD_PLAN row
// 3.2) and the approval of LLDP / CDP proposed cables (row 3.3) under /inventory-service/dcim on the JWT-authenticated v2 group: reads
// behind dcim.read, writes behind dcim.manage, changes.Middleware putting the
// actor and request id on the context for the change record.
//
// One literal registration per route, so the spec-route scanner sees each
// path. main() calls this; dcim_cable_routes_test.go drives the same function.
func mountDcimCableRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.CableHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/cables", read, h.List)
	d.POST("/cables", manage, h.Create)
	d.GET("/cables/:id", read, h.Get)
	d.PATCH("/cables/:id", manage, h.Update)
	d.DELETE("/cables/:id", manage, h.Delete)
	d.POST("/cables/:id/approve", manage, h.Approve)
	d.POST("/cables/:id/reject", manage, h.Reject)
	d.GET("/interfaces/:id/trace", read, h.Trace("interfaces"))
	d.GET("/front-ports/:id/trace", read, h.Trace("front-ports"))
	d.GET("/rear-ports/:id/trace", read, h.Trace("rear-ports"))
	d.GET("/console-ports/:id/trace", read, h.Trace("console-ports"))
	d.GET("/console-server-ports/:id/trace", read, h.Trace("console-server-ports"))
	d.GET("/circuit-terminations/:id/trace", read, h.Trace("circuit-terminations"))
	// The faceplate's crypto overlay (row 3.4).
	d.GET("/assets/:id/interface-posture", read, h.InterfacePosture)
}
