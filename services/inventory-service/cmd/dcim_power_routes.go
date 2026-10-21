package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimPowerRoutes mounts power panels, power feeds, the per-asset
// power summary (DCIM BUILD_PLAN row 6.1; ADR-0010 D9) and the rack power
// budget (row 6.2) under
// /inventory-service/dcim on the JWT-authenticated v2 group: reads behind
// dcim.read, writes behind dcim.manage, with changes.Middleware putting the
// actor and request id on the context for the change record. The power
// traces are mounted with the other traces (dcim_cable_routes.go).
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// dcim_power_routes_test.go drives the same function over every route.
func mountDcimPowerRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.PowerHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/power-panels", read, h.List("power-panels"))
	d.POST("/power-panels", manage, h.Create("power-panels"))
	d.GET("/power-panels/:id", read, h.Get("power-panels"))
	d.PATCH("/power-panels/:id", manage, h.Update("power-panels"))
	d.DELETE("/power-panels/:id", manage, h.Delete("power-panels"))
	d.GET("/power-feeds", read, h.List("power-feeds"))
	d.POST("/power-feeds", manage, h.Create("power-feeds"))
	d.GET("/power-feeds/:id", read, h.Get("power-feeds"))
	d.PATCH("/power-feeds/:id", manage, h.Update("power-feeds"))
	d.DELETE("/power-feeds/:id", manage, h.Delete("power-feeds"))
	d.GET("/assets/:id/power", read, h.AssetPower)
	d.GET("/racks/:id/power", read, h.RackPower)
}
