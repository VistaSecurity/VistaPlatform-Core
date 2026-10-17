package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimComponentRoutes mounts the asset components beyond interfaces (DCIM
// BUILD_PLAN row 3.1) under /inventory-service/dcim on the JWT-authenticated
// v2 group: reads behind dcim.read, writes behind dcim.manage, with
// changes.Middleware putting the actor and request id on the context for the
// change record. Power ports and outlets have routes and no UI (ADR-0010 D9).
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// dcim_component_routes_test.go drives the same function over every route.
func mountDcimComponentRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.ComponentHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/console-ports", read, h.List("console-ports"))
	d.POST("/console-ports", manage, h.Create("console-ports"))
	d.GET("/console-ports/:id", read, h.Get("console-ports"))
	d.PATCH("/console-ports/:id", manage, h.Update("console-ports"))
	d.DELETE("/console-ports/:id", manage, h.Delete("console-ports"))
	d.GET("/assets/:id/console-ports", read, h.ListForAsset("console-ports"))
	d.POST("/assets/:id/console-ports", manage, h.CreateForAsset("console-ports"))
	d.GET("/console-server-ports", read, h.List("console-server-ports"))
	d.POST("/console-server-ports", manage, h.Create("console-server-ports"))
	d.GET("/console-server-ports/:id", read, h.Get("console-server-ports"))
	d.PATCH("/console-server-ports/:id", manage, h.Update("console-server-ports"))
	d.DELETE("/console-server-ports/:id", manage, h.Delete("console-server-ports"))
	d.GET("/assets/:id/console-server-ports", read, h.ListForAsset("console-server-ports"))
	d.POST("/assets/:id/console-server-ports", manage, h.CreateForAsset("console-server-ports"))
	d.GET("/front-ports", read, h.List("front-ports"))
	d.POST("/front-ports", manage, h.Create("front-ports"))
	d.GET("/front-ports/:id", read, h.Get("front-ports"))
	d.PATCH("/front-ports/:id", manage, h.Update("front-ports"))
	d.DELETE("/front-ports/:id", manage, h.Delete("front-ports"))
	d.GET("/assets/:id/front-ports", read, h.ListForAsset("front-ports"))
	d.POST("/assets/:id/front-ports", manage, h.CreateForAsset("front-ports"))
	d.GET("/rear-ports", read, h.List("rear-ports"))
	d.POST("/rear-ports", manage, h.Create("rear-ports"))
	d.GET("/rear-ports/:id", read, h.Get("rear-ports"))
	d.PATCH("/rear-ports/:id", manage, h.Update("rear-ports"))
	d.DELETE("/rear-ports/:id", manage, h.Delete("rear-ports"))
	d.GET("/assets/:id/rear-ports", read, h.ListForAsset("rear-ports"))
	d.POST("/assets/:id/rear-ports", manage, h.CreateForAsset("rear-ports"))
	d.GET("/device-bays", read, h.List("device-bays"))
	d.POST("/device-bays", manage, h.Create("device-bays"))
	d.GET("/device-bays/:id", read, h.Get("device-bays"))
	d.PATCH("/device-bays/:id", manage, h.Update("device-bays"))
	d.DELETE("/device-bays/:id", manage, h.Delete("device-bays"))
	d.GET("/assets/:id/device-bays", read, h.ListForAsset("device-bays"))
	d.POST("/assets/:id/device-bays", manage, h.CreateForAsset("device-bays"))
	d.GET("/power-ports", read, h.List("power-ports"))
	d.POST("/power-ports", manage, h.Create("power-ports"))
	d.GET("/power-ports/:id", read, h.Get("power-ports"))
	d.PATCH("/power-ports/:id", manage, h.Update("power-ports"))
	d.DELETE("/power-ports/:id", manage, h.Delete("power-ports"))
	d.GET("/assets/:id/power-ports", read, h.ListForAsset("power-ports"))
	d.POST("/assets/:id/power-ports", manage, h.CreateForAsset("power-ports"))
	d.GET("/power-outlets", read, h.List("power-outlets"))
	d.POST("/power-outlets", manage, h.Create("power-outlets"))
	d.GET("/power-outlets/:id", read, h.Get("power-outlets"))
	d.PATCH("/power-outlets/:id", manage, h.Update("power-outlets"))
	d.DELETE("/power-outlets/:id", manage, h.Delete("power-outlets"))
	d.GET("/assets/:id/power-outlets", read, h.ListForAsset("power-outlets"))
	d.POST("/assets/:id/power-outlets", manage, h.CreateForAsset("power-outlets"))
}
