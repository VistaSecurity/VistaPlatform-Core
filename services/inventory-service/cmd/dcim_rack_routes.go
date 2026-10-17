package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimRackRoutes mounts racks, rack roles, rack types, rack reservations,
// the rack elevation and asset placement (DCIM BUILD_PLAN row 2.3) under
// /inventory-service/dcim on the JWT-authenticated v2 group: reads behind
// dcim.read, writes behind dcim.manage, with changes.Middleware putting the
// actor and request id on the context for the change record.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// dcim_rack_routes_test.go drives the same function over every route.
func mountDcimRackRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.RackHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/rack-roles", read, h.List("rack-roles"))
	d.POST("/rack-roles", manage, h.Create("rack-roles"))
	d.GET("/rack-roles/:id", read, h.Get("rack-roles"))
	d.PATCH("/rack-roles/:id", manage, h.Update("rack-roles"))
	d.DELETE("/rack-roles/:id", manage, h.Delete("rack-roles"))
	d.GET("/rack-types", read, h.List("rack-types"))
	d.POST("/rack-types", manage, h.Create("rack-types"))
	d.GET("/rack-types/:id", read, h.Get("rack-types"))
	d.PATCH("/rack-types/:id", manage, h.Update("rack-types"))
	d.DELETE("/rack-types/:id", manage, h.Delete("rack-types"))
	d.GET("/racks", read, h.List("racks"))
	d.POST("/racks", manage, h.Create("racks"))
	d.GET("/racks/:id", read, h.Get("racks"))
	d.PATCH("/racks/:id", manage, h.Update("racks"))
	d.DELETE("/racks/:id", manage, h.Delete("racks"))
	d.GET("/racks/:id/elevation", read, h.Elevation)
	d.GET("/rack-reservations", read, h.List("rack-reservations"))
	d.POST("/rack-reservations", manage, h.Create("rack-reservations"))
	d.GET("/rack-reservations/:id", read, h.Get("rack-reservations"))
	d.PATCH("/rack-reservations/:id", manage, h.Update("rack-reservations"))
	d.DELETE("/rack-reservations/:id", manage, h.Delete("rack-reservations"))
	d.GET("/assets/:id/placement", read, h.GetPlacement)
	d.PUT("/assets/:id/placement", manage, h.Place)
	d.DELETE("/assets/:id/placement", manage, h.Unplace)
}
