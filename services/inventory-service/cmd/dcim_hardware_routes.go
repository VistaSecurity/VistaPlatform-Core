package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountDcimHardwareRoutes mounts DCIM BUILD_PLAN row 2.4's hardware objects —
// module bays, modules, inventory item roles, inventory items and virtual
// chassis, with the chassis membership and the asset's chassis, and DCIM gap
// 1's virtual device contexts (also listed and declared per asset) — under
// /inventory-service/dcim on the JWT-authenticated v2 group: reads behind
// dcim.read, writes behind dcim.manage, with changes.Middleware putting the
// actor and request id on the context for the change record. POST /modules
// installs a module (its module type's templates are instantiated); DELETE
// /modules/{id} removes it, keeping measured components.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// dcim_hardware_routes_test.go drives the same function over every route.
func mountDcimHardwareRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.ComponentHandler, vc *handlers.VirtualChassisHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)

	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.GET("/module-bays", read, h.List("module-bays"))
	d.POST("/module-bays", manage, h.Create("module-bays"))
	d.GET("/module-bays/:id", read, h.Get("module-bays"))
	d.PATCH("/module-bays/:id", manage, h.Update("module-bays"))
	d.DELETE("/module-bays/:id", manage, h.Delete("module-bays"))
	d.GET("/assets/:id/module-bays", read, h.ListForAsset("module-bays"))
	d.POST("/assets/:id/module-bays", manage, h.CreateForAsset("module-bays"))
	d.GET("/modules", read, h.List("modules"))
	d.POST("/modules", manage, h.Create("modules"))
	d.GET("/modules/:id", read, h.Get("modules"))
	d.PATCH("/modules/:id", manage, h.Update("modules"))
	d.DELETE("/modules/:id", manage, h.Delete("modules"))
	d.GET("/assets/:id/modules", read, h.ListForAsset("modules"))
	d.POST("/assets/:id/modules", manage, h.CreateForAsset("modules"))
	d.GET("/inventory-item-roles", read, h.List("inventory-item-roles"))
	d.POST("/inventory-item-roles", manage, h.Create("inventory-item-roles"))
	d.GET("/inventory-item-roles/:id", read, h.Get("inventory-item-roles"))
	d.PATCH("/inventory-item-roles/:id", manage, h.Update("inventory-item-roles"))
	d.DELETE("/inventory-item-roles/:id", manage, h.Delete("inventory-item-roles"))
	d.GET("/inventory-items", read, h.List("inventory-items"))
	d.POST("/inventory-items", manage, h.Create("inventory-items"))
	d.GET("/inventory-items/:id", read, h.Get("inventory-items"))
	d.PATCH("/inventory-items/:id", manage, h.Update("inventory-items"))
	d.DELETE("/inventory-items/:id", manage, h.Delete("inventory-items"))
	d.GET("/assets/:id/inventory-items", read, h.ListForAsset("inventory-items"))
	d.POST("/assets/:id/inventory-items", manage, h.CreateForAsset("inventory-items"))
	d.GET("/virtual-chassis", read, h.List("virtual-chassis"))
	d.POST("/virtual-chassis", manage, h.Create("virtual-chassis"))
	d.GET("/virtual-chassis/:id", read, h.Get("virtual-chassis"))
	d.PATCH("/virtual-chassis/:id", manage, h.Update("virtual-chassis"))
	d.DELETE("/virtual-chassis/:id", manage, h.Delete("virtual-chassis"))
	d.GET("/virtual-chassis/:id/members", read, vc.Members)
	d.POST("/virtual-chassis/:id/members", manage, vc.AddMember)
	d.DELETE("/virtual-chassis/:id/members/:asset_id", manage, vc.RemoveMember)
	d.GET("/assets/:id/virtual-chassis", read, vc.ForAsset)
	d.GET("/virtual-device-contexts", read, h.List("virtual-device-contexts"))
	d.POST("/virtual-device-contexts", manage, h.Create("virtual-device-contexts"))
	d.GET("/virtual-device-contexts/:id", read, h.Get("virtual-device-contexts"))
	d.PATCH("/virtual-device-contexts/:id", manage, h.Update("virtual-device-contexts"))
	d.DELETE("/virtual-device-contexts/:id", manage, h.Delete("virtual-device-contexts"))
	d.GET("/assets/:id/virtual-device-contexts", read, h.ListForAsset("virtual-device-contexts"))
	d.POST("/assets/:id/virtual-device-contexts", manage, h.CreateForAsset("virtual-device-contexts"))
}
