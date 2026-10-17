package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountWirelessRoutes mounts wireless LAN groups, wireless LANs and wireless
// links (DCIM BUILD_PLAN row 4.4) under /inventory-service/wireless on the
// JWT-authenticated v2 group: every read behind wireless.read, every write
// behind wireless.manage (row 0.6's permissions), with changes.Middleware
// putting the actor and request id on the context for the change record.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// wireless_routes_test.go drives the same function, so a missing gate fails a
// test.
func mountWirelessRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.IPAMHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionWirelessRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionWirelessManage)

	g := v2.Group("/inventory-service/wireless")
	g.Use(changes.Middleware())
	g.GET("/wireless-lan-groups", read, h.List("wireless-lan-groups"))
	g.POST("/wireless-lan-groups", manage, h.Create("wireless-lan-groups"))
	g.GET("/wireless-lan-groups/:id", read, h.Get("wireless-lan-groups"))
	g.PATCH("/wireless-lan-groups/:id", manage, h.Update("wireless-lan-groups"))
	g.DELETE("/wireless-lan-groups/:id", manage, h.Delete("wireless-lan-groups"))
	g.GET("/wireless-lans", read, h.List("wireless-lans"))
	g.POST("/wireless-lans", manage, h.Create("wireless-lans"))
	g.GET("/wireless-lans/:id", read, h.Get("wireless-lans"))
	g.PATCH("/wireless-lans/:id", manage, h.Update("wireless-lans"))
	g.DELETE("/wireless-lans/:id", manage, h.Delete("wireless-lans"))
	g.GET("/wireless-links", read, h.List("wireless-links"))
	g.POST("/wireless-links", manage, h.Create("wireless-links"))
	g.GET("/wireless-links/:id", read, h.Get("wireless-links"))
	g.PATCH("/wireless-links/:id", manage, h.Update("wireless-links"))
	g.DELETE("/wireless-links/:id", manage, h.Delete("wireless-links"))
}
