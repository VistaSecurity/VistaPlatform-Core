package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountVPNRoutes mounts the VPN objects (DCIM BUILD_PLAN row 4.3) under
// /inventory-service/vpn on the JWT-authenticated v2 group: reads behind
// vpn.read, writes behind vpn.manage (row 0.6's permissions), with
// changes.Middleware putting the actor and request id on the context for the
// change record.
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this; vpn_routes_test.go
// drives the same function over every route.
func mountVPNRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.VPNHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionVpnRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionVpnManage)

	v := v2.Group("/inventory-service/vpn")
	v.Use(changes.Middleware())
	v.GET("/tunnel-groups", read, h.List("tunnel-groups"))
	v.POST("/tunnel-groups", manage, h.Create("tunnel-groups"))
	v.GET("/tunnel-groups/:id", read, h.Get("tunnel-groups"))
	v.PATCH("/tunnel-groups/:id", manage, h.Update("tunnel-groups"))
	v.DELETE("/tunnel-groups/:id", manage, h.Delete("tunnel-groups"))
	v.GET("/tunnels", read, h.List("tunnels"))
	v.POST("/tunnels", manage, h.Create("tunnels"))
	v.GET("/tunnels/:id", read, h.Get("tunnels"))
	v.PATCH("/tunnels/:id", manage, h.Update("tunnels"))
	v.DELETE("/tunnels/:id", manage, h.Delete("tunnels"))
	v.GET("/tunnel-terminations", read, h.List("tunnel-terminations"))
	v.POST("/tunnel-terminations", manage, h.Create("tunnel-terminations"))
	v.GET("/tunnel-terminations/:id", read, h.Get("tunnel-terminations"))
	v.PATCH("/tunnel-terminations/:id", manage, h.Update("tunnel-terminations"))
	v.DELETE("/tunnel-terminations/:id", manage, h.Delete("tunnel-terminations"))
	v.GET("/ike-proposals", read, h.List("ike-proposals"))
	v.POST("/ike-proposals", manage, h.Create("ike-proposals"))
	v.GET("/ike-proposals/:id", read, h.Get("ike-proposals"))
	v.PATCH("/ike-proposals/:id", manage, h.Update("ike-proposals"))
	v.DELETE("/ike-proposals/:id", manage, h.Delete("ike-proposals"))
	v.GET("/ike-policies", read, h.List("ike-policies"))
	v.POST("/ike-policies", manage, h.Create("ike-policies"))
	v.GET("/ike-policies/:id", read, h.Get("ike-policies"))
	v.PATCH("/ike-policies/:id", manage, h.Update("ike-policies"))
	v.DELETE("/ike-policies/:id", manage, h.Delete("ike-policies"))
	v.GET("/ipsec-proposals", read, h.List("ipsec-proposals"))
	v.POST("/ipsec-proposals", manage, h.Create("ipsec-proposals"))
	v.GET("/ipsec-proposals/:id", read, h.Get("ipsec-proposals"))
	v.PATCH("/ipsec-proposals/:id", manage, h.Update("ipsec-proposals"))
	v.DELETE("/ipsec-proposals/:id", manage, h.Delete("ipsec-proposals"))
	v.GET("/ipsec-policies", read, h.List("ipsec-policies"))
	v.POST("/ipsec-policies", manage, h.Create("ipsec-policies"))
	v.GET("/ipsec-policies/:id", read, h.Get("ipsec-policies"))
	v.PATCH("/ipsec-policies/:id", manage, h.Update("ipsec-policies"))
	v.DELETE("/ipsec-policies/:id", manage, h.Delete("ipsec-policies"))
	v.GET("/ipsec-profiles", read, h.List("ipsec-profiles"))
	v.POST("/ipsec-profiles", manage, h.Create("ipsec-profiles"))
	v.GET("/ipsec-profiles/:id", read, h.Get("ipsec-profiles"))
	v.PATCH("/ipsec-profiles/:id", manage, h.Update("ipsec-profiles"))
	v.DELETE("/ipsec-profiles/:id", manage, h.Delete("ipsec-profiles"))
	v.GET("/l2vpns", read, h.List("l2vpns"))
	v.POST("/l2vpns", manage, h.Create("l2vpns"))
	v.GET("/l2vpns/:id", read, h.Get("l2vpns"))
	v.PATCH("/l2vpns/:id", manage, h.Update("l2vpns"))
	v.DELETE("/l2vpns/:id", manage, h.Delete("l2vpns"))
	v.GET("/l2vpn-terminations", read, h.List("l2vpn-terminations"))
	v.POST("/l2vpn-terminations", manage, h.Create("l2vpn-terminations"))
	v.GET("/l2vpn-terminations/:id", read, h.Get("l2vpn-terminations"))
	v.PATCH("/l2vpn-terminations/:id", manage, h.Update("l2vpn-terminations"))
	v.DELETE("/l2vpn-terminations/:id", manage, h.Delete("l2vpn-terminations"))
}
