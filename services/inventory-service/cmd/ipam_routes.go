package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountIPAMRoutes mounts IPAM (DCIM BUILD_PLAN row 1.3) under
// /inventory-service/ipam on the JWT-authenticated v2 group: every read behind
// ipam.read, every write behind ipam.manage (row 0.6's permissions), with
// changes.Middleware putting the actor and request id on the context for the
// change record.
//
// main() calls this; ipam_routes_test.go drives the same function, so a
// missing gate fails a test.
func mountIPAMRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.IPAMHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionIpamRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionIpamManage)

	g := v2.Group("/inventory-service/ipam")
	g.Use(changes.Middleware())
	g.GET("/find", read, h.Find)
	g.GET("/prefixes/tree", read, h.PrefixTree)
	// One literal registration per route, so the spec-route scanner
	// (shared/api/spectest) sees each path; ipam_routes_test.go walks
	// services.IPAMRoutes() and fails if one is missing here.
	g.GET("/rirs", read, h.List("rirs"))
	g.POST("/rirs", manage, h.Create("rirs"))
	g.GET("/rirs/:id", read, h.Get("rirs"))
	g.PATCH("/rirs/:id", manage, h.Update("rirs"))
	g.DELETE("/rirs/:id", manage, h.Delete("rirs"))
	g.GET("/aggregates", read, h.List("aggregates"))
	g.POST("/aggregates", manage, h.Create("aggregates"))
	g.GET("/aggregates/:id", read, h.Get("aggregates"))
	g.PATCH("/aggregates/:id", manage, h.Update("aggregates"))
	g.DELETE("/aggregates/:id", manage, h.Delete("aggregates"))
	g.GET("/vrfs", read, h.List("vrfs"))
	g.POST("/vrfs", manage, h.Create("vrfs"))
	g.GET("/vrfs/:id", read, h.Get("vrfs"))
	g.PATCH("/vrfs/:id", manage, h.Update("vrfs"))
	g.DELETE("/vrfs/:id", manage, h.Delete("vrfs"))
	g.GET("/route-targets", read, h.List("route-targets"))
	g.POST("/route-targets", manage, h.Create("route-targets"))
	g.GET("/route-targets/:id", read, h.Get("route-targets"))
	g.PATCH("/route-targets/:id", manage, h.Update("route-targets"))
	g.DELETE("/route-targets/:id", manage, h.Delete("route-targets"))
	g.GET("/prefix-roles", read, h.List("prefix-roles"))
	g.POST("/prefix-roles", manage, h.Create("prefix-roles"))
	g.GET("/prefix-roles/:id", read, h.Get("prefix-roles"))
	g.PATCH("/prefix-roles/:id", manage, h.Update("prefix-roles"))
	g.DELETE("/prefix-roles/:id", manage, h.Delete("prefix-roles"))
	g.GET("/prefixes", read, h.List("prefixes"))
	g.POST("/prefixes", manage, h.Create("prefixes"))
	g.GET("/prefixes/:id", read, h.PrefixDetail)
	g.PATCH("/prefixes/:id", manage, h.Update("prefixes"))
	g.DELETE("/prefixes/:id", manage, h.Delete("prefixes"))
	g.GET("/ip-ranges", read, h.List("ip-ranges"))
	g.POST("/ip-ranges", manage, h.Create("ip-ranges"))
	g.GET("/ip-ranges/:id", read, h.Get("ip-ranges"))
	g.PATCH("/ip-ranges/:id", manage, h.Update("ip-ranges"))
	g.DELETE("/ip-ranges/:id", manage, h.Delete("ip-ranges"))
	g.GET("/ip-addresses", read, h.List("ip-addresses"))
	g.POST("/ip-addresses", manage, h.Create("ip-addresses"))
	g.GET("/ip-addresses/:id", read, h.Get("ip-addresses"))
	g.PATCH("/ip-addresses/:id", manage, h.Update("ip-addresses"))
	g.DELETE("/ip-addresses/:id", manage, h.Delete("ip-addresses"))
	g.GET("/vlan-groups", read, h.List("vlan-groups"))
	g.POST("/vlan-groups", manage, h.Create("vlan-groups"))
	g.GET("/vlan-groups/:id", read, h.Get("vlan-groups"))
	g.PATCH("/vlan-groups/:id", manage, h.Update("vlan-groups"))
	g.DELETE("/vlan-groups/:id", manage, h.Delete("vlan-groups"))
	g.GET("/vlans", read, h.List("vlans"))
	g.POST("/vlans", manage, h.Create("vlans"))
	g.GET("/vlans/:id", read, h.Get("vlans"))
	g.PATCH("/vlans/:id", manage, h.Update("vlans"))
	g.DELETE("/vlans/:id", manage, h.Delete("vlans"))
	g.GET("/fhrp-groups", read, h.List("fhrp-groups"))
	g.POST("/fhrp-groups", manage, h.Create("fhrp-groups"))
	g.GET("/fhrp-groups/:id", read, h.Get("fhrp-groups"))
	g.PATCH("/fhrp-groups/:id", manage, h.Update("fhrp-groups"))
	g.DELETE("/fhrp-groups/:id", manage, h.Delete("fhrp-groups"))
	g.GET("/fhrp-group-assignments", read, h.List("fhrp-group-assignments"))
	g.POST("/fhrp-group-assignments", manage, h.Create("fhrp-group-assignments"))
	g.GET("/fhrp-group-assignments/:id", read, h.Get("fhrp-group-assignments"))
	g.PATCH("/fhrp-group-assignments/:id", manage, h.Update("fhrp-group-assignments"))
	g.DELETE("/fhrp-group-assignments/:id", manage, h.Delete("fhrp-group-assignments"))
	g.GET("/asns", read, h.List("asns"))
	g.POST("/asns", manage, h.Create("asns"))
	g.GET("/asns/:id", read, h.Get("asns"))
	g.PATCH("/asns/:id", manage, h.Update("asns"))
	g.DELETE("/asns/:id", manage, h.Delete("asns"))
}
