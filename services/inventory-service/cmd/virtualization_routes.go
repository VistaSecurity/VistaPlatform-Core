package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountVirtualizationRoutes mounts virtualisation (DCIM BUILD_PLAN row 4.2)
// under /inventory-service/virtualization on the JWT-authenticated v2 group:
// reads behind virtualization.read, writes behind virtualization.manage (row
// 0.6's permissions), with changes.Middleware putting the actor and request id
// on the context for the change record. Platform-seeded cluster types are
// refused on write by the service (403 read_only).
//
// One literal registration per route, so the spec-route scanner
// (shared/api/spectest) sees each path. main() calls this;
// virtualization_routes_test.go drives the same function over every route.
func mountVirtualizationRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.VirtualizationHandler) {
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionVirtualizationRead)
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionVirtualizationManage)

	g := v2.Group("/inventory-service/virtualization")
	g.Use(changes.Middleware())
	g.GET("/cluster-types", read, h.List("cluster-types"))
	g.POST("/cluster-types", manage, h.Create("cluster-types"))
	g.GET("/cluster-types/:id", read, h.Get("cluster-types"))
	g.PATCH("/cluster-types/:id", manage, h.Update("cluster-types"))
	g.DELETE("/cluster-types/:id", manage, h.Delete("cluster-types"))
	g.GET("/cluster-groups", read, h.List("cluster-groups"))
	g.POST("/cluster-groups", manage, h.Create("cluster-groups"))
	g.GET("/cluster-groups/:id", read, h.Get("cluster-groups"))
	g.PATCH("/cluster-groups/:id", manage, h.Update("cluster-groups"))
	g.DELETE("/cluster-groups/:id", manage, h.Delete("cluster-groups"))
	g.GET("/clusters", read, h.List("clusters"))
	g.POST("/clusters", manage, h.Create("clusters"))
	g.GET("/clusters/:id", read, h.Get("clusters"))
	g.PATCH("/clusters/:id", manage, h.Update("clusters"))
	g.DELETE("/clusters/:id", manage, h.Delete("clusters"))
	g.GET("/virtual-disks", read, h.List("virtual-disks"))
	g.POST("/virtual-disks", manage, h.Create("virtual-disks"))
	g.GET("/virtual-disks/:id", read, h.Get("virtual-disks"))
	g.PATCH("/virtual-disks/:id", manage, h.Update("virtual-disks"))
	g.DELETE("/virtual-disks/:id", manage, h.Delete("virtual-disks"))
	g.GET("/clusters/:id/hosts", read, h.ClusterHosts)
	g.POST("/clusters/:id/hosts", manage, h.AddClusterHost)
	g.DELETE("/clusters/:id/hosts/:asset_id", manage, h.RemoveClusterHost)
	g.GET("/clusters/:id/vms", read, h.ClusterVMs)
	g.GET("/assets/:id/virtualization", read, h.AssetVirtualization)
	g.PATCH("/assets/:id/virtualization", manage, h.UpdateAssetVirtualization)
}
