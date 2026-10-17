package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// registerSiteRoutes mounts the region, site group, site and location routes
// (DCIM row 2.1): reads need dcim.read, writes dcim.manage. main() mounts them
// through this and site_routes_test.go fails if it does not; the integration
// test drives these routes against a real database.
func registerSiteRoutes(g gin.IRoutes, rawDB *sql.DB, h *handlers.SiteHandler) {
	actor := changes.Middleware()
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	write := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimManage)
	// Literal paths on purpose: the spec/route parity test scans for them.
	g.GET("/inventory-service/dcim/regions", actor, read, h.ListRegions)
	g.GET("/inventory-service/dcim/regions/:id", actor, read, h.GetRegion)
	g.POST("/inventory-service/dcim/regions", actor, write, h.CreateRegion)
	g.PUT("/inventory-service/dcim/regions/:id", actor, write, h.UpdateRegion)
	g.DELETE("/inventory-service/dcim/regions/:id", actor, write, h.DeleteRegion)

	g.GET("/inventory-service/dcim/site-groups", actor, read, h.ListSiteGroups)
	g.GET("/inventory-service/dcim/site-groups/:id", actor, read, h.GetSiteGroup)
	g.POST("/inventory-service/dcim/site-groups", actor, write, h.CreateSiteGroup)
	g.PUT("/inventory-service/dcim/site-groups/:id", actor, write, h.UpdateSiteGroup)
	g.DELETE("/inventory-service/dcim/site-groups/:id", actor, write, h.DeleteSiteGroup)

	g.GET("/inventory-service/dcim/sites", actor, read, h.ListSites)
	g.GET("/inventory-service/dcim/sites/:id", actor, read, h.GetSite)
	g.POST("/inventory-service/dcim/sites", actor, write, h.CreateSite)
	g.PUT("/inventory-service/dcim/sites/:id", actor, write, h.UpdateSite)
	g.DELETE("/inventory-service/dcim/sites/:id", actor, write, h.DeleteSite)

	g.GET("/inventory-service/dcim/locations", actor, read, h.ListLocations)
	g.GET("/inventory-service/dcim/locations/:id", actor, read, h.GetLocation)
	g.POST("/inventory-service/dcim/locations", actor, write, h.CreateLocation)
	g.PUT("/inventory-service/dcim/locations/:id", actor, write, h.UpdateLocation)
	g.DELETE("/inventory-service/dcim/locations/:id", actor, write, h.DeleteLocation)
}
