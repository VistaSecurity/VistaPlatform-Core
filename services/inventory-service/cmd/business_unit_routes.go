package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// registerBusinessUnitRoutes mounts the five Business Unit routes (DCIM 1.1):
// reads need dcim.read, every write needs business_units.manage (tenant admin
// only, ADR-0010 D10). main() mounts them through this and
// business_unit_routes_test.go fails if it does not; the integration test
// drives this function's routes against a real database.
func registerBusinessUnitRoutes(g gin.IRoutes, rawDB *sql.DB, h *handlers.BusinessUnitHandler) {
	// changes.Middleware puts the actor and request id on the request context so
	// every change the service records is attributed (row 0.3).
	actor := changes.Middleware()
	read := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionDcimRead)
	write := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionBusinessUnitsManage)
	// Literal paths on purpose: the spec/route parity test scans for them.
	g.GET("/inventory-service/dcim/business-units", actor, read, h.List)
	g.GET("/inventory-service/dcim/business-units/:id", actor, read, h.Get)
	g.POST("/inventory-service/dcim/business-units", actor, write, h.Create)
	g.PUT("/inventory-service/dcim/business-units/:id", actor, write, h.Update)
	g.DELETE("/inventory-service/dcim/business-units/:id", actor, write, h.Delete)
}
