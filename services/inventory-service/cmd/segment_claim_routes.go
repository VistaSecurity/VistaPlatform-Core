package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// segmentClaimChain is the middleware + handler chain of both claim routes
// (POST and DELETE /network-segments/:id/claim). Claiming a learned public
// range makes it scannable on request, which is what declaring a segment does,
// so it carries the same bar: settings.update ( D8). It is a function so
// main() and the route test build the identical chain — the test drives this,
// and segment_claim_routes_test.go pins that main.go mounts it.
func segmentClaimChain(rawDB *sql.DB, handler gin.HandlerFunc) []gin.HandlerFunc {
	return []gin.HandlerFunc{sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), handler}
}
