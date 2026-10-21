package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// mountAssetPrimaryIPRoutes mounts PATCH /dcim/assets/{id}/primary-ips — an
// asset's primary IPv4, primary IPv6 and out-of-band address — behind
// ipam.manage (it is the IP Addresses tab's action, and the addresses are
// IPAM's), with changes.Middleware for the change record. main() calls this;
// asset_primary_ips_routes_test.go drives the same function.
func mountAssetPrimaryIPRoutes(v2 gin.IRouter, rawDB *sql.DB, h *handlers.AssetPrimaryIPHandler) {
	manage := sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionIpamManage)
	d := v2.Group("/inventory-service/dcim")
	d.Use(changes.Middleware())
	d.PATCH("/assets/:id/primary-ips", manage, h.Update)
}
