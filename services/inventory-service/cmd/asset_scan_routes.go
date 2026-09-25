package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// newAssetLifecycleHandler builds the handler main() mounts, with the
// permission check confirming an external scan needs: discovery.create on top
// of the route's assets.update ( W5.13b). The handler fails CLOSED
// without it, so this is the one constructor main uses and the tests drive.
func newAssetLifecycleHandler(lc *services.AssetLifecycleService, rv *services.RevalidationService, as *services.AssetService, rawDB *sql.DB) *handlers.AssetLifecycleHandler {
	h := handlers.NewAssetLifecycleHandler(lc, rv, as)
	h.SetPermissionChecker(rbac.NewRBACService(rawDB))
	return h
}

// assetScanChain is the middleware + handler chain of both Active Scan routes
// (v1 /assets/scan and v2 /infrastructure-assets/scan): assets.update at the
// route, then the handler, which asks for discovery.create itself when the
// request confirms external targets.
func assetScanChain(rawDB *sql.DB, h *handlers.AssetLifecycleHandler) []gin.HandlerFunc {
	return []gin.HandlerFunc{sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate), h.ScanAssets}
}
