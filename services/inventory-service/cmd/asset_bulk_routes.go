package main

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// assetBulkActions are the bulk actions on a selection of assets and
// the permission each needs: the same one the single-asset action needs.
// Delete is assets.delete, as DELETE /infrastructure-assets/{id} is; the rest
// change an asset and are assets.update.
var assetBulkActions = map[string]string{
	"archive": rbac.PermissionAssetsUpdate,
	"restore": rbac.PermissionAssetsUpdate,
	"update":  rbac.PermissionAssetsUpdate,
	"delete":  rbac.PermissionAssetsDelete,
}

// assetBulkChain is the middleware + handler chain of one bulk-action route:
// the action's permission at the route, then its handler. main() mounts every
// bulk route through this, and asset_bulk_routes_test.go fails if it does not.
func assetBulkChain(rawDB *sql.DB, h *handlers.AssetBulkHandler, action string) []gin.HandlerFunc {
	perm, ok := assetBulkActions[action]
	if !ok {
		panic(fmt.Sprintf("assetBulkChain: unknown bulk action %q", action))
	}
	handler := map[string]gin.HandlerFunc{
		"archive": h.BulkArchive,
		"restore": h.BulkRestore,
		"update":  h.BulkUpdate,
		"delete":  h.BulkDelete,
	}[action]
	return []gin.HandlerFunc{sharedrbac.RequireTenantPermission(rawDB, perm), handler}
}
