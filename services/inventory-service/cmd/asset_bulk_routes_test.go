package main

// main.go must mount every bulk-action route through assetBulkChain, and the
// chain must carry each action's own permission. A registration naming the
// bare handler would compile, pass every handler test, and let any
// authenticated tenant user archive or delete five thousand assets at once;
// a delete gated on assets.update would let anyone who may EDIT an asset
// delete it. asset_bulk_routes_integration_test.go drives the chains against
// a real database.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

func TestAssetBulkRoutesAreMountedThroughTheGatedChain(t *testing.T) {
	for action := range assetBulkActions {
		path := "/inventory-service/infrastructure-assets/bulk-actions/" + action
		for _, args := range registrationsOf(t, http.MethodPost, path) {
			want := `assetBulkChain(rawDB, assetBulkHandler, "` + action + `")`
			if !strings.Contains(args, want) {
				t.Errorf("POST %s is not mounted through %s:\n%s", path, want, args)
			}
		}
	}
}

func TestAssetBulkActionsCarryTheSingleAssetPermission(t *testing.T) {
	want := map[string]string{
		"archive": rbac.PermissionAssetsUpdate,
		"restore": rbac.PermissionAssetsUpdate,
		"update":  rbac.PermissionAssetsUpdate,
		"delete":  rbac.PermissionAssetsDelete,
	}
	if len(assetBulkActions) != len(want) {
		t.Fatalf("bulk actions %v, want exactly %v", assetBulkActions, want)
	}
	for action, perm := range want {
		if got := assetBulkActions[action]; got != perm {
			t.Errorf("bulk %s is gated on %q, want %q", action, got, perm)
		}
	}
}
