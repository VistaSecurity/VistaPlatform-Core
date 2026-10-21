package main

// PATCH /dcim/assets/{id}/primary-ips: the gate (ipam.manage — dcim.manage
// opens nothing), the actor on the context, the body reaching the store, and
// main() mounting it. Mutation: drop `manage` from the route, or the
// changes.Middleware, in mountAssetPrimaryIPRoutes → a subtest fails; delete
// the mount line in main.go → the MountedByMain test fails.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type stubPrimaryIPs struct {
	calls    int
	sawActor bool
	patch    services.AssetPrimaryIPsPatch
}

func (s *stubPrimaryIPs) Update(ctx context.Context, _, asset uuid.UUID, p services.AssetPrimaryIPsPatch) (*services.AssetPrimaryIPs, error) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
	s.patch = p
	return &services.AssetPrimaryIPs{AssetID: asset}, nil
}

func primaryIPsRouter(t *testing.T, store *stubPrimaryIPs, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountAssetPrimaryIPRoutes(v2, grantPool(t, perms...), handlers.NewAssetPrimaryIPHandler(store))
	return r
}

func servePrimaryIPs(r http.Handler, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	var rd io.Reader = strings.NewReader(body)
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPatch, "/api/v2/inventory-service/dcim/assets/"+uuid.NewString()+"/primary-ips", rd))
	return w
}

func TestAssetPrimaryIPsRoute_Gates(t *testing.T) {
	const body = `{"primary_ip4_id":null}`
	for name, perms := range map[string][]string{
		"no grant":    nil,
		"ipam.read":   {rbac.PermissionIpamRead},
		"dcim.manage": {rbac.PermissionDcimRead, rbac.PermissionDcimManage},
	} {
		t.Run(name, func(t *testing.T) {
			store := &stubPrimaryIPs{}
			w := servePrimaryIPs(primaryIPsRouter(t, store, perms...), body)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
	}
	t.Run("ipam.manage", func(t *testing.T) {
		store := &stubPrimaryIPs{}
		w := servePrimaryIPs(primaryIPsRouter(t, store, rbac.PermissionIpamManage), body)
		if w.Code != http.StatusOK || store.calls != 1 {
			t.Fatalf("status %d (calls %d): %s", w.Code, store.calls, w.Body.String())
		}
		if !store.sawActor {
			t.Fatal("no actor on the store's context — changes.Middleware is not mounted")
		}
		if _, ok := store.patch["primary_ip4_id"]; !ok {
			t.Fatalf("the body did not reach the store: %v", store.patch)
		}
	})
	t.Run("not an object", func(t *testing.T) {
		store := &stubPrimaryIPs{}
		w := servePrimaryIPs(primaryIPsRouter(t, store, rbac.PermissionIpamManage), `[1]`)
		if w.Code != http.StatusBadRequest || store.calls != 0 {
			t.Fatalf("status %d, calls %d — want 400", w.Code, store.calls)
		}
	})
}

func TestAssetPrimaryIPsRoute_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountAssetPrimaryIPRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountAssetPrimaryIPRoutes(apiv2, rawDB, …): the route is not served")
	}
}
