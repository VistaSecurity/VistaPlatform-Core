package main

// The VPN routes' permission gates (DCIM row 4.3), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware
// (grantPool from dcim_substrate_routes_test.go). Every route: no grant → 403
// and nothing reaches the store; vpn.read → reads succeed, writes 403;
// vpn.manage → writes reach the store with an actor; dcim.manage opens
// nothing here.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// vpn_routes.go → a subtest fails; delete a registration → 404, red.

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

func vpnRouter(t *testing.T, store *stubCatalogue, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountVPNRoutes(v2, grantPool(t, perms...), handlers.NewVPNHandler(store))
	return r
}

func TestVPNRoutes_Gates(t *testing.T) {
	base := "/api/v2/inventory-service/vpn"
	var routes []catalogueRoute
	for _, r := range services.VPNRoutes {
		list, one := base+"/"+r, base+"/"+r+"/"+uuid.NewString()
		routes = append(routes,
			catalogueRoute{http.MethodGet, list, "", false, http.StatusOK},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, list, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	if len(routes) != 50 {
		t.Fatalf("expected 50 VPN routes, got %d", len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(vpnRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no vpn grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("vpn.read/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(vpnRouter(t, store, rbac.PermissionVpnRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with vpn.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("vpn.manage/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(vpnRouter(t, store, rbac.PermissionVpnRead, rbac.PermissionVpnManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(vpnRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("dcim permissions opened a VPN route: status %d", w.Code)
			}
		})
	}
}

func TestVPNRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountVPNRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountVPNRoutes(apiv2, rawDB, …): the VPN routes are not served")
	}
}
