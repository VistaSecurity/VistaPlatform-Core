package main

// The wireless routes' permission gates (DCIM row 4.4), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware. Every
// route of every object: no grant -> 403 and nothing reaches the store;
// wireless.read -> reads succeed, writes 403; wireless.manage -> writes reach
// the store with an actor on the context. Neither ipam nor dcim permissions
// open them.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// wireless_routes.go -> a subtest fails.

import (
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
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

func wirelessRouter(t *testing.T, store *stubIPAM, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountWirelessRoutes(v2, grantPool(t, perms...), handlers.NewIPAMHandler(store))
	return r
}

func wirelessRoutes() []ipamRoute {
	base := "/api/v2/inventory-service/wireless"
	var out []ipamRoute
	for _, r := range services.WirelessRoutes() {
		one := base + "/" + r + "/" + uuid.NewString()
		out = append(out,
			ipamRoute{http.MethodGet, base + "/" + r, "", false, http.StatusOK},
			ipamRoute{http.MethodGet, one, "", false, http.StatusOK},
			ipamRoute{http.MethodPost, base + "/" + r, `{}`, true, http.StatusCreated},
			ipamRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			ipamRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	return out
}

func serveWireless(r http.Handler, rt ipamRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, body))
	return w
}

func TestWirelessRoutes_Gates(t *testing.T) {
	routes := wirelessRoutes()
	if len(routes) != 3*5 {
		t.Fatalf("expected 3 wireless objects x 5 routes, got %d", len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveWireless(wirelessRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no wireless grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("wireless.read/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveWireless(wirelessRouter(t, store, rbac.PermissionWirelessRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with wireless.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("wireless.manage/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveWireless(wirelessRouter(t, store, rbac.PermissionWirelessRead, rbac.PermissionWirelessManage), rt)
			if w.Code != rt.want {
				t.Fatalf("status %d, want %d (%s)", w.Code, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("other families/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveWireless(wirelessRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage,
				rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("dcim/ipam permissions opened a wireless route: status %d", w.Code)
			}
		})
	}
}

func TestWirelessRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountWirelessRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountWirelessRoutes(apiv2, rawDB, …): the wireless routes are not served")
	}
}
