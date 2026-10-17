package main

// The custom-field routes' permission gates (DCIM row 5.1), through the REAL
// mount function main() calls and the REAL RequireTenantPermission middleware
// (grantPool from dcim_substrate_routes_test.go). Every route: no grant → 403
// and nothing reaches the store; dcim.read → reads succeed, writes 403;
// custom_fields.manage → writes reach the store with an actor on the context.
//
// Mutation: drop `read` from a GET or `manage` from a write in
// custom_field_routes.go → a subtest fails; drop the mount from main.go →
// TestCustomFieldRoutes_MountedByMain fails.

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

func customFieldRouter(t *testing.T, store *stubCircuits, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountCustomFieldRoutes(v2, grantPool(t, perms...), handlers.NewCustomFieldHandler(store))
	return r
}

func customFieldRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	var out []catalogueRoute
	for _, r := range []string{"custom-fields", "custom-field-choice-sets"} {
		list, one := base+"/"+r, base+"/"+r+"/"+uuid.NewString()
		out = append(out,
			catalogueRoute{http.MethodGet, list, "", false, http.StatusOK},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, list, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	return out
}

func TestCustomFieldRoutes_Gates(t *testing.T) {
	for _, rt := range customFieldRoutes() {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCircuits{}
			w := serveCircuit(customFieldRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubCircuits{}
			w := serveCircuit(customFieldRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("dcim.manage without custom_fields.manage on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with dcim.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("custom_fields.manage/"+name, func(t *testing.T) {
			store := &stubCircuits{}
			w := serveCircuit(customFieldRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionCustomFieldsManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
	}
}

func TestCustomFieldRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountCustomFieldRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountCustomFieldRoutes(apiv2, rawDB, …): the custom-field routes are not served")
	}
}
