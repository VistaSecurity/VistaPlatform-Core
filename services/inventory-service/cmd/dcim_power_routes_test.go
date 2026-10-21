package main

// The power routes' permission gates (DCIM row 6.1), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware
// (grantPool from dcim_substrate_routes_test.go answers user_has_permission).
// Every route: no grant → 403 and nothing reaches the store; dcim.read → reads
// succeed, writes 403; dcim.manage → writes reach the store with an actor on
// the context; ipam.manage opens nothing.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// dcim_power_routes.go → a subtest fails; delete a registration → the route
// answers 404 and its subtests fail.

import (
	"context"
	"net/http"
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

type stubPower struct{ *stubCatalogue }

func (s stubPower) AssetPower(ctx context.Context, _, asset uuid.UUID) (*services.AssetPowerSummary, error) {
	s.note(ctx)
	return &services.AssetPowerSummary{AssetID: asset}, nil
}

func (s stubPower) RackPower(ctx context.Context, _, rack uuid.UUID) (*services.RackPowerBudget, error) {
	s.note(ctx)
	return &services.RackPowerBudget{RackID: rack}, nil
}

func powerRouter(t *testing.T, store *stubCatalogue, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimPowerRoutes(v2, grantPool(t, perms...), handlers.NewPowerHandler(stubPower{store}))
	return r
}

func powerRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	var out []catalogueRoute
	for _, r := range services.PowerObjectRoutes() {
		list, one := base+"/"+r, base+"/"+r+"/"+uuid.NewString()
		out = append(out,
			catalogueRoute{http.MethodGet, list, "", false, http.StatusOK},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, list, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	out = append(out, catalogueRoute{http.MethodGet, base + "/assets/" + uuid.NewString() + "/power", "", false, http.StatusOK})
	out = append(out, catalogueRoute{http.MethodGet, base + "/racks/" + uuid.NewString() + "/power", "", false, http.StatusOK})
	return out
}

func TestDcimPowerRoutes_Gates(t *testing.T) {
	routes := powerRoutes()
	if want := 2*5 + 2; len(routes) != want {
		t.Fatalf("expected %d power routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(powerRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(powerRouter(t, store, rbac.PermissionDcimRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with dcim.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(powerRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(powerRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a power route: status %d", w.Code)
			}
		})
	}
}

func TestDcimPowerRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimPowerRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimPowerRoutes(apiv2, rawDB, …): the power routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/power-`) {
		t.Fatal("main.go registers a power route directly, outside the gated mount function")
	}
}

// The rack budget route returns the store's answer in the envelope.
//
// Mutation: answer nil from PowerHandler.RackPower → red.
func TestDcimPowerRoutes_RackPowerBody(t *testing.T) {
	id := uuid.NewString()
	w := serveCatalogue(powerRouter(t, &stubCatalogue{}, rbac.PermissionDcimRead),
		catalogueRoute{http.MethodGet, "/api/v2/inventory-service/dcim/racks/" + id + "/power", "", false, http.StatusOK})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"rack_id":"`+id+`"`) {
		t.Fatalf("status %d body %s; want the budget of rack %s", w.Code, w.Body.String(), id)
	}
}
