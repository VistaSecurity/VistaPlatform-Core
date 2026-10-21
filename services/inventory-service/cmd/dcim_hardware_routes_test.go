package main

// The hardware routes' permission gates (DCIM row 2.4), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware
// (grantPool answers user_has_permission). Every route: no grant → 403 and
// nothing reaches the store; dcim.read → reads succeed, writes 403;
// dcim.manage → writes reach the store with an actor on the context; ipam.*
// opens nothing.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// dcim_hardware_routes.go → a subtest fails; delete a registration → the route
// answers 404 and its subtests fail; drop the mount from main.go →
// TestDcimHardwareRoutes_MountedByMain fails.

import (
	"context"
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

type stubChassis struct{ *stubComponents }

func (s stubChassis) VirtualChassisMembers(ctx context.Context, _, _ uuid.UUID) ([]services.VirtualChassisMember, error) {
	s.note(ctx)
	return []services.VirtualChassisMember{}, nil
}
func (s stubChassis) AddVirtualChassisMember(ctx context.Context, _, _ uuid.UUID, _ services.VirtualChassisMemberInput) ([]services.VirtualChassisMember, error) {
	s.note(ctx)
	return []services.VirtualChassisMember{}, nil
}
func (s stubChassis) RemoveVirtualChassisMember(ctx context.Context, _, _, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s stubChassis) AssetVirtualChassis(ctx context.Context, _, _ uuid.UUID) (*services.AssetVirtualChassis, error) {
	s.note(ctx)
	return &services.AssetVirtualChassis{Members: []services.VirtualChassisMember{}}, nil
}

func hardwareRouter(t *testing.T, store *stubComponents, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimHardwareRoutes(v2, grantPool(t, perms...), handlers.NewComponentHandler(store), handlers.NewVirtualChassisHandler(stubChassis{store}))
	return r
}

func hardwareRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	var out []catalogueRoute
	for _, k := range services.HardwareRoutes() {
		one := base + "/" + k + "/" + uuid.NewString()
		out = append(out,
			catalogueRoute{http.MethodGet, base + "/" + k, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, base + "/" + k, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
		if k == services.HardwareModuleBay || k == services.HardwareModule || k == services.HardwareInventoryItem ||
			k == services.HardwareVirtualDeviceContext {
			onAsset := base + "/assets/" + uuid.NewString() + "/" + k
			out = append(out,
				catalogueRoute{http.MethodGet, onAsset, "", false, http.StatusOK},
				catalogueRoute{http.MethodPost, onAsset, `{}`, true, http.StatusCreated},
			)
		}
	}
	vc := base + "/virtual-chassis/" + uuid.NewString() + "/members"
	return append(out,
		catalogueRoute{http.MethodGet, vc, "", false, http.StatusOK},
		catalogueRoute{http.MethodPost, vc, `{"asset_id":"` + uuid.NewString() + `"}`, true, http.StatusOK},
		catalogueRoute{http.MethodDelete, vc + "/" + uuid.NewString(), "", true, http.StatusNoContent},
		catalogueRoute{http.MethodGet, base + "/assets/" + uuid.NewString() + "/virtual-chassis", "", false, http.StatusOK},
	)
}

func TestDcimHardwareRoutes_Gates(t *testing.T) {
	routes := hardwareRoutes()
	if want := 6*5 + 4*2 + 4; len(routes) != want {
		t.Fatalf("expected %d hardware routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubComponents{}
			w := serveComponent(hardwareRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubComponents{}
			w := serveComponent(hardwareRouter(t, store, rbac.PermissionDcimRead), rt)
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
			store := &stubComponents{}
			w := serveComponent(hardwareRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubComponents{}
			w := serveComponent(hardwareRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a hardware route: status %d", w.Code)
			}
		})
	}
}

func TestDcimHardwareRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimHardwareRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimHardwareRoutes(apiv2, rawDB, …): the hardware routes are not served")
	}
}
