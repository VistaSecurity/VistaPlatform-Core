package main

// The rack routes' permission gates (DCIM row 2.3), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware
// (grantPool from dcim_substrate_routes_test.go answers user_has_permission).
// Every route: no grant → 403 and nothing reaches a store; dcim.read → reads
// succeed, writes 403; dcim.manage → writes reach the store with an actor on
// the context; ipam.manage opens nothing.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// dcim_rack_routes.go → a subtest fails; delete a registration → the route
// answers 404 and its subtests fail.

import (
	"context"
	"encoding/json"
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

type stubPlacement struct{ s *stubCatalogue }

func (p stubPlacement) Get(ctx context.Context, _, _ uuid.UUID) (*services.AssetPlacement, error) {
	p.s.note(ctx)
	return &services.AssetPlacement{}, nil
}
func (p stubPlacement) Place(ctx context.Context, _, _ uuid.UUID, _ services.PlaceInput) (*services.AssetPlacement, error) {
	p.s.note(ctx)
	return &services.AssetPlacement{}, nil
}
func (p stubPlacement) Unplace(ctx context.Context, _, _ uuid.UUID) (*services.AssetPlacement, error) {
	p.s.note(ctx)
	return &services.AssetPlacement{}, nil
}
func (p stubPlacement) Elevation(ctx context.Context, _, _ uuid.UUID) (*services.RackElevation, error) {
	p.s.note(ctx)
	return &services.RackElevation{Rack: json.RawMessage(`{}`)}, nil
}
func (p stubPlacement) ElevationPosture(ctx context.Context, _, _ uuid.UUID) (map[uuid.UUID]*services.DevicePosture, error) {
	p.s.note(ctx)
	return map[uuid.UUID]*services.DevicePosture{}, nil
}

func rackRouter(t *testing.T, store *stubCatalogue, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimRackRoutes(v2, grantPool(t, perms...), handlers.NewRackHandler(store, stubPlacement{store}))
	return r
}

func rackRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	var out []catalogueRoute
	for _, r := range services.RackObjectRoutes() {
		list, one := base+"/"+r, base+"/"+r+"/"+uuid.NewString()
		out = append(out,
			catalogueRoute{http.MethodGet, list, "", false, http.StatusOK},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, list, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	asset := base + "/assets/" + uuid.NewString() + "/placement"
	out = append(out,
		catalogueRoute{http.MethodGet, base + "/racks/" + uuid.NewString() + "/elevation", "", false, http.StatusOK},
		catalogueRoute{http.MethodGet, asset, "", false, http.StatusOK},
		catalogueRoute{http.MethodPut, asset, `{"rack_id":"` + uuid.NewString() + `","position":10,"face":"front"}`, true, http.StatusOK},
		catalogueRoute{http.MethodDelete, asset, "", true, http.StatusOK},
	)
	return out
}

func TestDcimRackRoutes_Gates(t *testing.T) {
	routes := rackRoutes()
	if want := 4*5 + 4; len(routes) != want {
		t.Fatalf("expected %d rack routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(rackRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(rackRouter(t, store, rbac.PermissionDcimRead), rt)
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
			w := serveCatalogue(rackRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(rackRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a rack route: status %d", w.Code)
			}
		})
	}
}

// A placement conflict answers 409 placement_conflict naming the blocker.
func TestDcimRackRoutes_PlacementConflictBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
	})
	blocker := uuid.New()
	mountDcimRackRoutes(v2, grantPool(t, rbac.PermissionDcimRead, rbac.PermissionDcimManage),
		handlers.NewRackHandler(&stubCatalogue{}, conflictPlacement{blocker}))
	w := serveCatalogue(r, catalogueRoute{method: http.MethodPut,
		path: "/api/v2/inventory-service/dcim/assets/" + uuid.NewString() + "/placement",
		body: `{"rack_id":"` + uuid.NewString() + `","position":11,"face":"front"}`})
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409 (%s)", w.Code, w.Body.String())
	}
	var body struct {
		Error struct {
			Code          string `json:"code"`
			BlockingAsset struct {
				ID string `json:"id"`
			} `json:"blocking_asset"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "placement_conflict" || body.Error.BlockingAsset.ID != blocker.String() {
		t.Fatalf("body %s does not name the blocking asset", w.Body.String())
	}
}

type conflictPlacement struct{ blocker uuid.UUID }

func (conflictPlacement) Get(context.Context, uuid.UUID, uuid.UUID) (*services.AssetPlacement, error) {
	return nil, nil
}
func (p conflictPlacement) Place(context.Context, uuid.UUID, uuid.UUID, services.PlaceInput) (*services.AssetPlacement, error) {
	return nil, &services.PlacementConflictError{Message: "occupied", BlockingAsset: &services.PlacementBlocker{ID: p.blocker, Name: "sw-1"}}
}
func (conflictPlacement) Unplace(context.Context, uuid.UUID, uuid.UUID) (*services.AssetPlacement, error) {
	return nil, nil
}
func (conflictPlacement) Elevation(context.Context, uuid.UUID, uuid.UUID) (*services.RackElevation, error) {
	return nil, nil
}
func (conflictPlacement) ElevationPosture(context.Context, uuid.UUID, uuid.UUID) (map[uuid.UUID]*services.DevicePosture, error) {
	return nil, nil
}

func TestDcimRackRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimRackRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimRackRoutes(apiv2, rawDB, …): the rack routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/racks`) {
		t.Fatal("main.go registers a rack route directly, outside the gated mount function")
	}
}
