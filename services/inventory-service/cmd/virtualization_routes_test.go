package main

// The virtualisation routes' permission gates (DCIM row 4.2), through the REAL
// mount function main() calls and the REAL RequireTenantPermission middleware
// (grantPool from dcim_substrate_routes_test.go answers user_has_permission).
// Every route: no grant → 403 and nothing reaches the store;
// virtualization.read → reads succeed, writes 403; virtualization.manage →
// writes reach the store with an actor on the context; dcim.manage opens
// nothing here.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// virtualization_routes.go → a subtest fails; delete a registration → the
// route answers 404 and its subtests fail; drop the mount from main.go →
// TestVirtualizationRoutes_MountedByMain fails.

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
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type stubVirtualization struct {
	calls    int
	sawActor bool
}

func (s *stubVirtualization) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}

func (s *stubVirtualization) List(ctx context.Context, _ uuid.UUID, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubVirtualization) Get(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubVirtualization) Create(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubVirtualization) Update(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubVirtualization) Delete(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubVirtualization) ClusterHosts(ctx context.Context, _, _ uuid.UUID) ([]services.ClusterMember, error) {
	s.note(ctx)
	return []services.ClusterMember{}, nil
}
func (s *stubVirtualization) AddClusterHost(ctx context.Context, _, _, _ uuid.UUID) ([]services.ClusterMember, error) {
	s.note(ctx)
	return []services.ClusterMember{}, nil
}
func (s *stubVirtualization) RemoveClusterHost(ctx context.Context, _, _, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubVirtualization) ClusterVMs(ctx context.Context, _, _ uuid.UUID) ([]services.ClusterMember, error) {
	s.note(ctx)
	return []services.ClusterMember{}, nil
}
func (s *stubVirtualization) AssetVirtualization(ctx context.Context, _, _ uuid.UUID) (*services.AssetVirtualization, error) {
	s.note(ctx)
	return &services.AssetVirtualization{}, nil
}
func (s *stubVirtualization) UpdateAssetVirtualization(ctx context.Context, _, _ uuid.UUID, _ services.VirtualizationPatch) (*services.AssetVirtualization, error) {
	s.note(ctx)
	return &services.AssetVirtualization{}, nil
}

func virtualizationRouter(t *testing.T, store *stubVirtualization, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountVirtualizationRoutes(v2, grantPool(t, perms...), handlers.NewVirtualizationHandler(store))
	return r
}

func virtualizationRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/virtualization"
	var out []catalogueRoute
	for _, r := range services.VirtualizationObjectRoutes() {
		list, one := base+"/"+r, base+"/"+r+"/"+uuid.NewString()
		out = append(out,
			catalogueRoute{http.MethodGet, list, "", false, http.StatusOK},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, list, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	cluster := base + "/clusters/" + uuid.NewString()
	asset := base + "/assets/" + uuid.NewString()
	out = append(out,
		catalogueRoute{http.MethodGet, cluster + "/hosts", "", false, http.StatusOK},
		catalogueRoute{http.MethodPost, cluster + "/hosts", `{"asset_id":"` + uuid.NewString() + `"}`, true, http.StatusOK},
		catalogueRoute{http.MethodDelete, cluster + "/hosts/" + uuid.NewString(), "", true, http.StatusNoContent},
		catalogueRoute{http.MethodGet, cluster + "/vms", "", false, http.StatusOK},
		catalogueRoute{http.MethodGet, asset + "/virtualization", "", false, http.StatusOK},
		catalogueRoute{http.MethodPatch, asset + "/virtualization", `{"vcpus":4}`, true, http.StatusOK},
	)
	return out
}

func TestVirtualizationRoutes_Gates(t *testing.T) {
	routes := virtualizationRoutes()
	if want := 4*5 + 6; len(routes) != want {
		t.Fatalf("expected %d virtualization routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubVirtualization{}
			w := serveCatalogue(virtualizationRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("virtualization.read/"+name, func(t *testing.T) {
			store := &stubVirtualization{}
			w := serveCatalogue(virtualizationRouter(t, store, rbac.PermissionVirtualizationRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with virtualization.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("virtualization.manage/"+name, func(t *testing.T) {
			store := &stubVirtualization{}
			w := serveCatalogue(virtualizationRouter(t, store, rbac.PermissionVirtualizationRead, rbac.PermissionVirtualizationManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubVirtualization{}
			w := serveCatalogue(virtualizationRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("dcim permissions opened a virtualization route: status %d", w.Code)
			}
		})
	}
}

func TestVirtualizationRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountVirtualizationRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountVirtualizationRoutes(apiv2, rawDB, …): the virtualization routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/virtualization/`) {
		t.Fatal("main.go registers a virtualization route directly, outside the gated mount function")
	}
}
