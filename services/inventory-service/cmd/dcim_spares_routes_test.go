package main

// The spares routes' permission gates (DCIM gap 8), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware
// (grantPool answers user_has_permission). Every route: no grant → 403 and
// nothing reaches the store; dcim.read → reads succeed, writes 403;
// dcim.manage → writes reach the store with an actor on the context;
// ipam.manage opens nothing.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// dcim_spares_routes.go → a subtest fails; delete a registration → the route
// answers 404 and its subtests fail; drop the mount from main.go →
// TestDcimSparesRoutes_MountedByMain fails.

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

type stubSpares struct{ *stubCatalogue }

func (s stubSpares) Install(ctx context.Context, _, _ uuid.UUID, in services.SpareInstallInput) (*services.SpareResult, error) {
	s.note(ctx)
	return &services.SpareResult{Item: map[string]any{"asset_id": in.AssetID.String()}}, nil
}
func (s stubSpares) Remove(ctx context.Context, _, _ uuid.UUID, in services.SpareRemoveInput) (*services.SpareResult, error) {
	s.note(ctx)
	return &services.SpareResult{Item: map[string]any{"location_id": in.LocationID.String()}}, nil
}
func (s stubSpares) OpenRMA(ctx context.Context, _, _ uuid.UUID, in services.SpareRMAInput) (*services.SpareResult, error) {
	s.note(ctx)
	return &services.SpareResult{Item: map[string]any{}, RMACase: map[string]any{"vendor": in.Vendor}}, nil
}
func (s stubSpares) ListRMACases(ctx context.Context, _ uuid.UUID, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s stubSpares) GetRMACase(ctx context.Context, _, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s stubSpares) UpdateRMACase(ctx context.Context, _, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}

func sparesRouter(t *testing.T, store *stubCatalogue, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimSparesRoutes(v2, grantPool(t, perms...), handlers.NewSparesHandler(stubSpares{store}))
	return r
}

func sparesRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	item := base + "/inventory-items/" + uuid.NewString()
	rmaCase := base + "/rma-cases/" + uuid.NewString()
	return []catalogueRoute{
		{http.MethodPost, item + "/install", `{"asset_id":"` + uuid.NewString() + `"}`, true, http.StatusOK},
		{http.MethodPost, item + "/remove", `{"location_id":"` + uuid.NewString() + `"}`, true, http.StatusOK},
		{http.MethodPost, item + "/rma", `{"vendor":"Acme"}`, true, http.StatusOK},
		{http.MethodGet, base + "/rma-cases", "", false, http.StatusOK},
		{http.MethodGet, rmaCase, "", false, http.StatusOK},
		{http.MethodPatch, rmaCase, `{"state":"shipped"}`, true, http.StatusOK},
	}
}

func TestDcimSparesRoutes_Gates(t *testing.T) {
	for _, rt := range sparesRoutes() {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(sparesRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(sparesRouter(t, store, rbac.PermissionDcimRead), rt)
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
			w := serveCatalogue(sparesRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(sparesRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a spares route: status %d", w.Code)
			}
		})
	}
}

// A body that names no asset (install) or no stock location (remove), or
// carries a field the action does not take, is refused before the store.
//
// Mutation: drop `in.AssetID == uuid.Nil` from SparesHandler.Install, or the
// DisallowUnknownFields in decodeSpareBody → red.
func TestDcimSparesRoutes_RefuseBadBodies(t *testing.T) {
	base := "/api/v2/inventory-service/dcim/inventory-items/" + uuid.NewString()
	for _, rt := range []catalogueRoute{
		{http.MethodPost, base + "/install", `{}`, true, http.StatusBadRequest},
		{http.MethodPost, base + "/remove", `{"name":"x"}`, true, http.StatusBadRequest},
		{http.MethodPost, base + "/rma", `{"state":"open"}`, true, http.StatusBadRequest},
	} {
		store := &stubCatalogue{}
		w := serveCatalogue(sparesRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
		if w.Code != http.StatusBadRequest || store.calls != 0 {
			t.Errorf("%s %s: status %d, store calls %d — want 400 and nothing reached", rt.method, rt.path, w.Code, store.calls)
		}
	}
}

func TestDcimSparesRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimSparesRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimSparesRoutes(apiv2, rawDB, …): the spares routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/rma-cases`) {
		t.Fatal("main.go registers an RMA route directly, outside the gated mount function")
	}
}
