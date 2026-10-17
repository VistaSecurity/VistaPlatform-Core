package main

// The device catalogue routes' permission gates (DCIM row 2.2), through the
// REAL mount function main() calls and the REAL RequireTenantPermission
// middleware (grantPool from dcim_substrate_routes_test.go answers
// user_has_permission). Every route: no grant → 403 and nothing reaches the
// store; dcim.read → reads succeed, writes 403; dcim.manage → writes reach the
// store with an actor on the context; ipam.manage opens nothing here.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// dcim_catalogue_routes.go → a subtest fails; delete a registration → the
// route answers 404 and its subtests fail.

import (
	"context"
	"encoding/json"
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

type stubCatalogue struct {
	calls    int
	sawActor bool
}

func (s *stubCatalogue) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}

func (s *stubCatalogue) List(ctx context.Context, _ uuid.UUID, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubCatalogue) Get(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCatalogue) Create(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCatalogue) Update(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCatalogue) Delete(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubCatalogue) ListTemplates(ctx context.Context, _ uuid.UUID, _ services.TemplateParent, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubCatalogue) GetTemplate(ctx context.Context, _ uuid.UUID, _ services.TemplateParent, _ string, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCatalogue) CreateTemplate(ctx context.Context, _ uuid.UUID, _ services.TemplateParent, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCatalogue) UpdateTemplate(ctx context.Context, _ uuid.UUID, _ services.TemplateParent, _ string, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCatalogue) DeleteTemplate(ctx context.Context, _ uuid.UUID, _ services.TemplateParent, _ string, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubCatalogue) Hardware(ctx context.Context, _, _ uuid.UUID) (*services.AssetHardware, error) {
	s.note(ctx)
	return &services.AssetHardware{}, nil
}
func (s *stubCatalogue) UpdateHardware(ctx context.Context, _, _ uuid.UUID, _ services.HardwarePatch) (*services.AssetHardware, error) {
	s.note(ctx)
	return &services.AssetHardware{}, nil
}
func (s *stubCatalogue) ApplyDeviceType(ctx context.Context, _, _, _ uuid.UUID) (*services.ApplyDeviceTypeResult, error) {
	s.note(ctx)
	return &services.ApplyDeviceTypeResult{}, nil
}

func (s *stubCatalogue) ImportDeviceTypes(ctx context.Context, _ uuid.UUID, _ []byte) ([]services.ImportedDeviceType, error) {
	s.note(ctx)
	return []services.ImportedDeviceType{}, nil
}

func catalogueRouter(t *testing.T, store *stubCatalogue, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimCatalogueRoutes(v2, grantPool(t, perms...), handlers.NewCatalogueHandler(store))
	return r
}

type catalogueRoute struct {
	method, path, body string
	write              bool
	want               int
}

func catalogueRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	var out []catalogueRoute
	crud := func(list, one string) {
		out = append(out,
			catalogueRoute{http.MethodGet, list, "", false, http.StatusOK},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, list, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	for _, r := range services.CatalogueObjectRoutes() {
		crud(base+"/"+r, base+"/"+r+"/"+uuid.NewString())
	}
	for parent, kinds := range map[string][]string{
		"device-types": services.DeviceTypeTemplateRoutes(),
		"module-types": services.ModuleTypeTemplateRoutes(),
	} {
		for _, k := range kinds {
			list := base + "/" + parent + "/" + uuid.NewString() + "/" + k
			crud(list, list+"/"+uuid.NewString())
		}
	}
	asset := base + "/assets/" + uuid.NewString()
	out = append(out,
		catalogueRoute{http.MethodGet, asset + "/hardware", "", false, http.StatusOK},
		catalogueRoute{http.MethodPatch, asset + "/hardware", `{"serial":"FOC1"}`, true, http.StatusOK},
		catalogueRoute{http.MethodPost, asset + "/device-type", `{"device_type_id":"` + uuid.NewString() + `"}`, true, http.StatusOK},
		catalogueRoute{http.MethodPost, base + "/device-types/import", `{"yaml":"manufacturer: A\nmodel: B\n"}`, true, http.StatusOK},
	)
	return out
}

func serveCatalogue(r http.Handler, rt catalogueRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, body))
	return w
}

func TestDcimCatalogueRoutes_Gates(t *testing.T) {
	routes := catalogueRoutes()
	if want := 5*5 + 9*5 + 8*5 + 4; len(routes) != want {
		t.Fatalf("expected %d catalogue routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(catalogueRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(catalogueRouter(t, store, rbac.PermissionDcimRead), rt)
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
			w := serveCatalogue(catalogueRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubCatalogue{}
			w := serveCatalogue(catalogueRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a catalogue route: status %d", w.Code)
			}
		})
	}
}

func TestDcimCatalogueRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimCatalogueRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimCatalogueRoutes(apiv2, rawDB, …): the catalogue routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/device-types`) {
		t.Fatal("main.go registers a catalogue route directly, outside the gated mount function")
	}
}
