package main

// Saved Filters routes (BUILD_PLAN row 5.4) through the REAL mount function and
// the REAL RequireTenantPermission. The pool answers user_has_permission() from
// a grant table (grantPool, dcim_substrate_routes_test.go).
//
// Mutation: drop `read` from any registration -> the no-grant role reaches the
// stub and TestSavedFilterRoutes_Gate fails; make savedFilterCanShare return
// true -> TestSavedFilterRoutes_ShareRightComesFromSettingsUpdate fails.

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

type stubFilters struct {
	calls    int
	canShare bool
	sawActor bool
}

func (s *stubFilters) note(ctx context.Context, who services.SavedFilterCaller) {
	s.calls++
	s.canShare = who.CanShare
	_, s.sawActor = changes.ActorFrom(ctx)
}
func (s *stubFilters) List(ctx context.Context, _, user uuid.UUID, _ string) ([]services.SavedFilter, error) {
	s.note(ctx, services.SavedFilterCaller{UserID: user, CanShare: s.canShare})
	return []services.SavedFilter{}, nil
}
func (s *stubFilters) Create(ctx context.Context, _ uuid.UUID, who services.SavedFilterCaller, _ services.SavedFilterInput) (services.SavedFilter, error) {
	s.note(ctx, who)
	return services.SavedFilter{ID: uuid.New()}, nil
}
func (s *stubFilters) Update(ctx context.Context, _ uuid.UUID, who services.SavedFilterCaller, id uuid.UUID, _ services.SavedFilterInput) (services.SavedFilter, error) {
	s.note(ctx, who)
	return services.SavedFilter{ID: id}, nil
}
func (s *stubFilters) Delete(ctx context.Context, _ uuid.UUID, who services.SavedFilterCaller, _ uuid.UUID) error {
	s.note(ctx, who)
	return nil
}

func filterRouter(t *testing.T, store *stubFilters, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
	})
	db := grantPool(t, perms...)
	mountDcimSavedFilterRoutes(v2, db, handlers.NewDcimSavedFilterHandler(store, savedFilterCanShare(db)))
	return r
}

const filterBody = `{"name":"x","object_kinds":["asset"],"query":"risk >= high"}`

func filterRoutes() []substrateRoute {
	base := "/api/v2/inventory-service/dcim/saved-filters"
	one := base + "/" + uuid.NewString()
	return []substrateRoute{
		{http.MethodGet, base + "?kind=asset", "", false, http.StatusOK},
		{http.MethodPost, base, filterBody, true, http.StatusCreated},
		{http.MethodPut, one, filterBody, true, http.StatusOK},
		{http.MethodDelete, one, "", true, http.StatusNoContent},
	}
}

func serveFilter(r http.Handler, rt substrateRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, body))
	return w
}

func TestSavedFilterRoutes_Gate(t *testing.T) {
	for _, rt := range filterRoutes() {
		t.Run(rt.method, func(t *testing.T) {
			none := &stubFilters{}
			if w := serveFilter(filterRouter(t, none), rt); w.Code != http.StatusForbidden || none.calls != 0 {
				t.Fatalf("no assets.read: status %d, store calls %d, want 403 and nothing reached", w.Code, none.calls)
			}
			ok := &stubFilters{}
			if w := serveFilter(filterRouter(t, ok, rbac.PermissionAssetsRead), rt); w.Code != rt.want {
				t.Fatalf("assets.read: status %d, want %d (%s)", w.Code, rt.want, w.Body.String())
			}
			if !ok.sawActor {
				t.Fatal("changes.Middleware is not mounted: the store's context carried no actor")
			}
		})
	}
}

func TestSavedFilterRoutes_ShareRightComesFromSettingsUpdate(t *testing.T) {
	post := filterRoutes()[1]
	plain := &stubFilters{}
	serveFilter(filterRouter(t, plain, rbac.PermissionAssetsRead), post)
	if plain.calls != 1 || plain.canShare {
		t.Fatalf("assets.read only: calls=%d canShare=%v, want a call with canShare=false", plain.calls, plain.canShare)
	}
	admin := &stubFilters{}
	serveFilter(filterRouter(t, admin, rbac.PermissionAssetsRead, rbac.PermissionSettingsUpdate), post)
	if admin.calls != 1 || !admin.canShare {
		t.Fatalf("with settings.update: calls=%d canShare=%v, want canShare=true", admin.calls, admin.canShare)
	}
}

func TestSavedFilterRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimSavedFilterRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimSavedFilterRoutes(apiv2, rawDB, …): the Saved Filter routes are not served")
	}
}
