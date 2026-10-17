package main

// The component routes' permission gates (DCIM row 3.1), through the REAL
// mount function main() calls and the REAL RequireTenantPermission middleware
// (grantPool from dcim_substrate_routes_test.go answers user_has_permission).
// Every route, every kind (power ports and outlets included): no grant → 403
// and nothing reaches the store; dcim.read → reads succeed, writes 403;
// dcim.manage → writes reach the store with an actor on the context; ipam.*
// opens nothing here.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// dcim_component_routes.go → a subtest fails; delete a registration → the
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

type stubComponents struct {
	calls    int
	sawActor bool
}

func (s *stubComponents) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}

func (s *stubComponents) List(ctx context.Context, _ uuid.UUID, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubComponents) ListForAsset(ctx context.Context, _, _ uuid.UUID, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubComponents) Get(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubComponents) Create(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubComponents) CreateForAsset(ctx context.Context, _, _ uuid.UUID, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubComponents) Update(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubComponents) Delete(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}

func componentRouter(t *testing.T, store *stubComponents, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimComponentRoutes(v2, grantPool(t, perms...), handlers.NewComponentHandler(store))
	return r
}

func componentRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	var out []catalogueRoute
	for _, k := range services.ComponentRoutes() {
		one := base + "/" + k + "/" + uuid.NewString()
		onAsset := base + "/assets/" + uuid.NewString() + "/" + k
		out = append(out,
			catalogueRoute{http.MethodGet, base + "/" + k, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, base + "/" + k, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
			catalogueRoute{http.MethodGet, onAsset, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, onAsset, `{}`, true, http.StatusCreated},
		)
	}
	return out
}

func serveComponent(r http.Handler, rt catalogueRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, body))
	return w
}

func TestDcimComponentRoutes_Gates(t *testing.T) {
	routes := componentRoutes()
	if want := 7 * 7; len(routes) != want {
		t.Fatalf("expected %d component routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubComponents{}
			w := serveComponent(componentRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubComponents{}
			w := serveComponent(componentRouter(t, store, rbac.PermissionDcimRead), rt)
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
			w := serveComponent(componentRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubComponents{}
			w := serveComponent(componentRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a component route: status %d", w.Code)
			}
		})
	}
}

func TestDcimComponentRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimComponentRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimComponentRoutes(apiv2, rawDB, …): the component routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/rear-ports`) {
		t.Fatal("main.go registers a component route directly, outside the gated mount function")
	}
}
