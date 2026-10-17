package main

// Config-context permission gates (DCIM row 5.3) through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware.
//
// Mutation: drop `read`/`manage` from any registration in
// dcim_config_context_routes.go -> a subtest fails.

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

type stubConfigContexts struct {
	calls    int
	sawActor bool
}

func (s *stubConfigContexts) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}
func (s *stubConfigContexts) List(ctx context.Context, _ uuid.UUID, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubConfigContexts) Get(ctx context.Context, _, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubConfigContexts) Create(ctx context.Context, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubConfigContexts) Update(ctx context.Context, _, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubConfigContexts) Delete(ctx context.Context, _, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubConfigContexts) Render(ctx context.Context, _, _ uuid.UUID) (services.RenderedConfigContext, error) {
	s.note(ctx)
	return services.RenderedConfigContext{Data: map[string]any{}, Contributing: []services.ConfigContextRef{}}, nil
}

func configContextRouter(t *testing.T, store *stubConfigContexts, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimConfigContextRoutes(v2, grantPool(t, perms...), handlers.NewConfigContextHandler(store))
	return r
}

func TestDcimConfigContextRoutes_Gates(t *testing.T) {
	base := "/api/v2/inventory-service/dcim"
	one := base + "/config-contexts/" + uuid.NewString()
	routes := []contactRoute{
		{http.MethodGet, base + "/config-contexts", "", "", false, http.StatusOK},
		{http.MethodGet, one, "", "", false, http.StatusOK},
		{http.MethodPost, base + "/config-contexts", `{}`, "", true, http.StatusCreated},
		{http.MethodPatch, one, `{}`, "", true, http.StatusOK},
		{http.MethodDelete, one, "", "", true, http.StatusNoContent},
		{http.MethodGet, base + "/assets/" + uuid.NewString() + "/config-context", "", "", false, http.StatusOK},
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubConfigContexts{}
			w := serveContact(configContextRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubConfigContexts{}
			w := serveContact(configContextRouter(t, store, rbac.PermissionDcimRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, calls %d", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubConfigContexts{}
			w := serveContact(configContextRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("no actor on the store's context — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubConfigContexts{}
			w := serveContact(configContextRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a config-context route: status %d", w.Code)
			}
		})
	}
}

func TestDcimConfigContextRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimConfigContextRoutes\(apiv2, rawDB,`).Match(raw) {
		t.Fatal("main.go does not call mountDcimConfigContextRoutes(apiv2, rawDB, …): the routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/config-contexts`) {
		t.Fatal("main.go registers a config-context route directly, outside the gated mount function")
	}
}
