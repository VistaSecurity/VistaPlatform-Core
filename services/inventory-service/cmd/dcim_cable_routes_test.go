package main

// The cable routes' permission gates (DCIM row 3.2), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware: no
// grant → 403 and nothing reaches the store; dcim.read → reads (and every
// trace) succeed, writes 403; dcim.manage → writes reach the store with an
// actor on the context; ipam.* opens nothing.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// dcim_cable_routes.go → a subtest fails; delete a registration → that route
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
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type stubCables struct {
	calls    int
	sawActor bool
	kinds    []dcim.ObjectKind
}

func (s *stubCables) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}

func (s *stubCables) List(ctx context.Context, _ uuid.UUID, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubCables) Get(ctx context.Context, _, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCables) Create(ctx context.Context, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCables) Update(ctx context.Context, _, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCables) Delete(ctx context.Context, _, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubCables) Approve(ctx context.Context, _, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCables) Reject(ctx context.Context, _, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCables) Trace(ctx context.Context, _ uuid.UUID, k dcim.ObjectKind, _ uuid.UUID) (services.TraceResult, error) {
	s.note(ctx)
	s.kinds = append(s.kinds, k)
	return services.TraceResult{}, nil
}

func (s *stubCables) InterfacePosture(ctx context.Context, _, _ uuid.UUID) (services.AssetInterfacePosture, error) {
	s.note(ctx)
	return services.AssetInterfacePosture{}, nil
}

func cableRouter(t *testing.T, store *stubCables, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimCableRoutes(v2, grantPool(t, perms...), handlers.NewCableHandler(store))
	return r
}

func cableRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/dcim"
	one := base + "/cables/" + uuid.NewString()
	out := []catalogueRoute{
		{http.MethodGet, base + "/cables", "", false, http.StatusOK},
		{http.MethodPost, base + "/cables", `{}`, true, http.StatusCreated},
		{http.MethodGet, one, "", false, http.StatusOK},
		{http.MethodPatch, one, `{}`, true, http.StatusOK},
		{http.MethodDelete, one, "", true, http.StatusNoContent},
		// Row 3.3: accepting or refusing an LLDP / CDP proposal is a write.
		{http.MethodPost, one + "/approve", "", true, http.StatusOK},
		{http.MethodPost, one + "/reject", "", true, http.StatusOK},
	}
	for _, k := range []string{"interfaces", "front-ports", "rear-ports", "console-ports", "console-server-ports", "circuit-terminations",
		"power-ports", "power-outlets", "power-feeds"} {
		out = append(out, catalogueRoute{http.MethodGet, base + "/" + k + "/" + uuid.NewString() + "/trace", "", false, http.StatusOK})
	}
	out = append(out, catalogueRoute{http.MethodGet, base + "/assets/" + uuid.NewString() + "/interface-posture", "", false, http.StatusOK})
	return out
}

func TestDcimCableRoutes_Gates(t *testing.T) {
	routes := cableRoutes()
	if len(routes) != 17 {
		t.Fatalf("expected 17 cable routes, got %d", len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCables{}
			w := serveComponent(cableRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubCables{}
			w := serveComponent(cableRouter(t, store, rbac.PermissionDcimRead), rt)
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
			store := &stubCables{}
			w := serveComponent(cableRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubCables{}
			w := serveComponent(cableRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a cable route: status %d", w.Code)
			}
		})
	}
}

// Each trace route asks the store for its own kind (a copy-paste of one
// route's segment would trace the wrong table).
func TestDcimCableRoutes_TraceKinds(t *testing.T) {
	store := &stubCables{}
	r := cableRouter(t, store, rbac.PermissionDcimRead)
	want := map[string]dcim.ObjectKind{
		"interfaces": dcim.ObjectKindInterface, "front-ports": dcim.ObjectKindFrontPort, "rear-ports": dcim.ObjectKindRearPort,
		"console-ports": dcim.ObjectKindConsolePort, "console-server-ports": dcim.ObjectKindConsoleServerPort,
		"circuit-terminations": dcim.ObjectKindCircuitTermination,
		// Row 6.1: the power ends.
		"power-ports": dcim.ObjectKindPowerPort, "power-outlets": dcim.ObjectKindPowerOutlet, "power-feeds": dcim.ObjectKindPowerFeed,
	}
	for seg, k := range want {
		store.kinds = nil
		w := serveComponent(r, catalogueRoute{http.MethodGet, "/api/v2/inventory-service/dcim/" + seg + "/" + uuid.NewString() + "/trace", "", false, http.StatusOK})
		if w.Code != http.StatusOK || len(store.kinds) != 1 || store.kinds[0] != k {
			t.Fatalf("%s: status %d, traced %v, want %s", seg, w.Code, store.kinds, k)
		}
	}
}

func TestDcimCableRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimCableRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimCableRoutes(apiv2, rawDB, …): the cable routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/cables`) {
		t.Fatal("main.go registers a cable route directly, outside the gated mount function")
	}
}
