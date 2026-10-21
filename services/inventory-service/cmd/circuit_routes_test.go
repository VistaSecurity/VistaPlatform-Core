package main

// The circuit routes' permission gates (DCIM row 4.1), through the REAL mount
// function main() calls and the REAL RequireTenantPermission middleware
// (grantPool from dcim_substrate_routes_test.go answers user_has_permission).
// Every route: no grant → 403 and nothing reaches the store; circuits.read →
// reads succeed, writes 403; circuits.manage → writes reach the store with an
// actor on the context; dcim.manage opens nothing here.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// circuit_routes.go → a subtest fails; delete a registration → the route
// answers 404 and its subtests fail; drop the mount from main.go →
// TestCircuitRoutes_MountedByMain fails.

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

type stubCircuits struct {
	calls    int
	sawActor bool
}

func (s *stubCircuits) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}

func (s *stubCircuits) List(ctx context.Context, _ uuid.UUID, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubCircuits) Get(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCircuits) Create(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCircuits) Update(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubCircuits) Delete(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}

func circuitRouter(t *testing.T, store *stubCircuits, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountCircuitRoutes(v2, grantPool(t, perms...), handlers.NewCircuitHandler(store))
	return r
}

func circuitRoutes() []catalogueRoute {
	base := "/api/v2/inventory-service/circuits"
	var out []catalogueRoute
	for _, r := range services.CircuitObjectRoutes() {
		list, one := base+"/"+r, base+"/"+r+"/"+uuid.NewString()
		out = append(out,
			catalogueRoute{http.MethodGet, list, "", false, http.StatusOK},
			catalogueRoute{http.MethodGet, one, "", false, http.StatusOK},
			catalogueRoute{http.MethodPost, list, `{}`, true, http.StatusCreated},
			catalogueRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			catalogueRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	return out
}

func serveCircuit(r http.Handler, rt catalogueRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, body))
	return w
}

func TestCircuitRoutes_Gates(t *testing.T) {
	routes := circuitRoutes()
	if want := 11 * 5; len(routes) != want {
		t.Fatalf("expected %d circuit routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubCircuits{}
			w := serveCircuit(circuitRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no circuits grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("circuits.read/"+name, func(t *testing.T) {
			store := &stubCircuits{}
			w := serveCircuit(circuitRouter(t, store, rbac.PermissionCircuitsRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with circuits.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("circuits.manage/"+name, func(t *testing.T) {
			store := &stubCircuits{}
			w := serveCircuit(circuitRouter(t, store, rbac.PermissionCircuitsRead, rbac.PermissionCircuitsManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubCircuits{}
			w := serveCircuit(circuitRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("dcim permissions opened a circuit route: status %d", w.Code)
			}
		})
	}
}

func TestCircuitRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountCircuitRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountCircuitRoutes(apiv2, rawDB, …): the circuit routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/circuits/`) {
		t.Fatal("main.go registers a circuit route directly, outside the gated mount function")
	}
}
