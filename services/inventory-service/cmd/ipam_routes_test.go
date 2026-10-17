package main

// The IPAM routes' permission gates, through the REAL mount function main()
// calls and the REAL RequireTenantPermission middleware (grantPool from
// dcim_substrate_routes_test.go answers user_has_permission). Every route of
// every object: no grant → 403 and nothing reaches the store; ipam.read →
// reads succeed, writes 403; ipam.manage → writes reach the store with an
// actor on the context.
//
// Mutation: drop `read` from any GET, or `manage` from any write, in
// ipam_routes.go → a subtest fails.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

type stubIPAM struct {
	calls    int
	sawActor bool
}

func (s *stubIPAM) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}

func (s *stubIPAM) List(ctx context.Context, _ uuid.UUID, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubIPAM) Get(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubIPAM) Create(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubIPAM) Update(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubIPAM) Delete(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubIPAM) PrefixDetail(ctx context.Context, _, _ uuid.UUID, _ services.PrefixDetailParams) (*services.PrefixDetail, error) {
	s.note(ctx)
	return &services.PrefixDetail{}, nil
}
func (s *stubIPAM) PrefixTree(ctx context.Context, _ uuid.UUID, _ *uuid.UUID) ([]*services.PrefixTreeNode, int, error) {
	s.note(ctx)
	return []*services.PrefixTreeNode{}, 0, nil
}
func (s *stubIPAM) FindAddress(ctx context.Context, _ uuid.UUID, _ netip.Addr, _ *uuid.UUID, _ bool) ([]services.FindResult, error) {
	s.note(ctx)
	return []services.FindResult{}, nil
}

func ipamRouter(t *testing.T, store *stubIPAM, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountIPAMRoutes(v2, grantPool(t, perms...), handlers.NewIPAMHandler(store))
	return r
}

type ipamRoute struct {
	method, path, body string
	write              bool
	want               int
}

func ipamRoutes() []ipamRoute {
	base := "/api/v2/inventory-service/ipam"
	out := []ipamRoute{
		{http.MethodGet, base + "/find?address=10.0.0.5", "", false, http.StatusOK},
		{http.MethodGet, base + "/prefixes/tree?vrf=global", "", false, http.StatusOK},
	}
	for _, r := range services.IPAMRoutes() {
		one := base + "/" + r + "/" + uuid.NewString()
		out = append(out,
			ipamRoute{http.MethodGet, base + "/" + r, "", false, http.StatusOK},
			ipamRoute{http.MethodGet, one, "", false, http.StatusOK},
			ipamRoute{http.MethodPost, base + "/" + r, `{}`, true, http.StatusCreated},
			ipamRoute{http.MethodPatch, one, `{}`, true, http.StatusOK},
			ipamRoute{http.MethodDelete, one, "", true, http.StatusNoContent},
		)
	}
	return out
}

func serveIPAM(r http.Handler, rt ipamRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, body))
	return w
}

func TestIPAMRoutes_Gates(t *testing.T) {
	routes := ipamRoutes()
	if len(routes) != 2+5*13 {
		t.Fatalf("expected 13 IPAM objects × 5 routes + find + tree, got %d routes", len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveIPAM(ipamRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no ipam grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("ipam.read/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveIPAM(ipamRouter(t, store, rbac.PermissionIpamRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with ipam.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveIPAM(ipamRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != rt.want {
				t.Fatalf("status %d, want %d (%s)", w.Code, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		// The DCIM family is not the IPAM family: dcim.manage opens nothing here.
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubIPAM{}
			w := serveIPAM(ipamRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("dcim permissions opened an IPAM route: status %d", w.Code)
			}
		})
	}
}

func TestIPAMRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountIPAMRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountIPAMRoutes(apiv2, rawDB, …): the IPAM routes are not served")
	}
}
