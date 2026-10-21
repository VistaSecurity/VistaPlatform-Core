package main

// The capacity route's permission gate, through the REAL mount function main()
// calls and the REAL RequireTenantPermission middleware: no grant → 403 and the
// store is never reached; dcim.read → 200; dcim.manage alone and ipam.* open
// nothing (read access is its own grant).
//
// Mutation: drop `read` from the GET in dcim_capacity_routes.go → the no-grant
// subtest fails; delete the registration → 404 and every subtest fails; delete
// the mountDcimCapacityRoutes call in main.go → TestDcimCapacityRoutes_MountedByMain.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type stubCapacity struct{ calls int }

func (s *stubCapacity) Report(context.Context, uuid.UUID) (services.CapacityReport, error) {
	s.calls++
	return services.CapacityReport{}, nil
}

func capacityRouter(t *testing.T, store *stubCapacity, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimCapacityRoutes(v2, grantPool(t, perms...), handlers.NewCapacityHandler(store))
	return r
}

func TestDcimCapacityRoutes_Gates(t *testing.T) {
	rt := catalogueRoute{http.MethodGet, "/api/v2/inventory-service/dcim/capacity", "", false, http.StatusOK}
	cases := []struct {
		name  string
		perms []string
		code  int
		calls int
	}{
		{"no grant", nil, http.StatusForbidden, 0},
		{"dcim.read", []string{rbac.PermissionDcimRead}, http.StatusOK, 1},
		{"dcim.manage alone", []string{rbac.PermissionDcimManage}, http.StatusForbidden, 0},
		{"ipam.read", []string{rbac.PermissionIpamRead, rbac.PermissionIpamManage}, http.StatusForbidden, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := &stubCapacity{}
			w := serveComponent(capacityRouter(t, store, c.perms...), rt)
			if w.Code != c.code || store.calls != c.calls {
				t.Fatalf("status %d (store calls %d), want %d (%d): %s", w.Code, store.calls, c.code, c.calls, w.Body.String())
			}
		})
	}
}

func TestDcimCapacityRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimCapacityRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimCapacityRoutes(apiv2, rawDB, …): the capacity route is not served")
	}
}
