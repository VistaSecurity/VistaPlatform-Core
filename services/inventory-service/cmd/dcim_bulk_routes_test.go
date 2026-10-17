package main

// The bulk import/export routes' permission gates (DCIM BUILD_PLAN row 2.7),
// through the REAL mount function main() calls and the REAL
// RequireTenantPermission middleware over a fake grant pool. What a person may
// import depends on the kind: prefixes need ipam.manage, business units
// business_units.manage; exports need the kind's read permission.
//
// Mutation: make the handler skip authorize() on Import or Export → the
// no-grant and wrong-grant roles reach the stub store.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// bulkStubStore answers the registry questions from the real service (so the
// permission each kind names is the real one) and counts the calls that would
// read or write.
type bulkStubStore struct {
	*services.BulkImportService
	calls int
}

func (s *bulkStubStore) Import(context.Context, uuid.UUID, string, io.Reader, bool) (*services.BulkPlan, error) {
	s.calls++
	return &services.BulkPlan{Rows: []services.BulkRowResult{}}, nil
}

func (s *bulkStubStore) Export(context.Context, uuid.UUID, string, services.BulkExportQuery, func(services.BulkRecord) error) error {
	s.calls++
	return nil
}

// CustomFieldColumns reads the tenant's definitions; the stub has no database.
func (s *bulkStubStore) CustomFieldColumns(context.Context, uuid.UUID, string) ([]string, error) {
	return nil, nil
}

func TestDcimBulkRoutes_PermissionGates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const base = "/api/v2/inventory-service/dcim"
	routes := []struct {
		name, method, path string
		need               string // the permission that opens it
	}{
		{"kinds", http.MethodGet, base + "/import/kinds", rbac.PermissionDcimRead},
		{"template", http.MethodGet, base + "/import/template?kind=prefix", rbac.PermissionDcimRead},
		{"import prefix", http.MethodPost, base + "/import?kind=prefix&mode=dry_run", rbac.PermissionIpamManage},
		{"import business unit", http.MethodPost, base + "/import?kind=business_unit&mode=apply", rbac.PermissionBusinessUnitsManage},
		{"import interface", http.MethodPost, base + "/import?kind=interface", rbac.PermissionDcimManage},
		{"export prefix", http.MethodGet, base + "/export?kind=prefix", rbac.PermissionIpamRead},
		{"export asset", http.MethodGet, base + "/export?kind=asset&format=json", rbac.PermissionAssetsRead},
		{"export device type", http.MethodGet, base + "/export?kind=device_type", rbac.PermissionDcimRead},
	}
	allPerms := []string{rbac.PermissionDcimRead, rbac.PermissionDcimManage, rbac.PermissionIpamRead, rbac.PermissionIpamManage,
		rbac.PermissionBusinessUnitsManage, rbac.PermissionAssetsRead}
	for _, rt := range routes {
		// Granted: exactly the permission the route needs (plus dcim.read where the
		// route is gated on it, which the kinds/template routes are by themselves).
		for _, tc := range []struct {
			who   string
			perms []string
			ok    bool
		}{
			{"none", nil, false},
			{"everything but the needed", without(allPerms, rt.need), false},
			{"only the needed", []string{rt.need}, true},
		} {
			t.Run(rt.name+" "+tc.who, func(t *testing.T) {
				store := &bulkStubStore{BulkImportService: services.NewBulkImportService(nil, services.BulkDeps{})}
				r := gin.New()
				r.Use(func(c *gin.Context) {
					c.Set("userID", uuid.New())
					c.Set("tenantID", uuid.New())
				})
				mountDcimBulkRoutes(r.Group("/api/v2"), ifaceGrantPool(t, tc.perms...), store, nil)
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, strings.NewReader("a\n1\n")))
				touched := store.calls > 0 || w.Code == http.StatusOK
				if tc.ok && (w.Code != http.StatusOK) {
					t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
				}
				if !tc.ok && (w.Code != http.StatusForbidden || store.calls != 0) {
					t.Fatalf("want 403 with the store untouched, got %d (calls=%d, touched=%v)", w.Code, store.calls, touched)
				}
			})
		}
	}
}

func without(all []string, drop string) []string {
	var out []string
	for _, p := range all {
		if p != drop {
			out = append(out, p)
		}
	}
	return out
}

// An unknown kind is a 400 that never reaches the store, whoever asks.
func TestDcimBulkRoutes_UnknownKindAndBadMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &bulkStubStore{BulkImportService: services.NewBulkImportService(nil, services.BulkDeps{})}
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", uuid.New()); c.Set("tenantID", uuid.New()) })
	mountDcimBulkRoutes(r.Group("/api/v2"), ifaceGrantPool(t, rbac.PermissionIpamManage, rbac.PermissionIpamRead, rbac.PermissionDcimRead), store, nil)
	for _, p := range []string{
		"/api/v2/inventory-service/dcim/import?kind=nope",
		"/api/v2/inventory-service/dcim/import?kind=prefix&mode=sideways",
		"/api/v2/inventory-service/dcim/export?kind=prefix&format=xml",
		"/api/v2/inventory-service/dcim/import/template?kind=nope",
	} {
		method := http.MethodGet
		if strings.Contains(p, "/import?") {
			method = http.MethodPost
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, p, strings.NewReader("a\n1\n")))
		if w.Code != http.StatusBadRequest || store.calls != 0 {
			t.Fatalf("%s: want 400 untouched, got %d (calls=%d)", p, w.Code, store.calls)
		}
	}
}

func TestDcimBulkRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "mountDcimBulkRoutes(apiv2, rawDB,") {
		t.Fatal("main.go does not mount the bulk routes through mountDcimBulkRoutes")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/import`) || strings.Contains(string(raw), `"/inventory-service/dcim/export`) {
		t.Fatal("main.go registers a bulk route directly, outside the gated mount function")
	}
}

var _ handlers.BulkStore = (*bulkStubStore)(nil)
