package main

// Export-template permission gates (DCIM row 5.5) through the REAL mount
// functions main() calls and the REAL RequireTenantPermission middleware, plus
// the format=template branch and the preview route.
//
// Mutation: drop `read`/`manage` from a registration in
// dcim_export_template_routes.go or the preview registration in
// dcim_bulk_routes.go -> a subtest fails; drop WithTemplates -> the render test fails.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

type stubExportTemplates struct {
	calls    int
	sawActor bool
	tpl      services.ExportTemplate
}

func (s *stubExportTemplates) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}
func (s *stubExportTemplates) List(ctx context.Context, _ uuid.UUID, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubExportTemplates) Get(ctx context.Context, _, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubExportTemplates) Create(ctx context.Context, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubExportTemplates) Update(ctx context.Context, _, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubExportTemplates) Delete(ctx context.Context, _, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubExportTemplates) Template(ctx context.Context, _, _ uuid.UUID) (services.ExportTemplate, error) {
	s.note(ctx)
	return s.tpl, nil
}

func exportTemplateRouter(t *testing.T, store *stubExportTemplates, bulk handlers.BulkStore, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	pool := grantPool(t, perms...)
	mountDcimExportTemplateRoutes(v2, pool, handlers.NewExportTemplateHandler(store))
	mountDcimBulkRoutes(v2, pool, bulk, store)
	return r
}

func TestDcimExportTemplateRoutes_Gates(t *testing.T) {
	base := "/api/v2/inventory-service/dcim"
	one := base + "/export-templates/" + uuid.NewString()
	routes := []contactRoute{
		{http.MethodGet, base + "/export-templates", "", "", false, http.StatusOK},
		{http.MethodGet, one, "", "", false, http.StatusOK},
		{http.MethodPost, base + "/export-templates", `{}`, "", true, http.StatusCreated},
		{http.MethodPatch, one, `{}`, "", true, http.StatusOK},
		{http.MethodDelete, one, "", "", true, http.StatusNoContent},
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubExportTemplates{}
			w := serveContact(exportTemplateRouter(t, store, nil), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubExportTemplates{}
			w := serveContact(exportTemplateRouter(t, store, nil, rbac.PermissionDcimRead), rt)
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
			store := &stubExportTemplates{}
			w := serveContact(exportTemplateRouter(t, store, nil, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("no actor on the store's context — changes.Middleware is not mounted")
			}
		})
	}
}

// exportBulk is a bulk store whose export emits two rows.
type exportBulk struct{ bulkStubStore }

func (s *exportBulk) Export(_ context.Context, _ uuid.UUID, _ string, _ services.BulkExportQuery, emit func(services.BulkRecord) error) error {
	s.calls++
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		if err := emit(services.BulkRecord{"name": n}); err != nil {
			return err
		}
	}
	return nil
}

func TestDcimExportTemplateRoutes_TemplateFormatAndPreview(t *testing.T) {
	base := "/api/v2/inventory-service/dcim"
	id := uuid.NewString()
	newStore := func() *stubExportTemplates {
		return &stubExportTemplates{tpl: services.ExportTemplate{
			ObjectKinds: []string{"prefix"}, MimeType: "text/x-test", FileExtension: "tst",
			Template: `{{range .Rows}}<{{.name}}>{{end}}`}}
	}
	bulk := func() *exportBulk {
		return &exportBulk{bulkStubStore{BulkImportService: services.NewBulkImportService(nil, services.BulkDeps{})}}
	}
	do := func(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}

	b := bulk()
	mk := func(perms ...string) *gin.Engine {
		return exportTemplateRouter(t, newStore(), b, perms...)
	}
	w := do(mk(rbac.PermissionIpamRead), http.MethodGet, base+"/export?kind=prefix&format=template&template_id="+id, "")
	if w.Code != http.StatusOK || w.Body.String() != "<a><b><c><d><e><f><g>" || w.Header().Get("Content-Type") != "text/x-test" ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "prefix-export.tst") {
		t.Fatalf("template export: %d %q %v", w.Code, w.Body.String(), w.Header())
	}
	// Gated like any export: no ipam.read -> 403 and the store untouched.
	b.calls = 0
	if w := do(mk(rbac.PermissionDcimRead), http.MethodGet, base+"/export?kind=prefix&format=template&template_id="+id, ""); w.Code != http.StatusForbidden || b.calls != 0 {
		t.Fatalf("template export without the kind's read permission: %d (calls %d)", w.Code, b.calls)
	}
	// A template not offered for the kind is refused.
	if w := do(mk(rbac.PermissionIpamRead, rbac.PermissionDcimRead), http.MethodGet, base+"/export?kind=vlan&format=template&template_id="+id, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("template for the wrong kind: %d", w.Code)
	}
	// Preview: dcim.manage + the kind's read; five rows.
	body := `{"kind":"prefix","template":"{{.Count}}:{{range .Rows}}{{.name}}{{end}}"}`
	if w := do(mk(rbac.PermissionIpamRead), http.MethodPost, base+"/export/preview", body); w.Code != http.StatusForbidden {
		t.Fatalf("preview without dcim.manage: %d", w.Code)
	}
	if w := do(mk(rbac.PermissionDcimManage), http.MethodPost, base+"/export/preview", body); w.Code != http.StatusForbidden {
		t.Fatalf("preview without the kind's read: %d", w.Code)
	}
	w = do(mk(rbac.PermissionDcimManage, rbac.PermissionIpamRead), http.MethodPost, base+"/export/preview", body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"output":"5:abcde"`) {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	w = do(mk(rbac.PermissionDcimManage, rbac.PermissionIpamRead), http.MethodPost, base+"/export/preview", `{"kind":"prefix","template":"{{.ReadFile}}"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_template") {
		t.Fatalf("preview of a sandbox escape: %d %s", w.Code, w.Body.String())
	}
}

func TestDcimExportTemplateRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimExportTemplateRoutes\(apiv2, rawDB,`).Match(raw) {
		t.Fatal("main.go does not call mountDcimExportTemplateRoutes(apiv2, rawDB, …): the routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/export-templates`) {
		t.Fatal("main.go registers an export-template route directly, outside the gated mount function")
	}
}
