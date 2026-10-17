package services

// DB-integration tests for export templates (DCIM BUILD_PLAN row 5.5). Skipped
// unless TEST_DATABASE_URL is set; run with make test-integration-db. The
// service runs on the NON-OWNER app role, so RLS is in force as in production.

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Mutation: drop export_templates_tenant_isolation (or ENABLE ROW LEVEL
// SECURITY) -> B lists A's template.
func TestIntegration_ExportTemplates_RLSAndSave(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewExportTemplateService(app)

	row, err := svc.Create(ctx, tenantA, ccBody(t, map[string]any{
		"name": "hosts", "object_kinds": []string{"prefix"}, "template": `{{range .Rows}}{{.name}}{{"\n"}}{{end}}`,
		"mime_type": "text/plain", "file_extension": "txt"}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := catID(t, row)
	rows, total, err := svc.List(ctx, tenantB, IPAMListParams{Limit: 50})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B listed %d/%d of tenant A's templates (%v)", len(rows), total, err)
	}
	if _, err := svc.Template(ctx, tenantB, id); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B loaded A's template: %v", err)
	}
	if _, err := app.Exec(`INSERT INTO export_templates (tenant_id, name, object_kinds, template) VALUES ($1, 'x', '{prefix}', 'y')`, tenantA); err == nil {
		t.Fatal("app role inserted an export template with no tenant GUC set")
	}
	// Unique per tenant by name, free in another tenant.
	body := map[string]any{"name": "hosts", "object_kinds": []string{"vlan"}, "template": "x"}
	if _, err := svc.Create(ctx, tenantA, ccBody(t, body)); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("duplicate name: %v, want conflict", err)
	}
	if _, err := svc.Create(ctx, tenantB, ccBody(t, body)); err != nil {
		t.Fatalf("same name in another tenant: %v", err)
	}
	// The sandbox is enforced at save, on create and on update.
	for _, bad := range []string{`{{.ReadFile "/etc/passwd"}}`, `{{exec "id"}}`, `{{env "HOME"}}`, `{{call .Rows}}`} {
		if _, err := svc.Create(ctx, tenantA, ccBody(t, map[string]any{"name": "bad", "object_kinds": []string{"prefix"}, "template": bad})); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("create %q: %v, want invalid", bad, err)
		}
		if _, err := svc.Update(ctx, tenantA, id, ccBody(t, map[string]any{"template": bad})); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("update %q: %v, want invalid", bad, err)
		}
	}
	if _, err := svc.Create(ctx, tenantA, ccBody(t, map[string]any{"name": "k", "object_kinds": []string{"nope"}, "template": "x"})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("unknown kind: %v", err)
	}
	// ?object_kind= narrows the list; the stored template still renders.
	if rows, total, err := svc.List(ctx, tenantA, IPAMListParams{Limit: 50, Filters: map[string]string{"object_kind": "vlan"}}); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("vlan filter: %d/%d %v", len(rows), total, err)
	}
	got, err := svc.Template(ctx, tenantA, id)
	if err != nil || got.MimeType != "text/plain" || got.FileExtension != "txt" {
		t.Fatalf("template load: %+v %v", got, err)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'export_template'`, tenantA).Scan(&n); err != nil || n < 1 {
		t.Fatalf("no object_changes row for the create (%d, %v)", n, err)
	}
}
