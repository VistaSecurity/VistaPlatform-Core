package services

// DB-integration tests for config contexts (DCIM BUILD_PLAN row 5.3). Skipped
// unless TEST_DATABASE_URL is set; run with make test-integration-db. The
// service runs on the NON-OWNER app role, so RLS is in force as in production.

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func ccBody(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RLS: tenant B sees none of tenant A's contexts, cannot read them by id, and
// a context cannot be assigned to another tenant's objects.
//
// Mutation: drop config_contexts_tenant_isolation (or ENABLE ROW LEVEL
// SECURITY) -> B lists A's context.
func TestIntegration_ConfigContexts_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewConfigContextService(app)

	row, err := svc.Create(ctx, tenantA, ccBody(t, map[string]any{"name": "ntp", "data": map[string]any{"ntp": "a"}}))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := catID(t, row)
	rows, total, err := svc.List(ctx, tenantB, IPAMListParams{Limit: 50})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B listed %d/%d of tenant A's contexts (%v)", len(rows), total, err)
	}
	if _, err := svc.Get(ctx, tenantB, id); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B Get of A's context: %v, want not found", err)
	}
	// The insert path: B's connection cannot write a row for A.
	if _, err := app.Exec(`INSERT INTO config_contexts (tenant_id, name) VALUES ($1, 'x')`, tenantA); err == nil {
		t.Fatal("app role inserted a config context with no tenant GUC set")
	}
	// A rendered config never crosses tenants either.
	assetB := ifaceSeedAsset(t, owner, tenantB, "monitoring")
	out, err := svc.Render(ctx, tenantB, assetB)
	if err != nil || len(out.Contributing) != 0 {
		t.Fatalf("tenant B's asset rendered A's context: %+v (%v)", out, err)
	}
	// Writes are recorded.
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'config_context'`, tenantA).Scan(&n); err != nil || n < 1 {
		t.Fatalf("no object_changes row for the create (%d, %v)", n, err)
	}
}

// The rendered config of a real asset: weight order, deep merge, an inactive
// context excluded, assignment match on role / business unit / tag, and an
// unassigned context applying to all.
//
// Mutation: drop the weight sort in RenderConfigContexts -> the heavy value no
// longer wins.
func TestIntegration_ConfigContexts_Render(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewConfigContextService(app)

	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	other := ifaceSeedAsset(t, owner, tenant, "monitoring")
	var role, bu, tag uuid.UUID
	if err := owner.QueryRow(`INSERT INTO device_roles (tenant_id, name, slug) VALUES ($1, 'firewall', 'firewall-'||substr(gen_random_uuid()::text,1,6)) RETURNING id`, tenant).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1, 'Payments', 'payments') RETURNING id`, tenant).Scan(&bu); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(`INSERT INTO tags (tenant_id, name, slug) VALUES ($1, 'edge', 'edge') RETURNING id`, tenant).Scan(&tag); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`UPDATE assets SET device_role_id = $3, business_unit_id = $4 WHERE tenant_id = $1 AND id = $2`, tenant, asset, role, bu); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO object_tags (tenant_id, object_kind, object_id, tag_id) VALUES ($1, 'asset', $2, $3)`, tenant, asset, tag); err != nil {
		t.Fatal(err)
	}

	mk := func(m map[string]any) {
		t.Helper()
		if _, err := svc.Create(ctx, tenant, ccBody(t, m)); err != nil {
			t.Fatalf("create %v: %v", m["name"], err)
		}
	}
	mk(map[string]any{"name": "base", "weight": 100, "data": map[string]any{"ntp": "base", "dns": map[string]any{"servers": []any{"1.1.1.1"}, "search": "corp"}}})
	mk(map[string]any{"name": "fw", "weight": 500, "device_roles": []any{role.String()}, "data": map[string]any{"dns": map[string]any{"servers": []any{"9.9.9.9"}}, "fw": true}})
	mk(map[string]any{"name": "pay", "weight": 900, "business_units": []any{bu.String()}, "tags": []any{tag.String()}, "data": map[string]any{"ntp": "pay"}})
	mk(map[string]any{"name": "off", "weight": 950, "is_active": false, "data": map[string]any{"ntp": "off"}})
	mk(map[string]any{"name": "elsewhere", "weight": 960, "business_units": []any{bu.String()}, "device_roles": []any{role.String()}, "tags": []any{}, "data": map[string]any{"e": 1}})

	out, err := svc.Render(ctx, tenant, asset)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	got, _ := json.Marshal(out.Data)
	want := `{"dns":{"search":"corp","servers":["9.9.9.9"]},"e":1,"fw":true,"ntp":"pay"}`
	if string(got) != want {
		t.Fatalf("rendered %s, want %s", got, want)
	}
	names := []string{}
	for _, c := range out.Contributing {
		names = append(names, c.Name)
	}
	if len(names) != 4 || names[0] != "base" || names[1] != "fw" || names[2] != "pay" || names[3] != "elsewhere" {
		t.Fatalf("contributing %v", names)
	}

	// An asset with none of the attributes gets only the unassigned context.
	out, err = svc.Render(ctx, tenant, other)
	if err != nil || len(out.Contributing) != 1 || out.Contributing[0].Name != "base" {
		t.Fatalf("plain asset: %+v (%v)", out, err)
	}
	if _, err := svc.Render(ctx, tenant, uuid.New()); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("unknown asset: %v, want not found", err)
	}

	// Validation: a dimension id that is not the tenant's is refused; a
	// non-object data value is refused.
	if _, err := svc.Create(ctx, tenant, ccBody(t, map[string]any{"name": "bad", "device_roles": []any{uuid.NewString()}})); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("unknown role id: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, ccBody(t, map[string]any{"name": "bad2", "data": []any{1}})); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("array data: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, ccBody(t, map[string]any{"name": "base"})); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("duplicate name: %v, want conflict", err)
	}
}
