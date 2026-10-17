package services

// Custom fields on the hand-written write paths (DCIM row 5.1), against a
// real Postgres: assets (UpdateAsset), interfaces (InterfaceService) and
// business units (BusinessUnitService) each call the validator themselves,
// so each is driven through its REAL service method here. The engine path
// (IPAM, catalogue, circuits, wireless, contacts) is driven through its real
// route in cmd/custom_field_routes_integration_test.go.
//
// Mutations: delete the `if input.CustomFields != nil {…}` block in
// UpdateAsset → the asset subtests go red (the refused update is written);
// delete the validateCustomFieldsTx call in InterfaceService.BulkCreate → the
// interface test goes red; delete it from BusinessUnitService.createTx → the
// business-unit test goes red.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type cfExec interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// defineCustomField inserts a definition as the owner (the routes that write
// definitions are tested through the real router elsewhere).
func defineCustomField(t *testing.T, db cfExec, tenant uuid.UUID, name, typ, kind string, required bool, choices ...string) {
	t.Helper()
	var set any
	if len(choices) > 0 {
		pairs := "["
		for i, c := range choices {
			if i > 0 {
				pairs += ","
			}
			pairs += `["` + c + `","` + c + `"]`
		}
		pairs += "]"
		var id uuid.UUID
		if err := db.QueryRow(`INSERT INTO custom_field_choice_sets (tenant_id, name, choices) VALUES ($1, $2, $3::jsonb) RETURNING id`,
			tenant, name+"-set", pairs).Scan(&id); err != nil {
			t.Fatalf("choice set: %v", err)
		}
		set = id
	}
	if _, err := db.Exec(`INSERT INTO custom_fields (tenant_id, name, type, object_kinds, required, choice_set_id) VALUES ($1, $2, $3, ARRAY[$4], $5, $6)`,
		tenant, name, typ, kind, required, set); err != nil {
		t.Fatalf("define %s: %v", name, err)
	}
}

func TestIntegration_CustomFields_AssetUpdate(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	assetID := seedPlainAsset(t, svc, db, tenant, "cf-asset", "192.0.2.91", "28:cf:da:aa:cc:91")
	actor := seedClassReviewer(t, db, tenant)
	defineCustomField(t, db, tenant, "owner_team", "text", "asset", true)
	defineCustomField(t, db, tenant, "tier", "select", "asset", false, "gold", "silver")

	update := func(cf map[string]interface{}) error {
		_, _, err := svc.UpdateAsset(tenant, assetID, models.AssetInput{CustomFields: cf}, actor)
		return err
	}
	stored := func() map[string]interface{} {
		a, err := svc.GetAssetByID(tenant, assetID)
		if err != nil {
			t.Fatal(err)
		}
		return a.CustomFields
	}

	t.Run("a required field left empty refuses the update", func(t *testing.T) {
		if err := update(map[string]interface{}{"tier": "gold"}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("got %v, want ErrInvalidInput", err)
		}
		if len(stored()) != 0 {
			t.Fatalf("a refused update was written: %v", stored())
		}
	})
	t.Run("a choice outside the set is refused", func(t *testing.T) {
		if err := update(map[string]interface{}{"owner_team": "net", "tier": "bronze"}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("got %v, want ErrInvalidInput", err)
		}
	})
	t.Run("valid values are stored and read back", func(t *testing.T) {
		if err := update(map[string]interface{}{"owner_team": "Net", "tier": "gold"}); err != nil {
			t.Fatal(err)
		}
		if got := stored(); got["owner_team"] != "Net" || got["tier"] != "gold" {
			t.Fatalf("stored %v", got)
		}
	})
	t.Run("cf.<name> matches through the asset list's query", func(t *testing.T) {
		all := []string{"pending_approval", "monitoring", "denied", "archived"}
		hit, _, err := svc.GetAssets(tenant, models.AssetFilters{Query: "cf.owner_team:net", AssetStatus: all})
		if err != nil {
			t.Fatal(err)
		}
		if len(hit) != 1 || hit[0].ID != assetID {
			t.Fatalf("cf.owner_team:net matched %d assets, want the one", len(hit))
		}
		miss, _, err := svc.GetAssets(tenant, models.AssetFilters{Query: "cf.owner_team:ops", AssetStatus: all})
		if err != nil {
			t.Fatal(err)
		}
		if len(miss) != 0 {
			t.Fatalf("cf.owner_team:ops matched %d assets, want none", len(miss))
		}
	})
}

func TestIntegration_CustomFields_InterfaceCreate(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	defineCustomField(t, owner, tenant, "patch_panel", "text", "interface", true)
	svc := NewInterfaceService(app)
	ctx := ifaceActorCtx()

	_, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "eth0", Type: "1000base-t"})
	var ve *InterfaceValidationError
	if !errors.As(err, &ve) || ve.Field != "custom_fields" {
		t.Fatalf("interface without its required field: %v, want a custom_fields validation error", err)
	}
	got, err := svc.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "eth0", Type: "1000base-t",
		CustomFields: map[string]any{"patch_panel": "PP-01"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.CustomFields["patch_panel"] != "PP-01" {
		t.Fatalf("stored %v", got.CustomFields)
	}
}

func TestIntegration_CustomFields_BusinessUnitCreate(t *testing.T) {
	svc, _, tenant, db := buFixture(t)
	defineCustomField(t, db, tenant, "cost_center", "integer", "business_unit", true)
	ctx := context.Background()

	if _, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Finance")}); !errors.Is(err, ErrBusinessUnitInvalid) {
		t.Fatalf("unit without its required field: %v, want ErrBusinessUnitInvalid", err)
	}
	if _, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Finance"),
		CustomFields: map[string]interface{}{"cost_center": "abc"}}); !errors.Is(err, ErrBusinessUnitInvalid) {
		t.Fatalf("an integer field given text: %v, want ErrBusinessUnitInvalid", err)
	}
	bu, err := svc.Create(ctx, tenant, uuid.Nil, models.BusinessUnitInput{Name: sp("Finance"),
		CustomFields: map[string]interface{}{"cost_center": 4100}})
	if err != nil {
		t.Fatal(err)
	}
	if bu.CustomFields["cost_center"] != float64(4100) {
		t.Fatalf("stored %v", bu.CustomFields)
	}
	// A unit named on an asset form is created implicitly: its required
	// fields are not enforced, so the asset edit is not refused for them.
	if _, err := svc.ResolveOrCreateByName(ctx, tenant, uuid.Nil, "Implicit"); err != nil {
		t.Fatalf("implicit create: %v", err)
	}
}

// The bulk importer's `cf.<name>` columns for an engine kind: a required field
// missing from a created row is that row's error, a value outside the choices
// is refused, a valid one is stored, and the export carries the column back.
//
// Mutation: drop the `patch["custom_fields"] = cf` in bulk_import_engine.go's
// row → the stored value and the export column go red.
func TestIntegration_CustomFields_BulkImportExport(t *testing.T) {
	f := newBulkImpFixture(t)
	tenant := testdb.NewTenant(t, f.owner)
	defineCustomField(t, f.owner, tenant, "owner_team", "text", "prefix", true)
	defineCustomField(t, f.owner, tenant, "tier", "select", "prefix", false, "gold", "silver")

	imp := func(body string) *BulkPlan {
		t.Helper()
		plan, err := f.svc.Import(f.ctx, tenant, "prefix", strings.NewReader(body), true)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	plan := imp("prefix,cf.owner_team,cf.tier\n10.92.0.0/24,,\n10.92.1.0/24,net,bronze\n10.92.2.0/24,net,gold\n")
	if len(plan.Unknown) != 0 {
		t.Fatalf("cf. columns reported unknown: %v", plan.Unknown)
	}
	if plan.Rows[0].Action != BulkError || !strings.Contains(plan.Rows[0].Reason, "required") {
		t.Errorf("row without owner_team: %+v", plan.Rows[0])
	}
	if plan.Rows[1].Action != BulkError || !strings.Contains(plan.Rows[1].Reason, "choices") {
		t.Errorf("row with tier bronze: %+v", plan.Rows[1])
	}
	if plan.Rows[2].Action != BulkCreate {
		t.Fatalf("valid row: %+v", plan.Rows[2])
	}
	var stored string
	if err := f.owner.QueryRow(`SELECT custom_fields->>'tier' FROM prefixes WHERE tenant_id = $1 AND prefix = '10.92.2.0/24'`, tenant).Scan(&stored); err != nil || stored != "gold" {
		t.Fatalf("stored tier %q (%v)", stored, err)
	}
	cols, err := f.svc.CustomFieldColumns(f.ctx, tenant, "prefix")
	if err != nil || strings.Join(cols, ",") != "cf.owner_team,cf.tier" {
		t.Fatalf("export columns %v (%v)", cols, err)
	}
	var got []BulkRecord
	if err := f.svc.Export(f.ctx, tenant, "prefix", BulkExportQuery{}, func(r BulkRecord) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0]["cf.tier"] != "gold" || got[0]["cf.owner_team"] != "net" {
		t.Fatalf("export %v", got)
	}
	// Re-importing the export is a no-op; a changed cell is an update naming it.
	if p := imp("prefix,cf.owner_team,cf.tier\n10.92.2.0/24,net,gold\n"); p.Rows[0].Action != BulkUnchanged {
		t.Errorf("re-import: %+v", p.Rows[0])
	}
	if p := imp("prefix,cf.tier\n10.92.2.0/24,silver\n"); p.Rows[0].Action != BulkUpdate || strings.Join(p.Rows[0].Changed, ",") != "cf.tier" {
		t.Errorf("update tier: %+v", p.Rows[0])
	}
}
