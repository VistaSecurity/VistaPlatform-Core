package services

// DB-integration tests for the asset commercial lifecycle (DCIM gap 4).
// Skipped unless TEST_DATABASE_URL is set; run with make test-integration-db.
//
// The catalogue service and the asset reads run on the NON-OWNER app role, so
// RLS is in force; the owner connection seeds the platform end-of-life
// catalogue rows, as the admin catalogue feed does.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// lcEOLSeed inserts an end-of-life catalogue entry and removes it when the test
// ends (the catalogue is platform-wide, shared by every test tenant).
func lcEOLSeed(t *testing.T, owner *sql.DB, kind, product, eol, extended string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	nullable := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	if err := owner.QueryRow(`INSERT INTO eol_catalogue (product_kind, vendor, product, cycle, eol_date, extended_support_date)
		VALUES ($1, 'Acme', $2, '1', $3::date, $4::date) RETURNING id`, kind, product, nullable(eol), nullable(extended)).Scan(&id); err != nil {
		t.Fatalf("seed eol_catalogue: %v", err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM eol_catalogue WHERE id = $1`, id) })
	return id
}

func lcPatch(t *testing.T, kv map[string]any) HardwarePatch {
	t.Helper()
	p := HardwarePatch{}
	for k, v := range kv {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		p[k] = raw
	}
	return p
}

func lcStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// The whole path a person takes: link a device type and a platform to the
// end-of-life catalogue, record an asset's commercial columns through the
// hardware PATCH, and read the computed lifecycle back from the Hardware view,
// the single-asset read and the list. Declared dates win over the catalogue;
// the earlier of the type and the platform is the asset's.
//
// Mutation: make eolCatalogueOfKind return nil → the platform linked to a
// hardware entry is accepted; drop the platforms FK guard in POST-MIGRATIONS →
// the link dangles after its entry is deleted; drop the `lc_dte.eol_date` fallback (or swap
// COALESCE's arguments in loadHardwareLifecycle's eosDate) → the catalogue
// source assertions fail; drop the changes.InTx(...).Record call in
// writeAssetHardware → the object_changes count is 0.
func TestIntegration_AssetLifecycle_PatchCatalogueFallbackAndReads(t *testing.T) {
	owner, app, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()
	assets := NewAssetService(&database.DB{DB: sqlx.NewDb(app, "postgres")})
	suffix := uuid.NewString()[:8]
	hwEntry := lcEOLSeed(t, owner, "hardware", "AX-48 "+suffix, "2025-06-30", "2026-06-30")
	osEntry := lcEOLSeed(t, owner, "os", "AcmeOS "+suffix, "2031-01-01", "")

	mfr := catID(t, lcRaw(t)(svc.Create(ctx, tenant, "manufacturers", []byte(`{"name":"Acme `+suffix+`"}`))))
	// The link is checked by kind: a platform cannot fall back to a hardware
	// model's date, nor a device type to an operating system's.
	if _, err := svc.Create(ctx, tenant, "platforms", []byte(fmt.Sprintf(`{"name":"P-%s","eol_catalogue_id":%q}`, suffix, hwEntry))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("platform linked to a hardware entry: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, "device-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":"Bad","eol_catalogue_id":%q}`, mfr, osEntry))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("device type linked to an os entry: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, "device-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":"Ghost","eol_catalogue_id":%q}`, mfr, uuid.New()))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("device type linked to no entry: %v, want invalid", err)
	}
	plat := catID(t, lcRaw(t)(svc.Create(ctx, tenant, "platforms", []byte(fmt.Sprintf(`{"name":"AcmeOS %s","eol_catalogue_id":%q}`, suffix, osEntry)))))
	dt := catID(t, lcRaw(t)(svc.Create(ctx, tenant, "device-types", []byte(fmt.Sprintf(
		`{"manufacturer_id":%q,"model":"AX-48","end_of_sale":"2024-12-31","eol_catalogue_id":%q}`, mfr, hwEntry)))))

	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	warrantyEnd := time.Now().UTC().AddDate(0, 0, 30).Format(isoDate)
	hw, err := svc.UpdateHardware(ctx, tenant, asset, lcPatch(t, map[string]any{
		"device_type_id": dt.String(), "platform_id": plat.String(),
		"purchase_date": "2024-03-01", "warranty_start": "2024-03-01", "warranty_end": warrantyEnd,
		"purchase_cost": 1999.9, "purchase_currency": "eur", "purchase_order": "PO-1001", "vendor": "Acme Resale",
		"support_contract": "SC-77", "support_contract_end": "2027-03-31", "installed_at": "2024-03-15",
	}))
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	c := hw.Commercial
	if c.PurchaseCost == nil || *c.PurchaseCost != 1999.9 || lcStr(c.PurchaseCurrency) != "EUR" || lcStr(c.Vendor) != "Acme Resale" ||
		lcStr(c.WarrantyEnd) != warrantyEnd || c.DecommissionedAt != nil {
		t.Fatalf("commercial after patch: %+v", c)
	}
	if hw.DeviceTypeEOS == nil || !lcEOS(hw.DeviceTypeEOS.EndOfSale, "2024-12-31", models.EOSSourceDecl) ||
		lcStr(hw.DeviceTypeEOS.EndOfSupport.Date) != "2025-06-30" || hw.DeviceTypeEOS.EndOfSupport.Source != models.EOSSourceCat ||
		lcStr(hw.DeviceTypeEOS.EndOfLife.Date) != "2026-06-30" || hw.DeviceTypeEOS.EndOfLife.Source != models.EOSSourceCat ||
		hw.DeviceTypeEOS.EOLCatalogue == nil || hw.DeviceTypeEOS.EOLCatalogue.ID != hwEntry {
		t.Fatalf("device type dates: %+v", hw.DeviceTypeEOS)
	}
	if hw.PlatformEOS == nil || lcStr(hw.PlatformEOS.EndOfSupport.Date) != "2031-01-01" || hw.PlatformEOS.EndOfLife.Source != models.EOSSourceNone {
		t.Fatalf("platform dates: %+v", hw.PlatformEOS)
	}
	lc := hw.Lifecycle
	if lc.WarrantyState != models.WarrantyExpiring90 || lc.EOSState != models.EOSPastEOS || lcStr(lc.EffectiveEndOfSupport) != "2025-06-30" ||
		lc.Source != models.EOSSourceCat || lcStr(lc.Subject) != models.EOSSubjectDT {
		t.Fatalf("lifecycle: %+v", lc)
	}
	var recorded int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'asset' AND object_id = $2
		AND action = 'update' AND changed_fields @> ARRAY['purchase_cost', 'warranty_end', 'vendor']::text[]`, tenant, asset).Scan(&recorded); err != nil || recorded != 1 {
		t.Fatalf("object_changes rows for the commercial edit: %d (%v), want 1", recorded, err)
	}

	// A declared end of support on the type wins over its catalogue entry, and
	// the platform's earlier catalogue date then becomes the asset's.
	if _, err := svc.Update(ctx, tenant, "device-types", dt, []byte(`{"end_of_support":"2032-01-01"}`)); err != nil {
		t.Fatalf("declare end_of_support: %v", err)
	}
	hw, err = svc.Hardware(ctx, tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	if !lcEOS(hw.DeviceTypeEOS.EndOfSupport, "2032-01-01", models.EOSSourceDecl) {
		t.Fatalf("declared date did not win: %+v", hw.DeviceTypeEOS.EndOfSupport)
	}
	if lc = hw.Lifecycle; lcStr(lc.EffectiveEndOfSupport) != "2031-01-01" || lc.Source != models.EOSSourceCat || lcStr(lc.Subject) != models.EOSSubjectPlat {
		t.Fatalf("lifecycle after declaring: %+v", lc)
	}

	// The asset reads carry the same fields and the same computed block.
	got, err := assets.GetAssetByID(tenant, asset)
	if err != nil {
		t.Fatal(err)
	}
	if got.Lifecycle == nil || !lcSame(*got.Lifecycle, hw.Lifecycle) || lcStr(got.PurchaseCurrency) != "EUR" || lcStr(got.SupportContract) != "SC-77" {
		t.Fatalf("GetAssetByID lifecycle %+v / commercial %+v, want %+v", got.Lifecycle, got.AssetCommercial, hw.Lifecycle)
	}
	list, _, err := assets.GetAssets(tenant, models.AssetFilters{Query: `vendor = "Acme Resale"`, Page: 1, PageSize: 50})
	if err != nil || len(list) != 1 || list[0].Lifecycle == nil || !lcSame(*list[0].Lifecycle, hw.Lifecycle) {
		t.Fatalf("GetAssets by vendor: %d rows (%v)", len(list), err)
	}

	// An asset with nothing recorded is unknown on both counts — never healthy.
	bare := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if b, err := assets.GetAssetByID(tenant, bare); err != nil || b.Lifecycle == nil ||
		b.Lifecycle.WarrantyState != models.WarrantyUnknown || b.Lifecycle.EOSState != models.EOSUnknown || b.Lifecycle.Source != models.EOSSourceNone {
		t.Fatalf("bare asset lifecycle: %+v (%v)", b, err)
	}

	// The catalogue entry going away clears the link (ON DELETE SET NULL); the
	// declared dates stay.
	if _, err := owner.Exec(`DELETE FROM eol_catalogue WHERE id = $1`, osEntry); err != nil {
		t.Fatal(err)
	}
	var link sql.NullString
	if err := owner.QueryRow(`SELECT eol_catalogue_id::text FROM platforms WHERE id = $1`, plat).Scan(&link); err != nil || link.Valid {
		t.Fatalf("platforms.eol_catalogue_id after its entry was deleted: %v (%v), want NULL (ON DELETE SET NULL)", link, err)
	}
	hw, err = svc.Hardware(ctx, tenant, asset)
	if err != nil || hw.PlatformEOS.EOLCatalogue != nil || hw.PlatformEOS.EndOfSupport.Source != models.EOSSourceNone ||
		lcStr(hw.Lifecycle.EffectiveEndOfSupport) != "2032-01-01" || hw.Lifecycle.Source != models.EOSSourceDecl {
		t.Fatalf("after the catalogue entry was deleted: %+v %+v (%v)", hw.PlatformEOS, hw.Lifecycle, err)
	}
}

func lcEOS(d EOSDate, date, source string) bool { return lcStr(d.Date) == date && d.Source == source }

func lcSame(a, b models.AssetLifecycle) bool {
	return a.WarrantyState == b.WarrantyState && a.EOSState == b.EOSState && a.Source == b.Source &&
		lcStr(a.EffectiveEndOfSupport) == lcStr(b.EffectiveEndOfSupport) && lcStr(a.Subject) == lcStr(b.Subject)
}

func lcRaw(t *testing.T) func(json.RawMessage, error) json.RawMessage {
	return func(raw json.RawMessage, err error) json.RawMessage {
		t.Helper()
		if err != nil {
			t.Fatalf("catalogue write: %v", err)
		}
		return raw
	}
}

// The validation a person meets in the form, on the real write path, and the
// tenant boundary: another tenant cannot write an asset's commercial columns.
func TestIntegration_AssetLifecycle_PatchValidationAndTenantIsolation(t *testing.T) {
	owner, _, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := svc.UpdateHardware(ctx, tenant, asset, lcPatch(t, map[string]any{"warranty_start": "2026-01-01"})); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]map[string]any{
		"warranty ends before it starts": {"warranty_end": "2025-12-31"},
		"not a date":                     {"purchase_date": "01/02/2026"},
		"negative cost":                  {"purchase_cost": -5},
		"three decimals":                 {"purchase_cost": "1.005"},
		"not a currency":                 {"purchase_currency": "EURO"},
		"unknown field":                  {"purchase_price": "5"},
	} {
		if _, err := svc.UpdateHardware(ctx, tenant, asset, lcPatch(t, p)); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	// The CHECK backs the service: a direct write of a lower-case currency is
	// refused by the database itself.
	if _, err := owner.Exec(`UPDATE assets SET purchase_currency = 'eur' WHERE tenant_id = $1 AND id = $2`, tenant, asset); err == nil ||
		!strings.Contains(err.Error(), "assets_purchase_currency_check") {
		t.Fatalf("lower-case currency reached the column: %v", err)
	}
	other := testdb.NewTenant(t, owner)
	if _, err := svc.UpdateHardware(ctx, other, asset, lcPatch(t, map[string]any{"vendor": "Mallory"})); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("another tenant patched the asset: %v, want not found", err)
	}
	var vendor sql.NullString
	if err := owner.QueryRow(`SELECT vendor FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, asset).Scan(&vendor); err != nil || vendor.Valid {
		t.Fatalf("vendor after the cross-tenant attempt: %v (%v)", vendor, err)
	}
}

// The query language's `end_of_support` (shared/query/sql
// AssetEffectiveEndOfSupportSQL) and ComputeAssetLifecycle are two spellings
// of one rule; over every shape — declared, catalogue, platform only, both
// (earlier wins), neither — the date the SQL filters on is the date the Go
// read reports.
//
// Mutation: swap LEAST for GREATEST in AssetEffectiveEndOfSupportSQL, or the
// COALESCE arguments → a shape's boundary assertion fails.
func TestIntegration_AssetLifecycle_QueryLanguageEffectiveEndOfSupport(t *testing.T) {
	owner, app, tenant, svc := catFixture(t)
	ctx := ifaceActorCtx()
	assets := NewAssetService(&database.DB{DB: sqlx.NewDb(app, "postgres")})
	suffix := uuid.NewString()[:8]
	hwEntry := lcEOLSeed(t, owner, "hardware", "QX "+suffix, "2027-05-31", "")
	osEntry := lcEOLSeed(t, owner, "os", "QOS "+suffix, "2028-02-29", "")
	mfr := catID(t, lcRaw(t)(svc.Create(ctx, tenant, "manufacturers", []byte(`{"name":"Q `+suffix+`"}`))))
	mkType := func(model, body string) uuid.UUID {
		return catID(t, lcRaw(t)(svc.Create(ctx, tenant, "device-types", []byte(fmt.Sprintf(`{"manufacturer_id":%q,"model":%q%s}`, mfr, model, body)))))
	}
	declared := mkType("declared", `,"end_of_support":"2029-09-30"`)
	catalogued := mkType("catalogued", fmt.Sprintf(`,"eol_catalogue_id":%q`, hwEntry))
	plat := catID(t, lcRaw(t)(svc.Create(ctx, tenant, "platforms", []byte(fmt.Sprintf(`{"name":"QOS %s","eol_catalogue_id":%q}`, suffix, osEntry)))))

	shapes := map[string]map[string]any{
		"declared":      {"device_type_id": declared.String()},
		"catalogue":     {"device_type_id": catalogued.String()},
		"platform-only": {"platform_id": plat.String()},
		"both-earlier":  {"device_type_id": declared.String(), "platform_id": plat.String()},
		"neither":       {"vendor": "Q " + suffix},
	}
	want := map[string]string{"declared": "2029-09-30", "catalogue": "2027-05-31", "platform-only": "2028-02-29", "both-earlier": "2028-02-29"}
	ids := map[uuid.UUID]string{}
	for name, p := range shapes {
		a := ifaceSeedAsset(t, owner, tenant, "monitoring")
		ids[a] = name
		hw, err := svc.UpdateHardware(ctx, tenant, a, lcPatch(t, p))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := lcStr(hw.Lifecycle.EffectiveEndOfSupport); got != want[name] {
			t.Fatalf("%s: Go effective %q, want %q", name, got, want[name])
		}
	}
	matched := func(q string) []string {
		t.Helper()
		rows, _, err := assets.GetAssets(tenant, models.AssetFilters{Query: q, Page: 1, PageSize: 100})
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		var out []string
		for _, r := range rows {
			if n, ok := ids[r.ID]; ok {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	for name, date := range want {
		d, _ := time.Parse(isoDate, date)
		on := matched("end_of_support <= " + date)
		before := matched("end_of_support < " + date)
		if !contains(on, name) || contains(before, name) {
			t.Errorf("%s (Go says %s): matched by <= %v, by < %v", name, date, on, before)
		}
		if after := matched("end_of_support > " + d.AddDate(0, 0, -1).Format(isoDate)); !contains(after, name) {
			t.Errorf("%s: not matched by > the day before", name)
		}
	}
	if all := matched("end_of_support:*"); contains(all, "neither") || len(all) != 4 {
		t.Errorf("end_of_support:* = %v, want the four shapes with a date", all)
	}
	if none := matched("not end_of_support:*"); !contains(none, "neither") || len(none) != 1 {
		t.Errorf("not end_of_support:* = %v, want only the asset with no date", none)
	}
}

// The picker's source: entries of one product kind, filtered by text.
func TestIntegration_AssetLifecycle_EOLCatalogueEntries(t *testing.T) {
	owner, _, tenant, svc := catFixture(t)
	suffix := uuid.NewString()[:8]
	hw := lcEOLSeed(t, owner, "hardware", "Picker "+suffix, "2026-01-01", "")
	lcEOLSeed(t, owner, "os", "Picker "+suffix, "2026-01-01", "")
	rows, err := svc.EOLCatalogueEntries(ifaceActorCtx(), tenant, "hardware", "picker "+suffix, 50)
	if err != nil || len(rows) != 1 || rows[0].ID != hw || rows[0].ProductKind != "hardware" || lcStr(rows[0].EOLDate) != "2026-01-01" {
		t.Fatalf("hardware entries: %+v (%v)", rows, err)
	}
	if _, err := svc.EOLCatalogueEntries(ifaceActorCtx(), tenant, "software", "", 50); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("software kind: %v, want invalid", err)
	}
}

// The asset import's dry run shows a commercial column that would change, and
// refuses a bad commercial cell as a row error — before anything is written.
//
// Mutation: drop the parseHardwareValue check in assetBulk's check → the bad
// date is not a row error in the dry run.
func TestIntegration_AssetLifecycle_ImportDryRunRefusesBadCommercialCell(t *testing.T) {
	f := newBulkImpFixture(t)
	tenant := testdb.NewTenant(t, f.owner)
	f.seed(t, tenant)
	csvBody, rows := f.export(t, tenant, "asset")
	if rows != 1 || !strings.Contains(csvBody, "2027-02-28") {
		t.Fatalf("the export does not carry the commercial columns:\n%s", csvBody)
	}
	changed := strings.Replace(csvBody, "2027-02-28", "2027-08-31", 1)
	plan := f.imp(t, tenant, "asset", changed, false)
	if plan.Summary.Error != 0 || len(plan.Rows) != 1 || !contains(plan.Rows[0].Changed, "warranty_end") || len(plan.Rows[0].Changed) != 1 {
		t.Fatalf("dry run of a warranty change: %+v (%s)", plan.Rows, bulkPlanErrors(plan))
	}
	bad := strings.Replace(csvBody, "2027-02-28", "28/02/2027", 1)
	plan = f.imp(t, tenant, "asset", bad, false)
	if plan.Summary.Error != 1 || !strings.Contains(plan.Rows[0].Reason, "warranty_end") {
		t.Fatalf("dry run of a bad warranty date: %+v", plan.Rows)
	}
	var end string
	if err := f.owner.QueryRow(`SELECT warranty_end::text FROM assets WHERE tenant_id = $1 AND warranty_end IS NOT NULL`, tenant).Scan(&end); err != nil || end != "2027-02-28" {
		t.Fatalf("warranty_end after two dry runs: %q (%v)", end, err)
	}
}
