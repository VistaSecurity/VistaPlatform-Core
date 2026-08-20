package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// DB-backed integration tests for the EntitlementsService. Skipped
// without TEST_DATABASE_URL — same convention as the resolver and
// trial-bootstrap suites elsewhere in the tree.

const skip = "TEST_DATABASE_URL not set; skipping DB-backed entitlements-service tests"

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip(skip)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test db: %v", err)
	}
	return db
}

// applySchemaAndSeed delegates to the shared harness (advisory-lock
// serialized — concurrent appliers hit "tuple concurrently updated").
func applySchemaAndSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	testdb.ApplySchemaAndSeed(t, db)
}

func setup(t *testing.T) (*EntitlementsService, *sql.DB) {
	t.Helper()
	db := openTestDB(t)
	applySchemaAndSeed(t, db)
	// Tests use a single real connection for both handles; the bypass
	// path is exercised identically against the test DB.
	return NewEntitlementsService(db, db), db
}

func tierID(t *testing.T, db *sql.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM subscription_tiers WHERE name = $1`, name).Scan(&id); err != nil {
		t.Fatalf("tier %q lookup: %v", name, err)
	}
	return id
}

// ---------------------------------------------------------------------------
// Restoring shared reference state
//
// These tests run against a SHARED TEST_DATABASE_URL, and setup()'s
// testdb.ApplySchemaAndSeed CANNOT undo a mutated seed row: seed.sql inserts
// both billable_items and tier_entitlements with ON CONFLICT DO NOTHING, so a
// row that still exists is never rewritten. Anything this package UPDATEs in
// place on a seeded catalogue row therefore leaks — out of the test, out of the
// package, and into every other service's DB-integration suite.
//
// That is not hypothetical. TestUpdateBillableItem_RewritesNonKeyFields left
// max_sensors.default_value at {"quantity": 42}, and a tier-less tenant
// resolves max_sensors straight from that default, so auth-service's
// TestIntegration_UnknownDefaultSignupTier_DoesNotFailSignup then failed with
// "tier-less tenant was allowed a sensor; capacity caps must fail closed" —
// reading exactly like an auth-service bug.
//
// Any test here that mutates a seeded global row must register one of these.
// ---------------------------------------------------------------------------

// restoreBillableItem snapshots a catalogue row and writes it back verbatim
// when the test ends.
func restoreBillableItem(t *testing.T, db *sql.DB, id uuid.UUID) {
	t.Helper()
	before := snapshotRow(t, db, `SELECT to_jsonb(bi) FROM billable_items bi WHERE id = $1`, id)

	t.Cleanup(func() {
		// updated_at is trigger-owned and deliberately not restored.
		_, err := db.Exec(`
			UPDATE billable_items bi SET
				key                       = r.key,
				display_name              = r.display_name,
				description               = r.description,
				category                  = r.category,
				kind                      = r.kind,
				unit                      = r.unit,
				default_value             = r.default_value,
				is_addon_eligible         = r.is_addon_eligible,
				default_addon_price_cents = r.default_addon_price_cents,
				is_active                 = r.is_active,
				sort_order                = r.sort_order,
				created_at                = r.created_at
			FROM jsonb_populate_record(NULL::billable_items, $2::jsonb) r
			WHERE bi.id = $1`, id, before)
		if err != nil {
			t.Errorf("restore billable_items row %s: %v", id, err)
			return
		}
		// Self-check: the SET list above enumerates columns, so a column added
		// to billable_items later would silently stop being restored. Diffing
		// the whole row against the snapshot makes that fail loudly here
		// instead of in some other service's suite.
		after := snapshotRow(t, db, `SELECT to_jsonb(bi) FROM billable_items bi WHERE id = $1`, id)
		if drifted := diffRowKeys(t, before, after, "updated_at"); len(drifted) > 0 {
			t.Errorf("billable_items row %s not fully restored; columns still differing: %v "+
				"(add them to restoreBillableItem's SET list)", id, drifted)
		}
	})
}

// restoreTierEntitlements snapshots a tier's whole entitlement matrix and
// restores it when the test ends. Whole-matrix rather than per-row because
// ReplaceTierEntitlements deletes every row for the tier before writing.
func restoreTierEntitlements(t *testing.T, db *sql.DB, tier uuid.UUID) {
	t.Helper()
	before := snapshotRow(t, db,
		`SELECT coalesce(jsonb_agg(to_jsonb(te)), '[]'::jsonb) FROM tier_entitlements te WHERE tier_id = $1`, tier)

	t.Cleanup(func() {
		tx, err := db.Begin()
		if err != nil {
			t.Errorf("restore tier_entitlements for %s: begin: %v", tier, err)
			return
		}
		defer func() { _ = tx.Rollback() }()

		if _, err := tx.Exec(`DELETE FROM tier_entitlements WHERE tier_id = $1`, tier); err != nil {
			t.Errorf("restore tier_entitlements for %s: clear: %v", tier, err)
			return
		}
		// SELECT * is column-proof: no enumeration to keep in sync.
		if _, err := tx.Exec(`
			INSERT INTO tier_entitlements
			SELECT * FROM jsonb_populate_recordset(NULL::tier_entitlements, $1::jsonb)`, before); err != nil {
			t.Errorf("restore tier_entitlements for %s: reinsert: %v", tier, err)
			return
		}
		if err := tx.Commit(); err != nil {
			t.Errorf("restore tier_entitlements for %s: commit: %v", tier, err)
		}
	})
}

func snapshotRow(t *testing.T, db *sql.DB, query string, args ...any) []byte {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(query, args...).Scan(&raw); err != nil {
		t.Fatalf("snapshot for restore (%s): %v", query, err)
	}
	return raw
}

// diffRowKeys returns the column names whose values differ between two
// to_jsonb() row snapshots, ignoring the named columns.
func diffRowKeys(t *testing.T, before, after []byte, ignore ...string) []string {
	t.Helper()
	var b, a map[string]json.RawMessage
	if err := json.Unmarshal(before, &b); err != nil {
		t.Errorf("decode snapshot: %v", err)
		return nil
	}
	if err := json.Unmarshal(after, &a); err != nil {
		t.Errorf("decode restored row: %v", err)
		return nil
	}
	skip := make(map[string]bool, len(ignore))
	for _, k := range ignore {
		skip[k] = true
	}
	seen := make(map[string]bool, len(b)+len(a))
	var drifted []string
	for _, m := range []map[string]json.RawMessage{b, a} {
		for k := range m {
			if skip[k] || seen[k] {
				continue
			}
			seen[k] = true
			if string(b[k]) != string(a[k]) {
				drifted = append(drifted, k)
			}
		}
	}
	sort.Strings(drifted)
	return drifted
}

func TestListBillableItems_SeededRows(t *testing.T) {
	svc, _ := setup(t)
	items, err := svc.ListBillableItems()
	if err != nil {
		t.Fatalf("ListBillableItems: %v", err)
	}
	// PR 1 seeded ~15 items; assert the well-known ones are present.
	keys := make(map[string]BillableItem, len(items))
	for _, it := range items {
		keys[it.Key] = it
	}
	for _, want := range []string{
		"max_sensors", "max_assets", "retention_days", "storage_gb",
		"custom_policies", "ot_active_probing", "support_sla_tier",
	} {
		if _, ok := keys[want]; !ok {
			t.Errorf("expected catalog to include %q", want)
		}
	}
	if ot := keys["ot_active_probing"]; ot.Kind != "boolean" {
		t.Errorf("ot_active_probing kind = %s, want boolean", ot.Kind)
	}
	if ms := keys["max_sensors"]; ms.Category != "capacity" || ms.Kind != "numeric_cap" {
		t.Errorf("max_sensors metadata wrong: %+v", ms)
	}
}

func TestListBillableItems_Ordered(t *testing.T) {
	svc, _ := setup(t)
	items, err := svc.ListBillableItems()
	if err != nil {
		t.Fatalf("ListBillableItems: %v", err)
	}
	last := -1
	for _, it := range items {
		if it.SortOrder < last {
			t.Errorf("sort_order not ascending: %s at %d after %d", it.Key, it.SortOrder, last)
		}
		last = it.SortOrder
	}
}

func TestGetTierEntitlements_SeededTier(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")

	ents, err := svc.GetTierEntitlements(pro)
	if err != nil {
		t.Fatalf("GetTierEntitlements: %v", err)
	}
	// Every seeded tier carries a row for every catalogue item. Asserting
	// against the catalogue rather than a hard-coded count means adding a
	// billable item does not silently break the nightly — the previous
	// hard-coded 16 did exactly that when cmdb_sync and siem_export landed
	//
	items, err := svc.ListBillableItems()
	if err != nil {
		t.Fatalf("ListBillableItems: %v", err)
	}
	if len(ents) != len(items) {
		t.Errorf("pro tier entitlements = %d, want one per catalogue item (%d)", len(ents), len(items))
	}

	byKey := make(map[string]TierEntitlement)
	for _, e := range ents {
		byKey[e.ItemKey] = e
	}
	// Spot-check a numeric_cap and a boolean from the matrix.
	if ms, ok := byKey["max_sensors"]; ok {
		var v struct{ Quantity int }
		_ = json.Unmarshal(ms.IncludedValue, &v)
		if v.Quantity != 25 {
			t.Errorf("pro.max_sensors quantity = %d, want 25", v.Quantity)
		}
	} else {
		t.Error("pro tier missing max_sensors entitlement")
	}
	// ot_active_probing is edition-gated, so the seed's corrective UPDATE
	// forces it false on EVERY tier — a tier must never grant paid capability
	// (seed.sql "Edition-gate correction"; editionByItem in
	// shared/entitlements/editions.go). It arrives as a tenant_entitlements
	// override from the entitlement-token seeder instead. The row must still
	// exist so the tier editor can display it.
	if ot, ok := byKey["ot_active_probing"]; ok {
		var v struct{ Enabled bool }
		_ = json.Unmarshal(ot.IncludedValue, &v)
		if v.Enabled {
			t.Error("pro.ot_active_probing must be false: no tier may grant an edition-gated capability")
		}
	} else {
		t.Error("pro tier missing ot_active_probing entitlement")
	}
}

func TestReplaceTierEntitlements_ReplacesCompletely(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	// Start with a minimal replacement set — only one item. Anything else
	// previously composed for this tier should be deleted.
	inputs := []TierEntitlementInput{
		{
			ItemKey:       "max_sensors",
			IncludedValue: json.RawMessage(`{"quantity": 50}`),
		},
	}
	if err := svc.ReplaceTierEntitlements(pro, inputs); err != nil {
		t.Fatalf("ReplaceTierEntitlements: %v", err)
	}

	got, err := svc.GetTierEntitlements(pro)
	if err != nil {
		t.Fatalf("GetTierEntitlements after replace: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("after replace, entitlement count = %d, want 1", len(got))
	}
	if got[0].ItemKey != "max_sensors" {
		t.Errorf("remaining entitlement = %s, want max_sensors", got[0].ItemKey)
	}
	var v struct{ Quantity int }
	_ = json.Unmarshal(got[0].IncludedValue, &v)
	if v.Quantity != 50 {
		t.Errorf("updated quantity = %d, want 50", v.Quantity)
	}
}

func TestReplaceTierEntitlements_Idempotent(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	inputs := []TierEntitlementInput{
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 25}`)},
		{ItemKey: "ot_active_probing", IncludedValue: json.RawMessage(`{"enabled": true}`)},
	}
	for i := 0; i < 3; i++ {
		if err := svc.ReplaceTierEntitlements(pro, inputs); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	got, err := svc.GetTierEntitlements(pro)
	if err != nil {
		t.Fatalf("GetTierEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("after 3 identical replaces, entitlement count = %d, want 2", len(got))
	}
}

func TestReplaceTierEntitlements_UnknownKeyRejected(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	// Nothing should change here — the restore is the belt to that braces, and
	// keeps the test honest if validation ever moves after the DELETE.
	restoreTierEntitlements(t, db, pro)

	priorCount := func() int {
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM tier_entitlements WHERE tier_id = $1`, pro).Scan(&n)
		return n
	}
	before := priorCount()

	inputs := []TierEntitlementInput{
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 25}`)},
		{ItemKey: "no_such_thing", IncludedValue: json.RawMessage(`{"quantity": 1}`)},
	}
	err := svc.ReplaceTierEntitlements(pro, inputs)
	if err == nil {
		t.Fatal("expected UnknownItemKeyError; got nil")
	}
	var typedErr *UnknownItemKeyError
	if !errors.As(err, &typedErr) {
		t.Errorf("error type = %T, want *UnknownItemKeyError", err)
	}
	if typedErr != nil && typedErr.Key != "no_such_thing" {
		t.Errorf("UnknownItemKeyError.Key = %q, want %q", typedErr.Key, "no_such_thing")
	}

	// Validation runs BEFORE the DELETE, so nothing should have changed.
	after := priorCount()
	if after != before {
		t.Errorf("validation failure should leave row count unchanged; before=%d after=%d", before, after)
	}
}

func TestReplaceTierEntitlements_OverageFieldsPersist(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	cents := 25
	size := 1
	inputs := []TierEntitlementInput{
		{
			ItemKey:           "storage_gb",
			IncludedValue:     json.RawMessage(`{"quantity": 250}`),
			OveragePriceCents: &cents,
			OverageUnitSize:   &size,
		},
	}
	if err := svc.ReplaceTierEntitlements(pro, inputs); err != nil {
		t.Fatalf("ReplaceTierEntitlements: %v", err)
	}
	got, err := svc.GetTierEntitlements(pro)
	if err != nil {
		t.Fatalf("GetTierEntitlements: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("entitlement count = %d, want 1", len(got))
	}
	if got[0].OveragePriceCents == nil || *got[0].OveragePriceCents != 25 {
		t.Errorf("OveragePriceCents = %v, want 25", got[0].OveragePriceCents)
	}
	if got[0].OverageUnitSize == nil || *got[0].OverageUnitSize != 1 {
		t.Errorf("OverageUnitSize = %v, want 1", got[0].OverageUnitSize)
	}
}

func TestReplaceTierEntitlements_EmptyClearsAll(t *testing.T) {
	svc, db := setup(t)
	free := tierID(t, db, "free")
	restoreTierEntitlements(t, db, free)

	if err := svc.ReplaceTierEntitlements(free, nil); err != nil {
		t.Fatalf("ReplaceTierEntitlements(nil): %v", err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM tier_entitlements WHERE tier_id = $1`, free).Scan(&n)
	if n != 0 {
		t.Errorf("empty replace should clear all rows; got %d", n)
	}
}

// ---------------------------------------------------------------------------
// Catalog CRUD tests
// ---------------------------------------------------------------------------

func TestCreateBillableItem_HappyPath(t *testing.T) {
	svc, db := setup(t)
	// Remove the created row so re-runs against a persistent database (local
	// iteration) don't fail with "key already exists".
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM billable_items WHERE key = 'test_capability_x'`)
	})

	in := BillableItemInput{
		Key:                    "test_capability_x",
		DisplayName:            "Test Capability X",
		Description:            "Created by test",
		Category:               "capability",
		Kind:                   "boolean",
		DefaultValue:           json.RawMessage(`{"enabled": false}`),
		IsAddonEligible:        true,
		DefaultAddonPriceCents: ptrInt(2900),
		IsActive:               true,
		SortOrder:              999,
	}
	got, err := svc.CreateBillableItem(in)
	if err != nil {
		t.Fatalf("CreateBillableItem: %v", err)
	}
	if got.Key != in.Key {
		t.Errorf("Key = %s, want %s", got.Key, in.Key)
	}
	if got.Kind != in.Kind {
		t.Errorf("Kind = %s, want %s", got.Kind, in.Kind)
	}
	if got.DefaultAddonPriceCents == nil || *got.DefaultAddonPriceCents != 2900 {
		t.Errorf("DefaultAddonPriceCents = %v, want 2900", got.DefaultAddonPriceCents)
	}
}

func TestCreateBillableItem_DuplicateKeyRejected(t *testing.T) {
	svc, _ := setup(t)
	// max_sensors is seeded by PR 1.
	_, err := svc.CreateBillableItem(BillableItemInput{
		Key:          "max_sensors",
		DisplayName:  "duplicate",
		Category:     "capacity",
		Kind:         "numeric_cap",
		DefaultValue: json.RawMessage(`{"quantity": 0}`),
		IsActive:     true,
	})
	if err == nil {
		t.Fatal("expected DuplicateKeyError; got nil")
	}
	var dup *DuplicateKeyError
	if !errors.As(err, &dup) {
		t.Errorf("error type = %T, want *DuplicateKeyError", err)
	}
}

func TestUpdateBillableItem_RewritesNonKeyFields(t *testing.T) {
	svc, db := setup(t)
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM billable_items WHERE key = 'max_sensors'`).Scan(&id); err != nil {
		t.Fatalf("lookup id: %v", err)
	}
	// max_sensors is the catalogue entry a tier-less tenant's sensor cap falls
	// back to. Leaving it rewritten breaks other services' suites — see the
	// restore-helper block above.
	restoreBillableItem(t, db, id)

	in := BillableItemInput{
		Key:             "ignored_on_update",
		DisplayName:     "Sensors (renamed)",
		Description:     "updated description",
		Category:        "capacity",
		Kind:            "numeric_cap",
		Unit:            ptrStr("widgets"),
		DefaultValue:    json.RawMessage(`{"quantity": 42}`),
		IsAddonEligible: false,
		IsActive:        true,
		SortOrder:       99,
	}
	got, err := svc.UpdateBillableItem(id, in)
	if err != nil {
		t.Fatalf("UpdateBillableItem: %v", err)
	}
	if got.DisplayName != "Sensors (renamed)" {
		t.Errorf("DisplayName not updated: %s", got.DisplayName)
	}
	if got.Key != "max_sensors" {
		t.Errorf("Key should be immutable; got %s", got.Key)
	}
	if got.SortOrder != 99 {
		t.Errorf("SortOrder = %d, want 99", got.SortOrder)
	}
}

func TestUpdateBillableItem_NotFound(t *testing.T) {
	svc, _ := setup(t)
	_, err := svc.UpdateBillableItem(uuid.New(), BillableItemInput{
		DisplayName: "x", Category: "capacity", Kind: "numeric_cap", IsActive: true,
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows for nonexistent id, got %v", err)
	}
}

func TestDeleteBillableItem_RefusesWhenReferenced(t *testing.T) {
	svc, db := setup(t)
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM billable_items WHERE key = 'max_sensors'`).Scan(&id); err != nil {
		t.Fatalf("lookup id: %v", err)
	}
	// max_sensors is referenced by all 4 seeded tiers.
	err := svc.DeleteBillableItem(id)
	if err == nil {
		t.Fatal("expected ItemInUseError; got nil")
	}
	var inUse *ItemInUseError
	if !errors.As(err, &inUse) {
		t.Errorf("error type = %T, want *ItemInUseError", err)
	}
	if inUse != nil && inUse.TierRefs < 4 {
		t.Errorf("TierRefs = %d, want at least 4 (one per seeded tier)", inUse.TierRefs)
	}
}

func TestDeleteBillableItem_AllowedWhenUnreferenced(t *testing.T) {
	svc, _ := setup(t)
	created, err := svc.CreateBillableItem(BillableItemInput{
		Key:          "test_delete_me",
		DisplayName:  "Will Delete",
		Category:     "capability",
		Kind:         "boolean",
		DefaultValue: json.RawMessage(`{"enabled": false}`),
		IsActive:     true,
	})
	if err != nil {
		t.Fatalf("seed item: %v", err)
	}
	if err := svc.DeleteBillableItem(created.ID); err != nil {
		t.Errorf("DeleteBillableItem on unreferenced row: %v", err)
	}
	if _, err := svc.GetBillableItem(created.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("post-delete GetBillableItem should be ErrNoRows; got %v", err)
	}
}

func TestDeleteBillableItem_NotFound(t *testing.T) {
	svc, _ := setup(t)
	err := svc.DeleteBillableItem(uuid.New())
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func ptrInt(i int) *int       { return &i }
func ptrStr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// Tenant entitlements tests
// ---------------------------------------------------------------------------

func mkTenant(t *testing.T, db *sql.DB, tier string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "ten-" + id.String()[:8]
	_, err := db.Exec(`
		INSERT INTO tenants (id, name, slug, subscription_tier_id, created_at, updated_at)
		VALUES ($1, $2, $3, (SELECT id FROM subscription_tiers WHERE name=$4), NOW(), NOW())
	`, id, slug, slug, tier)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return id
}

func TestCreateTenantEntitlement_HappyPath(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")

	in := TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
		Reason:        ptrStr("sales addon"),
	}
	got, err := svc.CreateTenantEntitlement(tenant, nil, in)
	if err != nil {
		t.Fatalf("CreateTenantEntitlement: %v", err)
	}
	if got.ItemKey != "ot_active_probing" {
		t.Errorf("ItemKey = %s", got.ItemKey)
	}
}

func TestCreateTenantEntitlement_UnknownItem(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")

	_, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey:       "no_such_thing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
	})
	if err == nil {
		t.Fatal("want UnknownItemKeyError; got nil")
	}
	var unknown *UnknownItemKeyError
	if !errors.As(err, &unknown) {
		t.Errorf("error type = %T, want *UnknownItemKeyError", err)
	}
}

func TestCreateTenantEntitlement_ExpiresBeforeEffectiveRejected(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")

	_, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
		EffectiveFrom: "2026-06-01T00:00:00Z",
		ExpiresAt:     "2026-05-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected validation error for expires_at <= effective_from")
	}
}

func TestListTenantEntitlements_ReturnsCreatedRows(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")

	for _, key := range []string{"ot_active_probing", "sso_saml"} {
		_, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
			ItemKey:       key,
			OverrideValue: json.RawMessage(`{"enabled": true}`),
		})
		if err != nil {
			t.Fatalf("create %s: %v", key, err)
		}
	}
	got, err := svc.ListTenantEntitlements(tenant)
	if err != nil {
		t.Fatalf("ListTenantEntitlements: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d rows, want 2", len(got))
	}
}

func TestUpdateTenantEntitlement_RewritesFields(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	updated, err := svc.UpdateTenantEntitlement(tenant, created.ID, TenantEntitlementInput{
		OverrideValue: json.RawMessage(`{"enabled": false}`),
		Reason:        ptrStr("downgrade"),
	})
	if err != nil {
		t.Fatalf("UpdateTenantEntitlement: %v", err)
	}
	if updated.Reason == nil || *updated.Reason != "downgrade" {
		t.Errorf("Reason = %v", updated.Reason)
	}
}

func TestDeleteTenantEntitlement_RemovesRow(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := svc.DeleteTenantEntitlement(tenant, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.GetTenantEntitlement(created.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("after delete, expected ErrNoRows; got %v", err)
	}
}

func TestDeleteTenantEntitlement_NotFound(t *testing.T) {
	svc, db := setup(t)
	wrongTenant := mkTenant(t, db, "starter")
	if err := svc.DeleteTenantEntitlement(wrongTenant, uuid.New()); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected ErrNoRows; got %v", err)
	}
}

func TestUpdateTenantEntitlement_WrongTenantNotFound(t *testing.T) {
	svc, db := setup(t)
	tenantA := mkTenant(t, db, "starter")
	tenantB := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenantA, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err = svc.UpdateTenantEntitlement(tenantB, created.ID, TenantEntitlementInput{
		OverrideValue: json.RawMessage(`{"enabled": false}`),
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Update wrong tenant want ErrNoRows; got %v", err)
	}
}

func TestDeleteTenantEntitlement_WrongTenantNotFound(t *testing.T) {
	svc, db := setup(t)
	tenantA := mkTenant(t, db, "starter")
	tenantB := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenantA, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := svc.DeleteTenantEntitlement(tenantB, created.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Delete wrong tenant want ErrNoRows; got %v", err)
	}

	if _, err := svc.GetTenantEntitlement(created.ID); err != nil {
		t.Fatalf("override should still exist: %v", err)
	}
}

func TestUpdateTenantEntitlement_ChangesEffectiveFrom(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
		EffectiveFrom: "2027-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	updated, err := svc.UpdateTenantEntitlement(tenant, created.ID, TenantEntitlementInput{
		OverrideValue: json.RawMessage(`{"enabled": true}`),
		EffectiveFrom: "2028-02-02T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("UpdateTenantEntitlement: %v", err)
	}
	if updated.EffectiveFrom != "2028-02-02T00:00:00Z" {
		t.Errorf("EffectiveFrom = %q, want 2028-02-02T00:00:00Z", updated.EffectiveFrom)
	}
}

func TestUpdateTenantEntitlement_OmitsEffectiveFromKeepsStored(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
		EffectiveFrom: "2029-07-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	updated, err := svc.UpdateTenantEntitlement(tenant, created.ID, TenantEntitlementInput{
		OverrideValue: json.RawMessage(`{"enabled": false}`),
	})
	if err != nil {
		t.Fatalf("UpdateTenantEntitlement: %v", err)
	}
	want := created.EffectiveFrom
	if updated.EffectiveFrom != want {
		t.Errorf("EffectiveFrom got %q, want %q unchanged", updated.EffectiveFrom, want)
	}
}

func TestUpdateTenantEntitlement_ExpiresBeforeEffectiveRejected(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey:       "ot_active_probing",
		OverrideValue: json.RawMessage(`{"enabled": true}`),
		EffectiveFrom: "2027-06-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err = svc.UpdateTenantEntitlement(tenant, created.ID, TenantEntitlementInput{
		OverrideValue: json.RawMessage(`{"enabled": true}`),
		ExpiresAt:     "2027-05-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected expires_at validation error")
	}
}
