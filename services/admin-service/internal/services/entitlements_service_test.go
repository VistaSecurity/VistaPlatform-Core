package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
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
// restores it when the test ends, and removes the subscription_tier_history
// rows the test's composition writes added. Whole-matrix rather than per-row
// so a test may add, change and remove rows freely.
func restoreTierEntitlements(t *testing.T, db *sql.DB, tier uuid.UUID) {
	t.Helper()
	before := snapshotRow(t, db,
		`SELECT coalesce(jsonb_agg(to_jsonb(te)), '[]'::jsonb) FROM tier_entitlements te WHERE tier_id = $1`, tier)
	historyBefore := snapshotRow(t, db,
		`SELECT coalesce(jsonb_agg(id), '[]'::jsonb) FROM subscription_tier_history WHERE tier_id = $1`, tier)
	t.Cleanup(func() {
		if _, err := db.Exec(`
			DELETE FROM subscription_tier_history
			WHERE tier_id = $1
			  AND NOT (to_jsonb(id) <@ $2::jsonb)`, tier, historyBefore); err != nil {
			t.Errorf("restore subscription_tier_history for %s: %v", tier, err)
		}
	})

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
	// ot_active_probing is edition-gated, and every seeded tier ships every
	// gated capability disabled (scripts/generate-edition-matrix.mjs fails on a
	// seeded grant). Whether a tenant actually gets it is the licence's call
	// (shared/entitlements/license.go): Enterprise grants it to everyone, MSP
	// lets the MSP's own plans grant it. The row must still exist so the tier
	// editor can display it.
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

// compose applies a multi-item write the way the admin UI does: read the
// composition's version, then send it with the change.
func compose(t *testing.T, svc *EntitlementsService, tier uuid.UUID, set []TierEntitlementInput, remove ...string) (*CompositionWriteResult, error) {
	t.Helper()
	cur, err := svc.GetTierComposition(tier)
	if err != nil {
		t.Fatalf("GetTierComposition: %v", err)
	}
	return svc.UpdateTierComposition(tier, CompositionUpdate{Set: set, Remove: remove, Version: cur.Version}, uuid.Nil)
}

func countTierRows(t *testing.T, db *sql.DB, tier uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tier_entitlements WHERE tier_id = $1`, tier).Scan(&n); err != nil {
		t.Fatalf("count tier_entitlements: %v", err)
	}
	return n
}

// The RC-11 regression: a write that names ONE item must leave every other
// row alone. The old ReplaceTierEntitlements deleted everything it was not
// sent, so a client with an empty cache erased the tier.
func TestUpdateTierComposition_OmissionNeverDeletes(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)
	before := countTierRows(t, db, pro)
	if before < 2 {
		t.Fatalf("seeded pro tier has %d rows; the test needs several", before)
	}

	res, err := compose(t, svc, pro, []TierEntitlementInput{
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 50}`)},
	})
	if err != nil {
		t.Fatalf("UpdateTierComposition: %v", err)
	}
	if after := countTierRows(t, db, pro); after != before {
		t.Errorf("a one-item write changed the row count: %d before, %d after", before, after)
	}
	if len(res.Changes) != 1 || res.Changes[0].ItemKey != "max_sensors" {
		t.Errorf("changes = %+v, want exactly max_sensors", res.Changes)
	}
	for _, e := range res.Composition.Entitlements {
		if e.ItemKey == "max_sensors" && string(e.IncludedValue) != `{"quantity": 50}` {
			t.Errorf("max_sensors = %s, want {\"quantity\": 50}", e.IncludedValue)
		}
	}

	// The single-cell path has the same property.
	if _, err := svc.UpsertTierEntitlement(pro, TierEntitlementInput{
		ItemKey: "max_assets", IncludedValue: json.RawMessage(`{"quantity": 7}`),
	}, uuid.Nil); err != nil {
		t.Fatalf("UpsertTierEntitlement: %v", err)
	}
	if after := countTierRows(t, db, pro); after != before {
		t.Errorf("a single-cell write changed the row count: %d before, %d after", before, after)
	}
}

// An identical write changes nothing — no history row, no audit diff — and
// leaves the version where it was.
func TestUpdateTierComposition_IdenticalWriteIsNoOp(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	inputs := []TierEntitlementInput{
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 25}`)},
		{ItemKey: "ot_active_probing", IncludedValue: json.RawMessage(`{"enabled": false}`)},
	}
	if _, err := compose(t, svc, pro, inputs); err != nil {
		t.Fatalf("first write: %v", err)
	}
	v1, _ := svc.GetTierComposition(pro)
	for i := 0; i < 2; i++ {
		res, err := compose(t, svc, pro, inputs)
		if err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
		if len(res.Changes) != 0 {
			t.Errorf("repeat %d reported changes %+v, want none", i, res.Changes)
		}
		if res.Composition.Version != v1.Version {
			t.Errorf("repeat %d moved the version %s → %s", i, v1.Version, res.Composition.Version)
		}
	}
}

func TestUpdateTierComposition_UnknownKeyRejected(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	// Nothing should change here — the restore is the belt to that braces, and
	// keeps the test honest if validation ever moves after a write.
	restoreTierEntitlements(t, db, pro)
	before, _ := svc.GetTierComposition(pro)

	_, err := compose(t, svc, pro, []TierEntitlementInput{
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 99}`)},
		{ItemKey: "no_such_thing", IncludedValue: json.RawMessage(`{"quantity": 1}`)},
	})
	var typedErr *UnknownItemKeyError
	if !errors.As(err, &typedErr) || typedErr.Key != "no_such_thing" {
		t.Fatalf("error = %v, want UnknownItemKeyError{no_such_thing}", err)
	}
	after, _ := svc.GetTierComposition(pro)
	if after.Version != before.Version {
		t.Error("a rejected write changed the composition (max_sensors was written before the bad key was found)")
	}
}

// Overage fields round-trip, and a later write that omits them keeps them —
// the old replace nulled them on every save that did not repeat them.
func TestUpdateTierComposition_OverageFieldsPersist(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	cents, size := 25, 1
	if _, err := compose(t, svc, pro, []TierEntitlementInput{{
		ItemKey: "storage_gb", IncludedValue: json.RawMessage(`{"quantity": 250}`),
		OveragePriceCents: &cents, OverageUnitSize: &size,
	}}); err != nil {
		t.Fatalf("write with overage: %v", err)
	}
	if _, err := svc.UpsertTierEntitlement(pro, TierEntitlementInput{
		ItemKey: "storage_gb", IncludedValue: json.RawMessage(`{"quantity": 300}`),
	}, uuid.Nil); err != nil {
		t.Fatalf("write without overage: %v", err)
	}
	got, err := svc.GetTierEntitlements(pro)
	if err != nil {
		t.Fatalf("GetTierEntitlements: %v", err)
	}
	for _, e := range got {
		if e.ItemKey != "storage_gb" {
			continue
		}
		if string(e.IncludedValue) != `{"quantity": 300}` {
			t.Errorf("storage_gb = %s, want quantity 300", e.IncludedValue)
		}
		if e.OveragePriceCents == nil || *e.OveragePriceCents != 25 {
			t.Errorf("OveragePriceCents = %v, want 25 (kept)", e.OveragePriceCents)
		}
		if e.OverageUnitSize == nil || *e.OverageUnitSize != 1 {
			t.Errorf("OverageUnitSize = %v, want 1 (kept)", e.OverageUnitSize)
		}
		return
	}
	t.Fatal("storage_gb row missing")
}

// Only `remove` deletes, and only the keys it names.
func TestUpdateTierComposition_RemoveDeletesOnlyListed(t *testing.T) {
	svc, db := setup(t)
	free := tierID(t, db, "free")
	restoreTierEntitlements(t, db, free)
	before := countTierRows(t, db, free)

	res, err := compose(t, svc, free, nil, "max_sensors")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if after := countTierRows(t, db, free); after != before-1 {
		t.Errorf("removing one key: %d rows before, %d after, want %d", before, after, before-1)
	}
	if len(res.Changes) != 1 || res.Changes[0].After != nil || res.Changes[0].Before == nil {
		t.Errorf("remove change = %+v, want one before-only change", res.Changes)
	}
	// Removing it again is a no-op, not an error.
	if res, err := compose(t, svc, free, nil, "max_sensors"); err != nil || len(res.Changes) != 0 {
		t.Errorf("second remove: err %v, changes %+v; want a no-op", err, res)
	}
}

// Optimistic concurrency: a write computed from a composition that has since
// changed is refused, and the refusal writes nothing.
func TestUpdateTierComposition_StaleVersionRefused(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	read, _ := svc.GetTierComposition(pro)
	// Someone else edits a cell after we read.
	if _, err := svc.UpsertTierEntitlement(pro, TierEntitlementInput{
		ItemKey: "max_users", IncludedValue: json.RawMessage(`{"quantity": 3}`),
	}, uuid.Nil); err != nil {
		t.Fatalf("concurrent upsert: %v", err)
	}
	now, _ := svc.GetTierComposition(pro)

	_, err := svc.UpdateTierComposition(pro, CompositionUpdate{
		Set:     []TierEntitlementInput{{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 1}`)}},
		Version: read.Version,
	}, uuid.Nil)
	var stale *StaleCompositionError
	if !errors.As(err, &stale) {
		t.Fatalf("error = %v, want *StaleCompositionError", err)
	}
	if stale.Current != now.Version {
		t.Errorf("StaleCompositionError.Current = %s, want %s", stale.Current, now.Version)
	}
	if after, _ := svc.GetTierComposition(pro); after.Version != now.Version {
		t.Error("the refused write changed the composition")
	}

	if _, err := svc.UpdateTierComposition(pro, CompositionUpdate{
		Set: []TierEntitlementInput{{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 1}`)}},
	}, uuid.Nil); !errors.Is(err, ErrCompositionVersionRequired) {
		t.Errorf("no version: error = %v, want ErrCompositionVersionRequired", err)
	}
}

// An inactive item cannot be set (the catalogue hides it from the composer),
// but a row a tier still holds for one can be removed.
func TestUpdateTierComposition_InactiveItems(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	key := "p7_inactive_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	item, err := svc.CreateBillableItem(BillableItemInput{
		Key: key, DisplayName: "Retired lever", Category: "capability", Kind: "boolean",
		DefaultValue: json.RawMessage(`{"enabled": false}`), IsActive: true,
	})
	if err != nil {
		t.Fatalf("CreateBillableItem: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tier_entitlements WHERE item_id = $1`, item.ID)
		_, _ = db.Exec(`DELETE FROM billable_items WHERE id = $1`, item.ID)
	})
	if _, err := svc.UpsertTierEntitlement(pro, TierEntitlementInput{ItemKey: key, IncludedValue: json.RawMessage(`{"enabled": true}`)}, uuid.Nil); err != nil {
		t.Fatalf("set while active: %v", err)
	}
	if _, err := db.Exec(`UPDATE billable_items SET is_active = false WHERE id = $1`, item.ID); err != nil {
		t.Fatal(err)
	}

	_, err = svc.UpsertTierEntitlement(pro, TierEntitlementInput{ItemKey: key, IncludedValue: json.RawMessage(`{"enabled": false}`)}, uuid.Nil)
	var unknown *UnknownItemKeyError
	if !errors.As(err, &unknown) {
		t.Fatalf("setting an inactive item: error = %v, want *UnknownItemKeyError", err)
	}
	if res, err := compose(t, svc, pro, nil, key); err != nil || len(res.Changes) != 1 {
		t.Fatalf("removing an inactive item's row: err %v, result %+v", err, res)
	}
}

// Every change is recorded in subscription_tier_history, in the same
// transaction, with the before/after of each changed item.
func TestUpdateTierComposition_WritesHistory(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	var before int
	_ = db.QueryRow(`SELECT COUNT(*) FROM subscription_tier_history WHERE tier_id = $1`, pro).Scan(&before)
	if _, err := svc.UpsertTierEntitlement(pro, TierEntitlementInput{
		ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 31}`),
	}, uuid.Nil); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var (
		n       int
		changes []byte
	)
	if err := db.QueryRow(`
		SELECT COUNT(*) OVER (), changes_json
		FROM subscription_tier_history WHERE tier_id = $1
		ORDER BY changed_at DESC LIMIT 1`, pro).Scan(&n, &changes); err != nil {
		t.Fatalf("read history: %v", err)
	}
	if n != before+1 {
		t.Fatalf("history rows %d → %d, want one more", before, n)
	}
	var body struct {
		Entitlements []EntitlementChange `json:"entitlements"`
	}
	if err := json.Unmarshal(changes, &body); err != nil {
		t.Fatalf("decode changes_json %s: %v", changes, err)
	}
	if len(body.Entitlements) != 1 || body.Entitlements[0].ItemKey != "max_sensors" ||
		body.Entitlements[0].After == nil || string(body.Entitlements[0].After.IncludedValue) != `{"quantity": 31}` {
		t.Errorf("history changes_json = %s, want the max_sensors diff", changes)
	}
}

func TestUpsertTierEntitlement_UnknownTier(t *testing.T) {
	svc, _ := setup(t)
	_, err := svc.UpsertTierEntitlement(uuid.New(), TierEntitlementInput{
		ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 1}`),
	}, uuid.Nil)
	if !errors.Is(err, ErrTierNotFound) {
		t.Errorf("error = %v, want ErrTierNotFound", err)
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
	// A well-formed default: value validation runs before the row lookup, so
	// a malformed one would surface as InvalidValueError, not ErrNoRows.
	_, err := svc.UpdateBillableItem(uuid.New(), BillableItemInput{
		DisplayName: "x", Category: "capacity", Kind: "numeric_cap", IsActive: true,
		DefaultValue: json.RawMessage(`{"quantity": 1}`),
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

// ---------------------------------------------------------------------------
// Value-shape validation (entitlements.ValidateValue at every write path)
//
// These pin the ED-06 acceptance list: an omitted value, an empty object, a
// wrong-kind value, a negative quantity and a duplicated key each fail with a
// typed error and NO partial write. Explicit zero and explicit null remain
// distinct, valid values.
// ---------------------------------------------------------------------------

func TestUpdateTierComposition_RejectsMalformedValues(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	before, err := svc.GetTierEntitlements(pro)
	if err != nil {
		t.Fatalf("GetTierEntitlements: %v", err)
	}

	cases := []struct {
		name   string
		inputs []TierEntitlementInput
		want   string // substring of the error
	}{
		{"omitted value", []TierEntitlementInput{{ItemKey: "max_sensors"}}, "value is required"},
		{"empty object", []TierEntitlementInput{{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{}`)}}, `missing "quantity"`},
		{"boolean on a cap", []TierEntitlementInput{{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"enabled": true}`)}}, `missing "quantity"`},
		{"quantity on a gate", []TierEntitlementInput{{ItemKey: "custom_policies", IncludedValue: json.RawMessage(`{"quantity": 1}`)}}, `missing "enabled"`},
		{"negative quantity", []TierEntitlementInput{{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": -1}`)}}, "must not be negative"},
		{"string quantity", []TierEntitlementInput{{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": "10"}`)}}, "must be an integer or null"},
		{"empty enum", []TierEntitlementInput{{ItemKey: "support_sla_tier", IncludedValue: json.RawMessage(`{"value": ""}`)}}, "non-empty string"},
		{"malformed after a valid row", []TierEntitlementInput{
			{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 5}`)},
			{ItemKey: "max_assets", IncludedValue: json.RawMessage(`{}`)},
		}, `item max_assets`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compose(t, svc, pro, tc.inputs)
			if err == nil {
				t.Fatalf("UpdateTierComposition accepted %s", tc.name)
			}
			var ive *entitlements.InvalidValueError
			if !errors.As(err, &ive) {
				t.Fatalf("error type = %T (%v), want *entitlements.InvalidValueError", err, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
			after, gerr := svc.GetTierEntitlements(pro)
			if gerr != nil {
				t.Fatalf("GetTierEntitlements after rejected write: %v", gerr)
			}
			if len(after) != len(before) {
				t.Errorf("rejected write changed the composition: %d rows before, %d after", len(before), len(after))
			}
		})
	}
}

func TestUpdateTierComposition_DuplicateKeyRejected(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	// A key both set and removed is as ambiguous as one set twice.
	if _, err := compose(t, svc, pro, []TierEntitlementInput{
		{ItemKey: "max_assets", IncludedValue: json.RawMessage(`{"quantity": 5}`)},
	}, "max_assets"); err == nil {
		t.Error("a request that both sets and removes max_assets was accepted")
	}

	_, err := compose(t, svc, pro, []TierEntitlementInput{
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 5}`)},
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 50}`)},
	})
	if err == nil {
		t.Fatal("a composition naming max_sensors twice was accepted")
	}
	var dup *DuplicateItemKeyError
	if !errors.As(err, &dup) {
		t.Fatalf("error type = %T (%v), want *DuplicateItemKeyError", err, err)
	}
	if dup.Key != "max_sensors" {
		t.Errorf("DuplicateItemKeyError.Key = %q, want max_sensors", dup.Key)
	}
}

func TestUpdateTierComposition_ZeroAndUnlimitedStayDistinct(t *testing.T) {
	svc, db := setup(t)
	pro := tierID(t, db, "pro")
	restoreTierEntitlements(t, db, pro)

	if _, err := compose(t, svc, pro, []TierEntitlementInput{
		{ItemKey: "max_sensors", IncludedValue: json.RawMessage(`{"quantity": 0}`)},
		{ItemKey: "max_assets", IncludedValue: json.RawMessage(`{"quantity": null}`)},
	}); err != nil {
		t.Fatalf("UpdateTierComposition: %v", err)
	}
	got, err := svc.GetTierEntitlements(pro)
	if err != nil {
		t.Fatalf("GetTierEntitlements: %v", err)
	}
	byKey := map[string]string{}
	for _, e := range got {
		byKey[e.ItemKey] = string(e.IncludedValue)
	}
	if byKey["max_sensors"] != `{"quantity": 0}` {
		t.Errorf("max_sensors stored as %s, want {\"quantity\": 0}", byKey["max_sensors"])
	}
	if byKey["max_assets"] != `{"quantity": null}` {
		t.Errorf("max_assets stored as %s, want {\"quantity\": null}", byKey["max_assets"])
	}
}

func TestCreateBillableItem_RejectsMalformedDefault(t *testing.T) {
	svc, db := setup(t)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM billable_items WHERE key LIKE 'test_malformed_%'`)
	})

	cases := []struct {
		name string
		in   BillableItemInput
		want string
	}{
		{"omitted default", BillableItemInput{Key: "test_malformed_a", DisplayName: "A", Category: "capability", Kind: "boolean"}, "value is required"},
		{"empty object", BillableItemInput{Key: "test_malformed_b", DisplayName: "B", Category: "capacity", Kind: "numeric_cap", DefaultValue: json.RawMessage(`{}`)}, `missing "quantity"`},
		{"unknown kind", BillableItemInput{Key: "test_malformed_c", DisplayName: "C", Category: "capacity", Kind: "limit", DefaultValue: json.RawMessage(`{"quantity": 1}`)}, "unknown item kind"},
		{"negative default", BillableItemInput{Key: "test_malformed_d", DisplayName: "D", Category: "capacity", Kind: "numeric_cap", DefaultValue: json.RawMessage(`{"quantity": -3}`)}, "must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateBillableItem(tc.in)
			if err == nil {
				t.Fatalf("CreateBillableItem accepted %s", tc.name)
			}
			var ive *entitlements.InvalidValueError
			if !errors.As(err, &ive) {
				t.Fatalf("error type = %T (%v), want *entitlements.InvalidValueError", err, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
			var n int
			_ = db.QueryRow(`SELECT count(*) FROM billable_items WHERE key = $1`, tc.in.Key).Scan(&n)
			if n != 0 {
				t.Errorf("rejected create wrote %d row(s) for %s", n, tc.in.Key)
			}
		})
	}
}

func TestUpdateBillableItem_RejectsMalformedDefault(t *testing.T) {
	svc, db := setup(t)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM billable_items WHERE key = 'test_update_malformed'`)
	})
	created, err := svc.CreateBillableItem(BillableItemInput{
		Key: "test_update_malformed", DisplayName: "U", Category: "capacity", Kind: "numeric_cap",
		DefaultValue: json.RawMessage(`{"quantity": 3}`), IsActive: true,
	})
	if err != nil {
		t.Fatalf("CreateBillableItem: %v", err)
	}
	_, err = svc.UpdateBillableItem(created.ID, BillableItemInput{
		DisplayName: "U", Category: "capacity", Kind: "numeric_cap", DefaultValue: json.RawMessage(`{}`), IsActive: true,
	})
	var ive *entitlements.InvalidValueError
	if !errors.As(err, &ive) {
		t.Fatalf("UpdateBillableItem with {} default: err = %v, want *entitlements.InvalidValueError", err)
	}
	after, err := svc.GetBillableItem(created.ID)
	if err != nil {
		t.Fatalf("GetBillableItem: %v", err)
	}
	if string(after.DefaultValue) != `{"quantity": 3}` {
		t.Errorf("rejected update changed default_value to %s", after.DefaultValue)
	}
}

func TestCreateTenantEntitlement_RejectsMalformedValue(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")

	cases := []struct {
		name string
		key  string
		raw  string
		want string
	}{
		{"omitted", "max_sensors", ``, "value is required"},
		{"empty object on a cap", "max_sensors", `{}`, `missing "quantity"`},
		{"empty object on a gate", "ot_active_probing", `{}`, `missing "enabled"`},
		{"wrong kind", "ot_active_probing", `{"quantity": 5}`, `missing "enabled"`},
		{"negative", "max_sensors", `{"quantity": -1}`, "must not be negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
				ItemKey: tc.key, OverrideValue: json.RawMessage(tc.raw), Reason: ptrStr("test"),
			})
			var ive *entitlements.InvalidValueError
			if !errors.As(err, &ive) {
				t.Fatalf("err = %v, want *entitlements.InvalidValueError", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
	rows, err := svc.ListTenantEntitlements(tenant)
	if err != nil {
		t.Fatalf("ListTenantEntitlements: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rejected creates left %d override row(s)", len(rows))
	}
}

func TestUpdateTenantEntitlement_RejectsMalformedValue(t *testing.T) {
	svc, db := setup(t)
	tenant := mkTenant(t, db, "starter")
	created, err := svc.CreateTenantEntitlement(tenant, nil, TenantEntitlementInput{
		ItemKey: "max_sensors", OverrideValue: json.RawMessage(`{"quantity": 9}`), Reason: ptrStr("test"),
	})
	if err != nil {
		t.Fatalf("CreateTenantEntitlement: %v", err)
	}
	// The stored item is max_sensors (numeric_cap); the update must be
	// checked against THAT kind even though the request omits item_key.
	_, err = svc.UpdateTenantEntitlement(tenant, created.ID, TenantEntitlementInput{
		OverrideValue: json.RawMessage(`{"enabled": true}`), Reason: ptrStr("test"),
	})
	var ive *entitlements.InvalidValueError
	if !errors.As(err, &ive) {
		t.Fatalf("err = %v, want *entitlements.InvalidValueError", err)
	}
	after, err := svc.GetTenantEntitlement(created.ID)
	if err != nil {
		t.Fatalf("GetTenantEntitlement: %v", err)
	}
	if string(after.OverrideValue) != `{"quantity": 9}` {
		t.Errorf("rejected update changed override_value to %s", after.OverrideValue)
	}
}
