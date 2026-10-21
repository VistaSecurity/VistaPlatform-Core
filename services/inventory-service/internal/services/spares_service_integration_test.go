package services

// DB-integration tests for DCIM gap 8: spares, stock and RMA on inventory
// items. Skipped unless TEST_DATABASE_URL is set; run with
// make test-integration-db. The services run on the NON-OWNER app role, so RLS
// is in force as in production.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// spSeedLocation inserts a site and a location in it; returns both ids.
func spSeedLocation(t *testing.T, owner *sql.DB, tenant uuid.UUID, name string) (site, loc uuid.UUID) {
	t.Helper()
	slug := Slugify(name) + "-" + uuid.NewString()[:6]
	if err := owner.QueryRow(`INSERT INTO sites (tenant_id, name, slug) VALUES ($1, $2, $3) RETURNING id`, tenant, name+" "+slug, slug).Scan(&site); err != nil {
		t.Fatalf("seed site: %v", err)
	}
	if err := owner.QueryRow(`INSERT INTO locations (tenant_id, site_id, name, slug) VALUES ($1, $2, $3, $4) RETURNING id`, tenant, site, name, slug).Scan(&loc); err != nil {
		t.Fatalf("seed location: %v", err)
	}
	return site, loc
}

func spItem(t *testing.T, hw *HardwareService, ctx context.Context, tenant uuid.UUID, body map[string]any) map[string]any {
	t.Helper()
	raw, err := hw.Create(ctx, tenant, HardwareInventoryItem, compBody(t, body))
	if err != nil {
		t.Fatalf("create item %v: %v", body, err)
	}
	return compDecode(t, raw)
}

func spGet(t *testing.T, owner *sql.DB, id any) map[string]any {
	t.Helper()
	var raw []byte
	if err := owner.QueryRow(`SELECT to_jsonb(i) FROM inventory_items i WHERE id = $1`, fmt.Sprint(id)).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		t.Fatalf("read item %v: %v", id, err)
	}
	return compDecode(t, raw)
}

func spChanges(t *testing.T, owner *sql.DB, tenant uuid.UUID, kind string, id any) int {
	t.Helper()
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = $2 AND object_id = $3`,
		tenant, kind, fmt.Sprint(id)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func spID(t *testing.T, m map[string]any) uuid.UUID {
	t.Helper()
	return uuid.MustParse(fmt.Sprint(m["id"]))
}

// A spare is an item at a stock location with a quantity; a plain write keeps
// placement and state consistent and never crosses between the shelf and an
// asset; install splits a stock row and remove merges back into one; every
// transition is in the change log; the stock filters find what they name.
//
// Mutation: drop the `hasAsset && hasLoc` check in prepareStockPlacement → the
// item on both is still refused by inventory_items_placement_check (both
// layers; drop both to see it land); drop the patchStockable rule → the PATCH
// to rma succeeds; make split skip the stock row's decrement → the
// stock quantity stays 5; drop mergeIntoStock from Remove → the removed optic
// becomes a second stock row (stock identity conflict → 409); drop the
// site_id filter → the site's count is every spare.
func TestIntegration_Spares_StockInstallRemove(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	sp := NewSparesService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	site, shelf := spSeedLocation(t, owner, tenant, "Spares cage")
	_, other := spSeedLocation(t, owner, tenant, "Other room")

	box := spItem(t, hw, ctx, tenant, map[string]any{"location_id": shelf, "name": "SFP-10G-SR", "part_id": "SFP-10G-SR", "quantity": 5})
	if box["stock_state"] != "in_stock" || box["asset_id"] != nil || fmt.Sprint(box["quantity"]) != "5" {
		t.Fatalf("stock row defaults: %v", box)
	}
	onAsset := spItem(t, hw, ctx, tenant, map[string]any{"asset_id": asset, "name": "PSU0"})
	if onAsset["stock_state"] != "installed" || fmt.Sprint(onAsset["quantity"]) != "1" {
		t.Errorf("an item on an asset defaults to installed, quantity 1: %v", onAsset)
	}

	for name, body := range map[string]map[string]any{
		"neither asset nor location": {"name": "x"},
		"both asset and location":    {"name": "x", "asset_id": asset, "location_id": shelf},
		"in stock on an asset":       {"name": "x", "asset_id": asset, "stock_state": "in_stock"},
		"installed at a location":    {"name": "x", "location_id": shelf, "stock_state": "installed"},
		"created out for rma":        {"name": "x", "location_id": shelf, "stock_state": "rma"},
		"retired on an asset":        {"name": "x", "asset_id": asset, "stock_state": "retired"},
		"unknown state":              {"name": "x", "location_id": shelf, "stock_state": "lost"},
		"zero quantity":              {"name": "x", "location_id": shelf, "quantity": 0},
		"no such location":           {"name": "x", "location_id": uuid.New()},
		"a spare with a parent":      {"name": "x", "location_id": shelf, "parent_id": spID(t, onAsset)},
	} {
		if _, err := hw.Create(ctx, tenant, HardwareInventoryItem, compBody(t, body)); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	// The stock identity: the same name at the same shelf in the same state.
	if _, err := hw.Create(ctx, tenant, HardwareInventoryItem, compBody(t, map[string]any{"location_id": shelf, "name": "SFP-10G-SR"})); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("a second SFP-10G-SR row on the shelf: %v, want conflict", err)
	}
	// ... but two serialised spares of one model sit side by side.
	spItem(t, hw, ctx, tenant, map[string]any{"location_id": shelf, "name": "LC-48", "serial": "SN-A"})
	spItem(t, hw, ctx, tenant, map[string]any{"location_id": shelf, "name": "LC-48", "serial": "SN-B"})

	boxID := spID(t, box)
	for name, patch := range map[string]map[string]any{
		"onto an asset by PATCH":    {"asset_id": asset, "location_id": nil, "stock_state": "installed"},
		"to installed by PATCH":     {"stock_state": "installed"},
		"to rma by PATCH":           {"stock_state": "rma"},
		"off the shelf with no new": {"location_id": nil},
	} {
		if _, err := hw.Update(ctx, tenant, HardwareInventoryItem, boxID, compBody(t, patch)); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	if _, err := hw.Update(ctx, tenant, HardwareInventoryItem, spID(t, onAsset), compBody(t, map[string]any{"asset_id": nil, "location_id": shelf, "stock_state": "in_stock"})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("off an asset by PATCH: %v, want invalid", err)
	}
	// A spare may be reserved and moved between shelves by a write.
	if _, err := hw.Update(ctx, tenant, HardwareInventoryItem, boxID, compBody(t, map[string]any{"stock_state": "reserved"})); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := hw.Update(ctx, tenant, HardwareInventoryItem, boxID, compBody(t, map[string]any{"stock_state": "in_stock"})); err != nil {
		t.Fatalf("un-reserve: %v", err)
	}

	// Install two of five: the shelf keeps three, the asset gets a row of two.
	two := 2
	res, err := sp.Install(ctx, tenant, boxID, SpareInstallInput{AssetID: asset, Name: "Te1/0/1 optics", Quantity: &two})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Item["asset_id"] != asset.String() || res.Item["location_id"] != nil || res.Item["stock_state"] != "installed" ||
		fmt.Sprint(res.Item["quantity"]) != "2" || res.Item["part_id"] != "SFP-10G-SR" || res.Item["name"] != "Te1/0/1 optics" {
		t.Errorf("installed unit: %v", res.Item)
	}
	if got := spGet(t, owner, boxID); fmt.Sprint(got["quantity"]) != "3" || got["stock_state"] != "in_stock" {
		t.Errorf("stock row after installing two: %v", got)
	}
	for _, q := range []int{0, 4} {
		q := q
		if _, err := sp.Install(ctx, tenant, boxID, SpareInstallInput{AssetID: asset, Quantity: &q}); !errors.Is(err, ErrIPAMInvalid) {
			t.Errorf("install %d of 3: %v, want invalid", q, err)
		}
	}
	if _, err := sp.Install(ctx, tenant, spID(t, onAsset), SpareInstallInput{AssetID: asset}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("installing an installed item: %v, want invalid", err)
	}
	if _, err := sp.Install(ctx, tenant, boxID, SpareInstallInput{AssetID: asset, Name: "PSU0"}); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("installing under a name the asset has: %v, want conflict", err)
	}

	// Remove the installed pair back: an unserialised item of the same name and
	// part joins the stock row.
	res, err = sp.Remove(ctx, tenant, spID(t, res.Item), SpareRemoveInput{LocationID: shelf, Name: "SFP-10G-SR"})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if spID(t, res.Item) != boxID || fmt.Sprint(res.Item["quantity"]) != "5" {
		t.Errorf("removed optics should rejoin the box (5): %v", res.Item)
	}
	// Remove a serialised item: it moves, as itself.
	sup := spItem(t, hw, ctx, tenant, map[string]any{"asset_id": asset, "name": "Sup1", "serial": "SUP-1"})
	child := spItem(t, hw, ctx, tenant, map[string]any{"asset_id": asset, "name": "Sup1 fan", "parent_id": spID(t, sup)})
	if _, err := sp.Remove(ctx, tenant, spID(t, sup), SpareRemoveInput{LocationID: other}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("removing an item with a child: %v, want invalid", err)
	}
	if err := hw.Delete(ctx, tenant, HardwareInventoryItem, spID(t, child)); err != nil {
		t.Fatal(err)
	}
	res, err = sp.Remove(ctx, tenant, spID(t, sup), SpareRemoveInput{LocationID: other, StockState: "reserved"})
	if err != nil {
		t.Fatalf("remove serialised: %v", err)
	}
	if spID(t, res.Item) != spID(t, sup) || res.Item["asset_id"] != nil || res.Item["location_id"] != other.String() || res.Item["stock_state"] != "reserved" {
		t.Errorf("removed supervisor: %v", res.Item)
	}
	if _, err := sp.Remove(ctx, tenant, boxID, SpareRemoveInput{LocationID: other}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("removing a spare that is on no asset: %v, want invalid", err)
	}

	// Into a module bay: an empty bay of the asset gets a module of the module
	// type the spare's part number names, and the item is that module.
	mfr, _ := catSeedPlatformType(t, owner, "Cisco", "C9300 Spares "+uuid.NewString()[:6], 1)
	model := "C9300-NM-SP-" + uuid.NewString()[:6]
	hwSeedModuleType(t, owner, mfr, model, "TenGigabitEthernet1/{module}/1")
	var bay uuid.UUID
	if err := owner.QueryRow(`INSERT INTO module_bays (tenant_id, asset_id, name, position) VALUES ($1, $2, 'Slot 1', '1') RETURNING id`, tenant, asset).Scan(&bay); err != nil {
		t.Fatal(err)
	}
	nm := spItem(t, hw, ctx, tenant, map[string]any{"location_id": shelf, "name": "NM", "part_id": model, "serial": "NM-1"})
	res, err = sp.Install(ctx, tenant, spID(t, nm), SpareInstallInput{AssetID: asset, ModuleBayID: &bay})
	if err != nil {
		t.Fatalf("install into a bay: %v", err)
	}
	var modSerial string
	if err := owner.QueryRow(`SELECT serial FROM modules WHERE id = $1 AND module_bay_id = $2`, fmt.Sprint(res.Item["component_id"]), bay).Scan(&modSerial); err != nil ||
		res.Item["component_kind"] != "module" || modSerial != "NM-1" {
		t.Errorf("the item should be the module installed in the bay with its serial: %v (%q, %v)", res.Item, modSerial, err)
	}
	if n := compCount(t, owner, "interfaces", tenant, asset); n != 1 {
		t.Errorf("installing the module should instantiate its interface: %d interfaces", n)
	}

	// Filters.
	count := func(f map[string]string) int {
		t.Helper()
		_, total, err := hw.List(ctx, tenant, HardwareInventoryItem, IPAMListParams{Limit: 100, Filters: f})
		if err != nil {
			t.Fatalf("list %v: %v", f, err)
		}
		return total
	}
	if n := count(map[string]string{"asset_id": "null"}); n != 4 {
		t.Errorf("asset_id=null: %d, want 4 (the box, two LC-48, Sup1)", n)
	}
	if n := count(map[string]string{"stock_state": "reserved"}); n != 1 {
		t.Errorf("stock_state=reserved: %d, want 1", n)
	}
	if n := count(map[string]string{"location_id": shelf.String()}); n != 3 {
		t.Errorf("location_id=shelf: %d, want 3", n)
	}
	if n := count(map[string]string{"site_id": site.String()}); n != 3 {
		t.Errorf("site_id: %d, want 3 (the other room is another site)", n)
	}

	// Every transition is a recorded change.
	if n := spChanges(t, owner, tenant, "inventory_item", boxID); n != 5 {
		t.Errorf("the box has %d changes; want 5: create, reserve, un-reserve, the split, the merge (refused writes roll back)", n)
	}
	if n := spChanges(t, owner, tenant, "inventory_item", spID(t, sup)); n != 2 {
		t.Errorf("Sup1 has %d changes, want create + remove", n)
	}
}

// RMA: a unit splits off a box; one open case per unit; shipping takes it off
// the shelf; receiving puts a replacement in stock (joining the box); closing
// retires the shipped unit and is final. An advance replacement (the failed
// unit still installed) lands at the asset's location and the unit goes back
// into service when the case closes.
//
// Mutation: drop the `curAsset != str(row["asset_id"])` check in
// prepareStockPlacement → the PSU comes off its asset by PATCH; drop the split in OpenRMA (the `quantityOf > 1` branch) → the
// whole box goes out; drop the rma_cases_open_item_uniq index and the state
// check in OpenRMA → the second case opens; drop the `shipped` branch of
// afterRMACaseWrite → the unit keeps its shelf; drop receiveReplacement → no
// replacement and the box stays at 2; drop the `closed` branch → the unit
// stays rma; drop the closed-is-final rule in prepareRMACase → re-opening
// succeeds; drop the asset-location fallback → the advance replacement is
// refused.
func TestIntegration_Spares_RMA(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	sp := NewSparesService(app)
	_, shelf := spSeedLocation(t, owner, tenant, "Stores")

	box := spItem(t, hw, ctx, tenant, map[string]any{"location_id": shelf, "name": "QSFP-40G", "part_id": "QSFP-40G-SR4", "quantity": 3})
	boxID := spID(t, box)
	res, err := sp.OpenRMA(ctx, tenant, boxID, SpareRMAInput{Vendor: "Acme Networks", CaseNumber: "RMA-1001", Notes: "DOA"})
	if err != nil {
		t.Fatalf("open rma: %v", err)
	}
	unit := spID(t, res.Item)
	if unit == boxID || res.Item["stock_state"] != "rma" || res.Item["location_id"] != shelf.String() || fmt.Sprint(res.Item["quantity"]) != "1" {
		t.Errorf("the RMA unit should be one split off the box, at the shelf: %v", res.Item)
	}
	if fmt.Sprint(res.Stock["quantity"]) != "2" {
		t.Errorf("box after the split: %v", res.Stock)
	}
	if res.RMACase["state"] != "open" || res.RMACase["vendor"] != "Acme Networks" || res.RMACase["opened_at"] == nil ||
		res.RMACase["inventory_item_id"] != unit.String() {
		t.Errorf("case: %v", res.RMACase)
	}
	caseID := spID(t, res.RMACase)
	if _, err := sp.OpenRMA(ctx, tenant, unit, SpareRMAInput{}); !errors.Is(err, ErrIPAMConflict) {
		t.Errorf("a second case for the unit: %v, want conflict", err)
	}
	if _, err := sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"state": "lost"})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("unknown case state: %v, want invalid", err)
	}
	if _, err := sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"shipped_at": "2000-01-01"})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("shipped before opened: %v, want invalid", err)
	}
	if _, err := sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"inventory_item_id": boxID})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("re-pointing the case at another item: %v, want invalid", err)
	}

	raw, err := sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"state": "shipped"}))
	if err != nil {
		t.Fatalf("ship: %v", err)
	}
	if c := compDecode(t, raw); c["shipped_at"] == nil {
		t.Errorf("shipping stamps shipped_at: %v", c)
	}
	if got := spGet(t, owner, unit); got["location_id"] != nil || got["asset_id"] != nil || got["stock_state"] != "rma" {
		t.Errorf("a shipped unit is with the vendor: %v", got)
	}
	raw, err = sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"state": "received"}))
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if c := compDecode(t, raw); c["received_at"] == nil || c["replacement_item_id"] != boxID.String() {
		t.Errorf("receiving names the replacement (the box it joined): %v", c)
	}
	if got := spGet(t, owner, boxID); fmt.Sprint(got["quantity"]) != "3" {
		t.Errorf("box after the replacement arrived: %v, want 3", got)
	}
	if _, err := sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"state": "closed"})); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := spGet(t, owner, unit); got["stock_state"] != "retired" {
		t.Errorf("the shipped unit is retired when the case closes: %v", got)
	}
	if _, err := sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"state": "open"})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("re-opening a closed case: %v, want invalid", err)
	}
	if _, err := sp.UpdateRMACase(ctx, tenant, caseID, compBody(t, map[string]any{"notes": "credited"})); err != nil {
		t.Errorf("a note on a closed case: %v", err)
	}
	if _, err := sp.OpenRMA(ctx, tenant, unit, SpareRMAInput{}); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("a retired unit out for RMA: %v, want invalid", err)
	}

	// Advance replacement: the failed PSU stays installed; the replacement
	// lands at the asset's location; closing puts the PSU back in service (it
	// never shipped — the person swapped it later or the case was withdrawn).
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")
	if _, err := owner.Exec(`UPDATE assets SET location_id = $2 WHERE id = $1`, asset, shelf); err != nil {
		t.Fatal(err)
	}
	psu := spItem(t, hw, ctx, tenant, map[string]any{"asset_id": asset, "name": "PSU1", "part_id": "PWR-C1-715WAC", "serial": "PSU-9"})
	res, err = sp.OpenRMA(ctx, tenant, spID(t, psu), SpareRMAInput{Vendor: "Acme Networks"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Item["asset_id"] != asset.String() || res.Item["stock_state"] != "rma" {
		t.Errorf("the PSU stays on its asset, out for RMA: %v", res.Item)
	}
	// A write cannot take it off the asset (its state stays rma, so only the
	// asset rule stands in the way).
	if _, err := hw.Update(ctx, tenant, HardwareInventoryItem, spID(t, psu), compBody(t, map[string]any{"asset_id": nil, "location_id": shelf})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("off its asset by PATCH while out for RMA: %v, want invalid", err)
	}
	adv := spID(t, res.RMACase)
	raw, err = sp.UpdateRMACase(ctx, tenant, adv, compBody(t, map[string]any{"state": "received"}))
	if err != nil {
		t.Fatalf("advance receive: %v", err)
	}
	rep := compDecode(t, raw)["replacement_item_id"]
	if got := spGet(t, owner, rep); got == nil || got["location_id"] != shelf.String() || got["stock_state"] != "in_stock" ||
		got["part_id"] != "PWR-C1-715WAC" || got["serial"] != nil {
		t.Errorf("the replacement should be a new PSU in stock at the asset's location: %v", got)
	}
	if _, err := sp.UpdateRMACase(ctx, tenant, adv, compBody(t, map[string]any{"state": "closed"})); err != nil {
		t.Fatal(err)
	}
	if got := spGet(t, owner, spID(t, psu)); got["stock_state"] != "installed" || got["asset_id"] != asset.String() {
		t.Errorf("an unshipped unit goes back into service on close: %v", got)
	}

	// Open cases filter.
	_, open, err := sp.ListRMACases(ctx, tenant, IPAMListParams{Limit: 50, Filters: map[string]string{"open": "true"}})
	if err != nil || open != 0 {
		t.Errorf("open cases: %d (%v), want 0", open, err)
	}
	_, all, _ := sp.ListRMACases(ctx, tenant, IPAMListParams{Limit: 50})
	if all != 2 {
		t.Errorf("all cases: %d, want 2", all)
	}
	if n := spChanges(t, owner, tenant, "rma_case", caseID); n < 5 {
		t.Errorf("the case has %d changes; want create, ship, receive (+ replacement), close, note", n)
	}
}

// A tenant sees and acts on only its own spares and cases; another tenant's
// stock location cannot be named; RLS holds rma_cases on the app role.
//
// Mutation: drop rma_cases_tenant_isolation (or its ENABLE ROW LEVEL
// SECURITY) → tenant B lists A's case; drop the visible(locations) check in
// prepareStockPlacement → B's spare is filed at A's location (the plain FK
// sees no tenancy).
func TestIntegration_Spares_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	sp := NewSparesService(app)
	_, shelfA := spSeedLocation(t, owner, tenantA, "A stores")
	_, shelfB := spSeedLocation(t, owner, tenantB, "B stores")
	assetB := ifaceSeedAsset(t, owner, tenantB, "monitoring")

	item := spItem(t, hw, ctx, tenantA, map[string]any{"location_id": shelfA, "name": "Fan tray", "quantity": 2})
	res, err := sp.OpenRMA(ctx, tenantA, spID(t, item), SpareRMAInput{CaseNumber: "A-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, total, err := sp.ListRMACases(ctx, tenantB, IPAMListParams{Limit: 50}); err != nil || total != 0 {
		t.Errorf("tenant B lists %d cases (%v), want 0", total, err)
	}
	if _, err := sp.GetRMACase(ctx, tenantB, spID(t, res.RMACase)); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("tenant B reads A's case: %v, want not found", err)
	}
	if _, err := sp.UpdateRMACase(ctx, tenantB, spID(t, res.RMACase), compBody(t, map[string]any{"state": "shipped"})); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("tenant B ships A's case: %v, want not found", err)
	}
	if _, err := sp.Install(ctx, tenantB, spID(t, item), SpareInstallInput{AssetID: assetB}); !errors.Is(err, ErrIPAMNotFound) {
		t.Errorf("tenant B installs A's spare: %v, want not found", err)
	}
	if _, err := hw.Create(ctx, tenantB, HardwareInventoryItem, compBody(t, map[string]any{"location_id": shelfA, "name": "x"})); !errors.Is(err, ErrIPAMInvalid) {
		t.Errorf("tenant B files a spare at A's location: %v, want invalid", err)
	}
	spItem(t, hw, ctx, tenantB, map[string]any{"location_id": shelfB, "name": "x"})
	// The cross-tenant insert on the app role is refused by WITH CHECK.
	tx, err := app.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.tenant_id', $1, true)`, tenantB.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO rma_cases (tenant_id, inventory_item_id) VALUES ($1, $2)`, tenantA, spID(t, item)); err == nil {
		t.Error("tenant B's session inserted a case for tenant A")
	}
}

// Deleting a location (or its site) that still holds a spare is refused as in
// use — the spares move first — while deleting the tenant, which removes the
// location and its spares in one statement, is not.
//
// Mutation: make the location key ON DELETE SET NULL → the location delete
// fails on the home CHECK instead (a 400, not in use); RESTRICT → the tenant
// delete fails.
func TestIntegration_Spares_LocationDelete(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	site, shelf := spSeedLocation(t, owner, tenant, "Cage 9")
	spItem(t, hw, ctx, tenant, map[string]any{"location_id": shelf, "name": "Optic"})
	for what, q := range map[string]string{"location": `DELETE FROM locations WHERE id = $1`, "site": `DELETE FROM sites WHERE id = $1`} {
		id := shelf
		if what == "site" {
			id = site
		}
		_, err := owner.Exec(q, id)
		if !errors.Is(mapIPAMError(err, true), ErrIPAMInUse) {
			t.Errorf("deleting the %s of a spare: %v, want in use", what, err)
		}
	}
	if _, err := owner.Exec(`DELETE FROM tenants WHERE id = $1`, tenant); err != nil {
		t.Errorf("deleting the tenant with its locations and spares: %v", err)
	}
}

// The query language reaches the stock state (QUERY_LANGUAGE §15.10): the
// assets with a part out for RMA, and its negation, against Postgres.
func TestIntegration_Spares_QueryStockState(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	hw := NewHardwareService(app)
	sp := NewSparesService(app)
	hit := ifaceSeedAsset(t, owner, tenant, "monitoring")
	miss := ifaceSeedAsset(t, owner, tenant, "monitoring")
	psu := spItem(t, hw, ctx, tenant, map[string]any{"asset_id": hit, "name": "PSU1"})
	spItem(t, hw, ctx, tenant, map[string]any{"asset_id": miss, "name": "PSU1"})
	if _, err := sp.OpenRMA(ctx, tenant, spID(t, psu), SpareRMAInput{}); err != nil {
		t.Fatal(err)
	}
	match := func(q string) map[uuid.UUID]bool {
		t.Helper()
		c, err := query.Compile(q, "asset", query.DefaultCatalog(), query.DefaultOptionsFor(query.DefaultCatalog()))
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		out := map[uuid.UUID]bool{}
		testdb.AsTenant(t, owner, tenant, func(tx *sql.Tx) {
			rows, err := tx.Query("SELECT a.id FROM assets a WHERE a.tenant_id = '"+tenant.String()+"' AND "+c.Where, c.Args...)
			if err != nil {
				t.Fatalf("run %q: %v", q, err)
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					t.Fatal(err)
				}
				out[id] = true
			}
		})
		return out
	}
	if got := match(`inventory_item.stock_state = rma`); !got[hit] || len(got) != 1 {
		t.Errorf("a part out for RMA: %v, want only %s", got, hit)
	}
	if got := match(`inventory_item.stock_state != rma`); got[hit] || !got[miss] {
		t.Errorf("no part out for RMA: %v, want %s and not %s", got, miss, hit)
	}
	if got := match(`inventory_item.stock_state = installed`); !got[miss] || got[hit] {
		t.Errorf("an installed item: %v, want %s only", got, miss)
	}
}
