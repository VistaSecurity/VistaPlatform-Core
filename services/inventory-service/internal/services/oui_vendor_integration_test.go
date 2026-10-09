package services

// hw.vendor from the MAC prefix is resolved on the platform, at ingestion, from
// the full IEEE registry (oui_vendor.go), and existing assets are brought up to
// it by the backfill (oui_vendor_backfill.go). These drive the REAL ingest path
// and the real backfill against Postgres: a helper test would stay green with
// the one line that calls the registry deleted.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

const (
	// 00:B4:63 is Ring's in the IEEE registry and was never in the sensor's old
	// curated table, so only the platform-side lookup can name it.
	macRing = "00:b4:63:12:34:56"
	// 00:19:9D is Vizio's: the second vendor for the "two MACs disagree" case.
	macVizio = "00:19:9d:12:34:56"
	// 00:00:0C is Cisco's, in both the old table and the registry.
	macCisco = "00:00:0c:12:34:57"
	// 00:AB:12 is not assigned in the IEEE registry.
	macUnassigned = "00:ab:12:33:44:55"
)

type vendorRow struct{ value, kind, ref string }

// vendorFacts returns every hw.vendor row of the asset holding mac, keyed by
// source_ref.
func vendorFacts(t *testing.T, db *database.DB, tenant uuid.UUID, assetID uuid.UUID) map[string]vendorRow {
	t.Helper()
	rows, err := db.Query(`SELECT value #>> '{}', source_kind, source_ref FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = 'hw.vendor'`, tenant, assetID)
	if err != nil {
		t.Fatalf("read hw.vendor facts: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]vendorRow{}
	for rows.Next() {
		var r vendorRow
		if err := rows.Scan(&r.value, &r.kind, &r.ref); err != nil {
			t.Fatal(err)
		}
		out[r.ref] = r
	}
	return out
}

func assetByMAC(t *testing.T, db *database.DB, tenant uuid.UUID, mac string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT asset_id FROM asset_identifiers
		WHERE tenant_id = $1 AND kind = 'mac_address' AND value = $2`, tenant, mac).Scan(&id); err != nil {
		t.Fatalf("no asset holds mac %s: %v", mac, err)
	}
	return id
}

func ingestObservation(t *testing.T, svc *AssetService, tenant uuid.UUID, ho *hostobs.HostObservation) {
	t.Helper()
	if _, err := svc.IngestFindings(tenant, []IngestFinding{observationFinding(t, ho)}); err != nil {
		t.Fatalf("IngestFindings: %v", err)
	}
}

// The wiring test. A current sensor sends no vendor; the ingest path must
// resolve it from the registry, write it as the enricher's catalogue fact, and
// hand the same answer to the classifier.
//
// Mutation-tested: deleting the resolveHostObservationVendor(ho) call in
// ingestHostObservation turns both halves red — no hw.vendor row, and the
// vendor-scoped model rule below matches and classes the doorbell a printer.
func TestIntegration_HostObservation_VendorResolvedFromRegistryAtIngest(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	if ouiregistry.VendorForMAC(macRing) != "Ring" {
		t.Fatalf("precondition: %s must be Ring's in the registry", macRing)
	}

	// A model rule that only fires when the vendor is unknown or agrees with
	// "Not Ring Inc": with the registry's "Ring" reaching the classifier, it is
	// excluded; with no vendor (the resolution skipped), it matches.
	var ruleID uuid.UUID
	if err := db.QueryRow(`INSERT INTO classification_rules (rule_kind, pattern, class_key, vendor, confidence)
		VALUES ('model', 'OUITEST-DOORBELL', 'printer', 'Not Ring Inc', 0.90) RETURNING id`).Scan(&ruleID); err != nil {
		t.Fatalf("insert test rule: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM classification_rules WHERE id = $1`, ruleID) })

	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source:     hostobs.SourceLLDP,
		MAC:        macRing,
		Model:      "OUITEST-DOORBELL-2",
		Addresses:  addrsFor(t, "192.0.2.77"),
		Hostnames:  []string{"front-door"},
		ObservedAt: time.Now().UTC().Add(-time.Minute),
	})
	assetID := assetByMAC(t, db, tenant, macRing)

	got := vendorFacts(t, db, tenant, assetID)
	want := vendorRow{value: "Ring", kind: "imported", ref: ouiVendorSourceRef}
	if len(got) != 1 || got[ouiVendorSourceRef] != want {
		t.Errorf("hw.vendor rows = %+v; want exactly %+v", got, want)
	}

	var classKey string
	if err := db.QueryRow(`SELECT class_key FROM assets WHERE id = $1`, assetID).Scan(&classKey); err != nil {
		t.Fatal(err)
	}
	if classKey == "printer" {
		t.Error("class_key = printer: the classifier did not see the registry's vendor (a rule scoped to another vendor matched)")
	}
}

// An older sensor binary still sends its own table's answer. Where the
// registry has one, the platform's wins and the sensor's row is not written.
func TestIntegration_HostObservation_RegistryVendorBeatsTheSensorsCarriedVendor(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source:     hostobs.SourceARP,
		MAC:        macCisco,
		Vendor:     "Stale Table Spelling",
		Addresses:  addrsFor(t, "192.0.2.78"),
		ObservedAt: time.Now().UTC().Add(-time.Minute),
	})
	got := vendorFacts(t, db, tenant, assetByMAC(t, db, tenant, macCisco))
	want := vendorRow{value: ouiregistry.VendorForMAC(macCisco), kind: "imported", ref: ouiVendorSourceRef}
	if len(got) != 1 || got[ouiVendorSourceRef] != want {
		t.Errorf("hw.vendor rows = %+v; want only the registry's %+v", got, want)
	}
}

// A prefix the registry does not determine falls back to what the observation
// carried, under the sensor's own producer, as before.
func TestIntegration_HostObservation_UnresolvedPrefixKeepsTheCarriedVendor(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source:     hostobs.SourceARP,
		MAC:        macUnassigned,
		Vendor:     "Legacy Vendor",
		Addresses:  addrsFor(t, "192.0.2.79"),
		ObservedAt: time.Now().UTC().Add(-time.Minute),
	})
	got := vendorFacts(t, db, tenant, assetByMAC(t, db, tenant, macUnassigned))
	if _, ok := got[ouiVendorSourceRef]; ok {
		t.Errorf("an OUI row was written for a prefix the registry does not determine: %+v", got)
	}
	if len(got) != 1 {
		t.Fatalf("hw.vendor rows = %+v; want the carried vendor only", got)
	}
	for ref, r := range got {
		if r.value != "Legacy Vendor" || r.kind != "measured" || ref == ouiVendorSourceRef {
			t.Errorf("hw.vendor = %+v; want the carried Legacy Vendor under the sensor", r)
		}
	}
}

// A vendor the device itself (or a system of record) stated outranks the OUI
// lookup: the next observation does not write the OUI row, and retracts one
// written before the device-identity fact arrived.
func TestIntegration_HostObservation_DeviceIdentityVendorSuppressesTheOUIFact(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	obs := func() *hostobs.HostObservation {
		return &hostobs.HostObservation{
			Source:     hostobs.SourceARP,
			MAC:        macRing,
			Addresses:  addrsFor(t, "192.0.2.80"),
			ObservedAt: time.Now().UTC().Add(-time.Minute),
		}
	}
	ingestObservation(t, svc, tenant, obs())
	assetID := assetByMAC(t, db, tenant, macRing)
	if _, ok := vendorFacts(t, db, tenant, assetID)[ouiVendorSourceRef]; !ok {
		t.Fatal("precondition: the first observation should write the OUI vendor")
	}

	if _, err := db.Exec(`INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		VALUES ($1, $2, 'hw.vendor', '"Ring LLC"', 'measured', 'agent:oui-test', now())`, tenant, assetID); err != nil {
		t.Fatalf("seed the device-agent vendor: %v", err)
	}
	ingestObservation(t, svc, tenant, obs())

	got := vendorFacts(t, db, tenant, assetID)
	if _, ok := got[ouiVendorSourceRef]; ok {
		t.Errorf("the OUI vendor survived a device-agent vendor: %+v", got)
	}
	if got["agent:oui-test"].value != "Ring LLC" {
		t.Errorf("the device-agent vendor was disturbed: %+v", got)
	}
}

// The backfill: an asset ingested before the move (no vendor fact, or the old
// table's answer under `sensor`) gets the registry's; one whose vendor came
// from a device-identity source is left alone; one whose MACs disagree gets
// nothing. Then it records the snapshot and is idempotent.
func TestIntegration_OUIVendorBackfill_ResolvesExistingAssets(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ctx := context.Background()

	ingest := func(mac, addr string) uuid.UUID {
		ingestObservation(t, svc, tenant, &hostobs.HostObservation{
			Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(t, addr),
			ObservedAt: time.Now().UTC().Add(-time.Minute),
		})
		id := assetByMAC(t, db, tenant, mac)
		// Back to the pre-move state: no platform-side vendor at all.
		if _, err := db.Exec(`DELETE FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = 'hw.vendor'`, tenant, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	noVendor := ingest(macRing, "192.0.2.81")
	oldTable := ingest(macCisco, "192.0.2.82")
	if _, err := db.Exec(`INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		VALUES ($1, $2, 'hw.vendor', '"Old Table Answer"', 'measured', 'sensor:11111111-2222-3333-4444-555555555555', now())`, tenant, oldTable); err != nil {
		t.Fatal(err)
	}
	deviceAgent := ingest("00:19:9d:00:00:01", "192.0.2.83")
	if _, err := db.Exec(`INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		VALUES ($1, $2, 'hw.vendor', '"VIZIO, Inc."', 'measured', 'agent:oui-backfill', now())`, tenant, deviceAgent); err != nil {
		t.Fatal(err)
	}
	disagree := ingest(macVizio, "192.0.2.84")
	if _, err := db.Exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value) VALUES ($1, $2, 'mac_address', $3)`,
		tenant, disagree, "00:b4:63:00:00:02"); err != nil {
		t.Fatalf("second MAC: %v", err)
	}

	due, err := OUIVendorBackfillDueTenants(ctx, db.DB.DB)
	if err != nil {
		t.Fatal(err)
	}
	if !containsUUID(due, tenant) {
		t.Fatalf("tenant %s with no recorded backfill is not due: %v", tenant, due)
	}

	n, err := svc.BackfillRegistryVendors(ctx, tenant)
	if err != nil {
		t.Fatalf("BackfillRegistryVendors: %v", err)
	}
	if n != 2 {
		t.Errorf("wrote %d assets, want 2 (the vendor-less one and the old-table one)", n)
	}

	if got := vendorFacts(t, db, tenant, noVendor); len(got) != 1 || got[ouiVendorSourceRef].value != "Ring" {
		t.Errorf("vendor-less asset: %+v; want the registry's Ring", got)
	}
	if got := vendorFacts(t, db, tenant, oldTable); len(got) != 1 || got[ouiVendorSourceRef].value != ouiregistry.VendorForMAC(macCisco) {
		t.Errorf("old-table asset: %+v; want only the registry's answer (the sensor's row superseded)", got)
	}
	if got := vendorFacts(t, db, tenant, deviceAgent); len(got) != 1 || got["agent:oui-backfill"].value != "VIZIO, Inc." {
		t.Errorf("device-agent asset: %+v; want its own vendor untouched and no OUI row", got)
	}
	if got := vendorFacts(t, db, tenant, disagree); len(got) != 0 {
		t.Errorf("asset whose MACs disagree (Vizio and Ring): %+v; ambiguity must write nothing", got)
	}

	var snapshot string
	if err := db.QueryRow(`SELECT snapshot_id FROM oui_vendor_backfill_state WHERE tenant_id = $1`, tenant).Scan(&snapshot); err != nil {
		t.Fatalf("no backfill state recorded: %v", err)
	}
	if snapshot != ouiregistry.SnapshotID() {
		t.Errorf("recorded snapshot %q, want %q", snapshot, ouiregistry.SnapshotID())
	}
	due, err = OUIVendorBackfillDueTenants(ctx, db.DB.DB)
	if err != nil {
		t.Fatal(err)
	}
	if containsUUID(due, tenant) {
		t.Error("tenant is still due after completing under the running snapshot")
	}

	// Idempotent: a second pass rewrites the same answers and adds no rows.
	var before, after int
	countAll := func(dst *int) {
		if err := db.QueryRow(`SELECT count(*) FROM asset_facts WHERE tenant_id = $1 AND key = 'hw.vendor'`, tenant).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	countAll(&before)
	if _, err := svc.BackfillRegistryVendors(ctx, tenant); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	countAll(&after)
	if before != after {
		t.Errorf("hw.vendor rows %d -> %d across a second pass; the backfill is not idempotent", before, after)
	}

	// A new snapshot makes the tenant due again.
	if _, err := db.Exec(`UPDATE oui_vendor_backfill_state SET snapshot_id = 'an-older-snapshot' WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	due, err = OUIVendorBackfillDueTenants(ctx, db.DB.DB)
	if err != nil {
		t.Fatal(err)
	}
	if !containsUUID(due, tenant) {
		t.Error("tenant recorded under another snapshot is not due")
	}
}

func containsUUID(ids []uuid.UUID, id uuid.UUID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
