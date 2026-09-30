package services

// Per-source scan consent (platform ADR-0002 D10) through the REAL automatic
// selection path and the REAL dispatch guard, against Postgres:
//
//   - autoscan.Store.EligibleTargets — what the auto-scan sweep and the
//     first-observation pass pick (jobs/auto_active_scan_job.go);
//   - dispatchguard.AuthorizeAutomaticScan — the re-check every later stage
//     runs (job creation, platform execution, sensor pickup);
//   - dispatchguard.AuthorizeTargets — the EXPLICIT path a person's scan uses,
//     which consent must not touch.
//
// Assets are made the way production makes them: an import through
// SourceImportService.ResolveAssets (imported source), a sensor's through
// AssetService.CreateAssetFromSource (measured source).
//
// Polarity, both ways:
//   - consent off → an imported-only asset is not selected and its address is
//     refused at dispatch; the explicit path still admits it;
//   - consent on and owned (private) → eligible and admitted;
//   - consent on but not owned (public, no segment) → still refused;
//   - a sensor-observed asset, and an imported asset a sensor has since seen,
//     are eligible exactly as before, consent or not;
//   - a scan's own result is not independent evidence;
//   - independent evidence counts whichever table carries it (a measured
//     identifier, fact or endpoint);
//   - consent from ANY source that reported the asset counts (its imported
//     identifiers, facts or endpoints), not only the source that created it;
//   - another connection's consent does not count; consent withdrawn takes
//     effect.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func TestIntegration_ScanConsent_GatesOnlyImportedOnlyAssetsOnTheAutomaticPath(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	conn1 := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}
	conn2 := identity.Source{Kind: identity.SourceImported, Ref: "netbox:" + uuid.NewString()}
	// conn3 created nothing; it reported (identifier / fact / endpoint) on
	// assets conn2 created.
	conn3 := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}

	imported := func(src identity.Source, serial, ip string) uuid.UUID {
		t.Helper()
		res := f.svc.ResolveAssets(ctx, tenant, src, []SourceAssetItem{sourceHost(serial, ip, "host-"+serial)})
		if res[0].Outcome != string(identity.OutcomeCreated) || res[0].AssetID == nil {
			t.Fatalf("import %s: %+v", serial, res[0])
		}
		return *res[0].AssetID
	}
	measured := func(asset uuid.UUID, ref, mac string) {
		t.Helper()
		if _, err := f.db.Exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_kind, source_ref)
			VALUES ($1, $2, 'mac_address', $3, 'measured', $4)`, tenant, asset, mac, ref); err != nil {
			t.Fatal(err)
		}
	}

	fact := func(asset uuid.UUID, kind, ref string) {
		t.Helper()
		if _, err := f.db.Exec(`INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref)
			VALUES ($1, $2, 'os.name', '"linux"', $3, $4)`, tenant, asset, kind, ref); err != nil {
			t.Fatal(err)
		}
	}
	endpoint := func(asset uuid.UUID, ip, kind, ref string) {
		t.Helper()
		if _, err := f.db.Exec(`INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, source_kind, source_ref)
			VALUES ($1, $2, $3::inet, 443, $4, $5)`, tenant, asset, ip, kind, ref); err != nil {
			t.Fatal(err)
		}
	}
	reportedID := func(asset uuid.UUID, ref, serial string) {
		t.Helper()
		if _, err := f.db.Exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, source_kind, source_ref)
			VALUES ($1, $2, 'serial_number', $3, 'imported', $4)`, tenant, asset, serial, ref); err != nil {
			t.Fatal(err)
		}
	}

	imp := imported(conn1, "SC-IMP-1", "10.61.0.11")
	seen := imported(conn1, "SC-SEEN-1", "10.61.0.13")
	measured(seen, "sensor:"+uuid.NewString(), "02:00:00:61:00:13")
	scanned := imported(conn1, "SC-SCAN-1", "10.61.0.14")
	measured(scanned, "scan:"+uuid.NewString(), "02:00:00:61:00:14")
	public := imported(conn1, "SC-PUB-1", "203.0.113.61")
	other := imported(conn2, "SC-OTHER-1", "10.61.0.15")
	seenFact := imported(conn1, "SC-SEENF-1", "10.61.0.16")
	fact(seenFact, "measured", "sensor:"+uuid.NewString())
	seenEndpoint := imported(conn1, "SC-SEENE-1", "10.61.0.17")
	endpoint(seenEndpoint, "10.61.0.17", "measured", "agent:"+uuid.NewString())
	viaID := imported(conn2, "SC-VIAI-1", "10.61.0.18")
	reportedID(viaID, conn3.Ref, "SC-VIAI-3")
	viaFact := imported(conn2, "SC-VIAF-1", "10.61.0.19")
	fact(viaFact, "imported", conn3.Ref)
	viaEndpoint := imported(conn2, "SC-VIAE-1", "10.61.0.20")
	endpoint(viaEndpoint, "10.61.0.20", "imported", conn3.Ref)
	// A scan's own result, in each table, is not independent evidence.
	scannedFact := imported(conn1, "SC-SCANF-1", "10.61.0.21")
	fact(scannedFact, "measured", "scan:"+uuid.NewString())
	scannedEndpoint := imported(conn1, "SC-SCANE-1", "10.61.0.22")
	endpoint(scannedEndpoint, "10.61.0.22", "measured", "scan")
	// Created by conn1 but carrying none of its rows any more (its identifiers
	// were merged or expired away): the creating history entry is the only
	// thing naming the source, and it alone must carry that source's consent.
	historyOnly := imported(conn1, "SC-HIST-1", "10.61.0.23")
	for _, tbl := range []string{"asset_identifiers", "asset_facts", "asset_endpoints"} {
		if _, err := f.db.Exec(`DELETE FROM `+tbl+` WHERE tenant_id = $1 AND asset_id = $2`, tenant, historyOnly); err != nil {
			t.Fatal(err)
		}
	}
	vias := map[string]uuid.UUID{"identifier": viaID, "fact": viaFact, "endpoint": viaEndpoint}

	sensorIP, sensorHost := "10.61.0.12", "sensor-seen-12"
	sensorAsset, _, err := NewAssetService(f.db).CreateAssetFromSource(tenant, models.AssetInput{
		ClassKey: "server", IPAddress: &sensorIP, Hostname: &sensorHost, DisplayName: &sensorHost,
		Identifiers: []models.AssetIdentifierInput{{Kind: string(identity.KindSerialNumber), Value: "SC-SENSOR-1"}},
	}, identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + uuid.NewString()})
	if err != nil || sensorAsset == nil {
		t.Fatalf("sensor asset: %v", err)
	}

	store := autoscan.NewStore(f.db)
	selected := func() (map[uuid.UUID]bool, map[sharedautoscan.Reason]int) {
		t.Helper()
		got, refusals, err := store.EligibleTargets(ctx, tenant, sharedautoscan.DefaultPolicy(), time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[uuid.UUID]bool{}
		for _, g := range got {
			out[g.AssetID] = true
		}
		return out, refusals
	}
	policy := sharedautoscan.DefaultPolicy()
	automatic := func(address string) error {
		return dispatchguard.AuthorizeAutomaticScan(f.db.DB.DB, sensordispatch.Payload{
			TenantID: tenant.String(), Targets: []string{address},
			Protocols: policy.Protocols[:1], Ports: policy.Ports[:1],
			Options: map[string]interface{}{"origin": "auto_scan"},
		})
	}

	// --- Consent OFF (the default for every connection) --------------------
	got, refusals := selected()
	for name, id := range map[string]uuid.UUID{"imported-only": imp, "scanned only by us": scanned, "public": public, "other connection": other,
		"scanned only by us (fact)": scannedFact, "scanned only by us (endpoint)": scannedEndpoint,
		"created by conn1, history only": historyOnly, "reported by identifier": viaID, "reported by fact": viaFact, "reported by endpoint": viaEndpoint} {
		if got[id] {
			t.Errorf("consent off: %s asset was selected for an automatic scan", name)
		}
	}
	for name, id := range map[string]uuid.UUID{"sensor": sensorAsset.ID, "imported, then a measured identifier": seen,
		"imported, then a measured fact": seenFact, "imported, then a measured endpoint": seenEndpoint} {
		if !got[id] {
			t.Errorf("consent off: %s asset must stay eligible", name)
		}
	}
	if refusals[sharedautoscan.ReasonImportedWithoutConsent] != 10 {
		t.Errorf("refusals = %v, want 10 imported_without_scan_consent", refusals)
	}
	if err := automatic("10.61.0.11"); err == nil {
		t.Error("consent off: the dispatch guard admitted an imported-only address")
	}
	if err := automatic(sensorIP); err != nil {
		t.Errorf("consent off: the dispatch guard refused a sensor-observed address: %v", err)
	}
	// An explicit scan a person asks for is not gated by consent.
	if err := dispatchguard.AuthorizeTargets(f.db.DB.DB, tenant.String(), []string{"10.61.0.11"}); err != nil {
		t.Errorf("the explicit path refused an imported asset's private address: %v", err)
	}

	// --- Consent ON for connection 1 --------------------------------------
	if _, err := f.svc.SetScanConsent(ctx, tenant, conn1, true, uuid.New()); err != nil {
		t.Fatal(err)
	}
	got, _ = selected()
	if !got[historyOnly] {
		t.Error("consent on: an asset whose only link to connection 1 is its creating history entry was not selected")
	}
	if !got[imp] || !got[scanned] || !got[scannedFact] || !got[scannedEndpoint] {
		t.Errorf("consent on: connection 1's owned assets were not selected (imported %v, scanned %v/%v/%v)",
			got[imp], got[scanned], got[scannedFact], got[scannedEndpoint])
	}
	if got[public] {
		t.Error("consent on but not owned: a public address was selected — consent must never widen ownership")
	}
	if got[other] {
		t.Error("connection 1's consent admitted connection 2's asset")
	}
	if !got[sensorAsset.ID] || !got[seen] {
		t.Error("consent on: sensor-observed assets dropped out")
	}
	if err := automatic("10.61.0.11"); err != nil {
		t.Errorf("consent on: the dispatch guard refused an owned imported address: %v", err)
	}
	if err := automatic("203.0.113.61"); err == nil {
		t.Error("consent on: the dispatch guard admitted a public imported address")
	}
	if err := automatic("10.61.0.15"); err == nil {
		t.Error("consent on for connection 1: the dispatch guard admitted connection 2's asset")
	}

	for name, id := range vias {
		if got[id] {
			t.Errorf("connection 1's consent admitted an asset only connection 2 and 3 reported (%s)", name)
		}
	}

	// --- Consent ON for a source that REPORTED, not created ----------------
	if _, err := f.svc.SetScanConsent(ctx, tenant, conn3, true, uuid.New()); err != nil {
		t.Fatal(err)
	}
	got, _ = selected()
	for name, id := range vias {
		if !got[id] {
			t.Errorf("consent on for a reporting source: the asset it reported by %s was not selected", name)
		}
	}
	if got[other] {
		t.Error("connection 3's consent admitted an asset it never reported")
	}

	// --- Consent withdrawn --------------------------------------------------
	if _, err := f.svc.SetScanConsent(ctx, tenant, conn1, false, uuid.New()); err != nil {
		t.Fatal(err)
	}
	got, _ = selected()
	if got[imp] || got[scanned] || got[scannedFact] || got[scannedEndpoint] {
		t.Error("consent withdrawn: connection 1's imported-only assets are still selected")
	}
	if err := automatic("10.61.0.11"); err == nil {
		t.Error("consent withdrawn: the dispatch guard still admits the imported address")
	}
}

// Scan consent is about CONNECTIONS only. A spreadsheet upload is recorded as
// `imported` too, but it is a person's explicit list with no connection to
// consent on: an asset it created, or one it listed, stays eligible exactly as
// before. An SBOM upload creates `declared` assets and is untouched.
//
// Decision for the mixed case: a spreadsheet vouching for an asset keeps it
// eligible whichever came first — the connection's pull is then not the ONLY
// reason it is in scope.
//
// MUTATION (goes red): drop the connection-ref scoping from the created-by
// clause (every `imported` creation, spreadsheet included, is gated); drop the
// spreadsheet-listed clause (a CMDB asset a person listed stays gated).
func TestIntegration_ScanConsent_OnlyConnectionImportsAreGated(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	conn := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}
	assets := NewAssetService(f.db)

	sheet := func(serial, ip string) uuid.UUID {
		t.Helper()
		res := assets.BulkCreateAssets(tenant, []models.AssetInput{sourceHost(serial, ip, "sheet-"+serial).Input})
		if len(res.Results) != 1 || res.Results[0].ID == nil {
			t.Fatalf("spreadsheet row %s: %+v", serial, res.Results)
		}
		return *res.Results[0].ID
	}
	pull := func(serial, ip string) (uuid.UUID, identity.Outcome) {
		t.Helper()
		res := f.svc.ResolveAssets(ctx, tenant, conn, []SourceAssetItem{sourceHost(serial, ip, "sheet-"+serial)})
		if res[0].AssetID == nil {
			t.Fatalf("pull %s: %+v", serial, res[0])
		}
		return *res[0].AssetID, identity.Outcome(res[0].Outcome)
	}

	sheetOnly := sheet("SC-SHEET-1", "10.62.0.11")
	sheetFirst := sheet("SC-SHEET-2", "10.62.0.12")
	if id, outcome := pull("SC-SHEET-2", "10.62.0.12"); id != sheetFirst || outcome != identity.OutcomeMatched {
		t.Fatalf("the pull did not match the spreadsheet's asset: %v %s", id, outcome)
	}
	pulledFirst, outcome := pull("SC-SHEET-3", "10.62.0.13")
	if outcome != identity.OutcomeCreated {
		t.Fatalf("pull created = %s", outcome)
	}
	if again := sheet("SC-SHEET-3", "10.62.0.13"); again != pulledFirst {
		t.Fatalf("the spreadsheet did not match the pulled asset: %v vs %v", again, pulledFirst)
	}
	cmdbOnly, _ := pull("SC-SHEET-4", "10.62.0.14")

	// SBOM: an uploaded SBOM creates its subject as a DECLARED application
	// asset (no address, so never an auto-scan candidate either way), and an
	// SBOM uploaded onto the spreadsheet's host leaves it eligible.
	sbomSvc := NewSBOMIngestService(f.db, assets)
	subject, err := sbomSvc.Ingest(ctx, tenant, uuid.Nil, uuid.Nil, "app.cdx.json",
		strings.NewReader(cycloneDX(t, "scan-consent-app", comp("openssl", map[string]any{"version": "3.0.13"}))))
	if err != nil {
		t.Fatalf("sbom subject: %v", err)
	}
	if _, err := sbomSvc.Ingest(ctx, tenant, sheetOnly, uuid.Nil, "host.cdx.json",
		strings.NewReader(cycloneDX(t, "", comp("zlib", map[string]any{"version": "1.3"})))); err != nil {
		t.Fatalf("sbom onto the spreadsheet host: %v", err)
	}
	var sbomWithheld bool
	if err := f.db.QueryRow(`SELECT `+sharedautoscan.ImportedWithoutConsentSQL("a")+` FROM assets a WHERE a.id = $1`, subject.AssetID).Scan(&sbomWithheld); err != nil {
		t.Fatal(err)
	}
	if sbomWithheld {
		t.Error("an SBOM-created asset is withheld as if a connection imported it")
	}

	got, refusals, err := autoscan.NewStore(f.db).EligibleTargets(ctx, tenant, sharedautoscan.DefaultPolicy(), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := map[uuid.UUID]bool{}
	for _, g := range got {
		selected[g.AssetID] = true
	}
	policy := sharedautoscan.DefaultPolicy()
	automatic := func(address string) error {
		return dispatchguard.AuthorizeAutomaticScan(f.db.DB.DB, sensordispatch.Payload{
			TenantID: tenant.String(), Targets: []string{address},
			Protocols: policy.Protocols[:1], Ports: policy.Ports[:1],
			Options: map[string]interface{}{"origin": "auto_scan"},
		})
	}
	for name, c := range map[string]struct {
		id uuid.UUID
		ip string
	}{
		"spreadsheet only":                      {sheetOnly, "10.62.0.11"},
		"spreadsheet first, then a CMDB pull":   {sheetFirst, "10.62.0.12"},
		"CMDB pull first, then the spreadsheet": {pulledFirst, "10.62.0.13"},
	} {
		if !selected[c.id] {
			t.Errorf("%s: not selected for auto-scan — no connection consent can apply to it", name)
		}
		if err := automatic(c.ip); err != nil {
			t.Errorf("%s: the dispatch guard refused it: %v", name, err)
		}
	}
	// The other polarity, in the same tenant: a CMDB-only asset is still gated.
	if selected[cmdbOnly] {
		t.Error("a CMDB-only asset was selected without consent")
	}
	if err := automatic("10.62.0.14"); err == nil {
		t.Error("the dispatch guard admitted a CMDB-only address without consent")
	}
	if refusals[sharedautoscan.ReasonImportedWithoutConsent] != 1 {
		t.Errorf("refusals = %v, want exactly 1 imported_without_scan_consent (the CMDB-only asset)", refusals)
	}
}
