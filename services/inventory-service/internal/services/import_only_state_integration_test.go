package services

// The STORED import-only state (assets.import_only_sources, platform ADR-0002
// D10 as amended through the real write paths and the real
// checkpoints:
//
//   - set by a connection's import, never by a spreadsheet or a sensor;
//   - cleared by independent measured evidence (identifier, fact or
//     endpoint), never by an active scan's own result;
//   - cleared by a person's spreadsheet listing;
//   - on a merge, kept only when every merged asset was import-only;
//   - refused at selection (EligibleTargets) and at authorization
//     (AuthorizeAutomaticScan, which job creation, the platform's unit
//     authorizer and sensor pickup all run) in undeclared private space,
//     admitted with consent or inside a segment a person declared;
//   - the authorization is set-based and skips the consent clause for a
//     tenant with no import-only asset;
//   - the stored rule agrees with the old derived rule, and so does the
//     upgrade backfill in schema.sql.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// --- writers: the identity repository, as every producer reaches it --------

func assetRef(tenant, asset uuid.UUID) identity.AssetRef {
	return identity.AssetRef{TenantID: tenant.String(), ID: asset.String()}
}

func writeIdentifier(t *testing.T, f *sourceFixture, tenant, asset uuid.UUID, kind identity.Kind, value string, sk identity.SourceKind, ref string) {
	t.Helper()
	if _, err := pgidentity.New(f.db.DB.DB).AttachIdentifiers(context.Background(), assetRef(tenant, asset), []identity.Identifier{{
		Kind: kind, Value: value, Confidence: 1, Source: identity.Source{Kind: sk, Ref: ref},
	}}); err != nil {
		t.Fatal(err)
	}
}

func writeFact(t *testing.T, f *sourceFixture, tenant, asset uuid.UUID, sk identity.SourceKind, ref string) {
	t.Helper()
	producer := "device-agent"
	if sk == identity.SourceImported {
		producer = "connector"
	}
	if err := pgidentity.New(f.db.DB.DB).UpsertFacts(context.Background(), assetRef(tenant, asset), producer, []pgidentity.Fact{{
		Key: "os.name", Value: "linux", SourceKind: sk, SourceRef: ref,
	}}); err != nil {
		t.Fatal(err)
	}
}

func writeEndpoint(t *testing.T, f *sourceFixture, tenant, asset uuid.UUID, ip string, sk identity.SourceKind, ref string) {
	t.Helper()
	if _, err := pgidentity.New(f.db.DB.DB).UpsertEndpoints(context.Background(), assetRef(tenant, asset), []identity.EndpointObservation{{
		Address: ip, Port: 443, Transport: "tcp", Source: identity.Source{Kind: sk, Ref: ref},
	}}); err != nil {
		t.Fatal(err)
	}
}

// importOnlySources reads the stored state; nil is "not import-only".
func importOnlySources(t *testing.T, f *sourceFixture, asset uuid.UUID) []string {
	t.Helper()
	var refs pq.StringArray
	if err := f.db.QueryRow(`SELECT import_only_sources FROM assets WHERE id = $1`, asset).Scan(&refs); err != nil {
		t.Fatal(err)
	}
	if refs == nil {
		return nil
	}
	return []string(refs)
}

// countingQueryer is a dispatchguard.Queryer that records every statement.
type countingQueryer struct {
	db      *sql.DB
	queries []string
}

func (c *countingQueryer) QueryRow(q string, args ...any) *sql.Row {
	c.queries = append(c.queries, q)
	return c.db.QueryRow(q, args...)
}

func (c *countingQueryer) mentions(s string) int {
	n := 0
	for _, q := range c.queries {
		if strings.Contains(q, s) {
			n++
		}
	}
	return n
}

func automaticPayload(tenant uuid.UUID, targets ...string) sensordispatch.Payload {
	policy := sharedautoscan.DefaultPolicy()
	return sensordispatch.Payload{
		TenantID: tenant.String(), Targets: targets,
		Protocols: policy.Protocols[:1], Ports: policy.Ports[:1],
		Options: map[string]interface{}{"origin": "auto_scan"},
	}
}

func (f *sourceFixture) importAsset(t *testing.T, tenant uuid.UUID, src identity.Source, serial, ip string) uuid.UUID {
	t.Helper()
	res := f.svc.ResolveAssets(context.Background(), tenant, src, []SourceAssetItem{sourceHost(serial, ip, "host-"+strings.ToLower(serial))})
	if res[0].Outcome != string(identity.OutcomeCreated) || res[0].AssetID == nil {
		t.Fatalf("import %s: %+v", serial, res[0])
	}
	return *res[0].AssetID
}

func (f *sourceFixture) selected(t *testing.T, tenant uuid.UUID) (map[uuid.UUID]bool, map[sharedautoscan.Reason]int) {
	t.Helper()
	got, refusals, err := autoscan.NewStore(f.db).EligibleTargets(context.Background(), tenant, sharedautoscan.DefaultPolicy(), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uuid.UUID]bool{}
	for _, g := range got {
		out[g.AssetID] = true
	}
	return out, refusals
}

func (f *sourceFixture) segmentRow(t *testing.T, tenant uuid.UUID, cidr, metadata, sourceKind string) {
	t.Helper()
	if _, err := f.db.Exec(`INSERT INTO network_segments (tenant_id, name, segment_type, value, network_type, environment, is_active, metadata, source_kind)
		VALUES ($1, $2, 'cidr', $2, 'private', 'production', true, $3::jsonb, NULLIF($4, ''))`, tenant, cidr, metadata, sourceKind); err != nil {
		t.Fatal(err)
	}
}

// MUTATION (each goes red here): CreateAsset not storing the connection ref;
// the `scan`/`scan:%` exclusion dropped from independentEvidenceSQL (the
// scan-measured assets clear); attach / UpsertFacts / upsertEndpoints not
// calling ClearImportOnlyIfVouched; the spreadsheet clear in
// createAssetResolved removed; MergeImportOnly not called by ExecuteMerge, or
// keeping the state when one side was not import-only.
func TestIntegration_ImportOnly_StoredStateFollowsTheEvidence(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	conn := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}
	conn2 := identity.Source{Kind: identity.SourceImported, Ref: "netbox:" + uuid.NewString()}
	assets := NewAssetService(f.db)

	imp := f.importAsset(t, tenant, conn, "IO-IMP-1", "10.71.0.11")
	if got := importOnlySources(t, f, imp); len(got) != 1 || got[0] != conn.Ref {
		t.Fatalf("a connection-created asset stores %v, want [%s]", got, conn.Ref)
	}

	sheet := assets.BulkCreateAssets(tenant, []models.AssetInput{sourceHost("IO-SHEET-1", "10.71.0.12", "sheet-1").Input})
	if sheet.Results[0].ID == nil || importOnlySources(t, f, *sheet.Results[0].ID) != nil {
		t.Errorf("a spreadsheet-created asset is import-only: %+v", sheet.Results[0])
	}
	sensorIP, sensorHost := "10.71.0.13", "sensor-13"
	sensorAsset, _, err := assets.CreateAssetFromSource(tenant, models.AssetInput{
		ClassKey: "server", IPAddress: &sensorIP, Hostname: &sensorHost, DisplayName: &sensorHost,
		Identifiers: []models.AssetIdentifierInput{{Kind: string(identity.KindSerialNumber), Value: "IO-SENSOR-1"}},
	}, identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + uuid.NewString()})
	if err != nil || importOnlySources(t, f, sensorAsset.ID) != nil {
		t.Fatalf("a sensor-created asset is import-only (err %v)", err)
	}

	// A scan's own result, in every table, leaves the state alone.
	scanned := f.importAsset(t, tenant, conn, "IO-SCAN-1", "10.71.0.14")
	writeIdentifier(t, f, tenant, scanned, identity.KindMACAddress, "02:00:00:71:00:14", identity.SourceMeasured, "scan:"+uuid.NewString())
	writeFact(t, f, tenant, scanned, identity.SourceMeasured, "scan:"+uuid.NewString())
	writeEndpoint(t, f, tenant, scanned, "10.71.0.14", identity.SourceMeasured, "scan")
	if importOnlySources(t, f, scanned) == nil {
		t.Error("an active scan's own result cleared the import-only state")
	}
	// Another connection reporting it is not independent either.
	writeIdentifier(t, f, tenant, scanned, identity.KindSerialNumber, "IO-SCAN-1-NB", identity.SourceImported, conn2.Ref)
	if importOnlySources(t, f, scanned) == nil {
		t.Error("another connection's report cleared the import-only state")
	}
	// A sensor re-sighting the serial the CMDB imported leaves that row
	// `imported` (measured does not outrank imported), so the asset still
	// carries no measured row but the scan's — and the scan's must not count.
	// This is the case where the stored-row check, not the write's own
	// provenance, decides.
	writeIdentifier(t, f, tenant, scanned, identity.KindSerialNumber, "IO-SCAN-1", identity.SourceMeasured, "sensor:"+uuid.NewString())
	if importOnlySources(t, f, scanned) == nil {
		t.Error("a sensor re-sighting an imported identifier, beside a scan's own rows, cleared the import-only state")
	}

	// Independent evidence clears it, whichever table carries it.
	for name, write := range map[string]func(uuid.UUID){
		"identifier": func(a uuid.UUID) {
			writeIdentifier(t, f, tenant, a, identity.KindMACAddress, "02:00:00:71:00:21", identity.SourceMeasured, "sensor:"+uuid.NewString())
		},
		"fact": func(a uuid.UUID) { writeFact(t, f, tenant, a, identity.SourceMeasured, "agent:job:"+uuid.NewString()) },
		"endpoint": func(a uuid.UUID) {
			writeEndpoint(t, f, tenant, a, "10.71.0.99", identity.SourceMeasured, "agent:"+uuid.NewString())
		},
	} {
		a := f.importAsset(t, tenant, conn, "IO-SEEN-"+name, "10.71.1."+map[string]string{"identifier": "1", "fact": "2", "endpoint": "3"}[name])
		write(a)
		if got := importOnlySources(t, f, a); got != nil {
			t.Errorf("a measured %s from a sensor/agent did not clear the import-only state: %v", name, got)
		}
	}

	// A person's spreadsheet listing it clears it, even when it changes nothing.
	listed := f.importAsset(t, tenant, conn, "IO-LISTED-1", "10.71.0.15")
	again := assets.BulkCreateAssets(tenant, []models.AssetInput{sourceHost("IO-LISTED-1", "10.71.0.15", "host-io-listed-1").Input})
	if again.Results[0].ID == nil || *again.Results[0].ID != listed {
		t.Fatalf("the spreadsheet did not match the imported asset: %+v", again.Results[0])
	}
	if importOnlySources(t, f, listed) != nil {
		t.Error("a spreadsheet listing did not clear the import-only state")
	}

	// Merges.
	merge := func(survivor, source uuid.UUID) {
		t.Helper()
		svc := NewMergeProposalService(f.db)
		selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
		preview, err := svc.PreviewMerge(ctx, tenant, uuid.Nil, selection)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ExecuteMerge(ctx, tenant, uuid.Nil, seedUser(t, f.db, tenant),
			MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "same device"}); err != nil {
			t.Fatal(err)
		}
	}
	bothA := f.importAsset(t, tenant, conn, "IO-MERGE-A", "10.71.2.1")
	bothB := f.importAsset(t, tenant, conn2, "IO-MERGE-B", "10.71.2.2")
	merge(bothA, bothB)
	if got := importOnlySources(t, f, bothA); len(got) != 2 || !strings.Contains(strings.Join(got, ","), conn.Ref) || !strings.Contains(strings.Join(got, ","), conn2.Ref) {
		t.Errorf("merging two import-only assets: survivor carries %v, want both connections", got)
	}
	half := f.importAsset(t, tenant, conn, "IO-MERGE-C", "10.71.2.3")
	declared := assets.BulkCreateAssets(tenant, []models.AssetInput{sourceHost("IO-MERGE-D", "10.71.2.4", "sheet-d").Input})
	merge(half, *declared.Results[0].ID)
	if got := importOnlySources(t, f, half); got != nil {
		t.Errorf("merging a spreadsheet's asset into an import-only one: survivor still import-only %v", got)
	}
	reverse := f.importAsset(t, tenant, conn, "IO-MERGE-E", "10.71.2.5")
	merge(sensorAsset.ID, reverse)
	if got := importOnlySources(t, f, sensorAsset.ID); got != nil {
		t.Errorf("merging an import-only asset into a sensor's: survivor became import-only %v", got)
	}
}

// MUTATION (each goes red here): drop the declared-segment narrowing from
// AuthorizeAutomaticScan or from scannableAssets; read learned or
// connection-imported segments as declared; drop the import clause from
// targetAssets; drop the AnyImportOnly short-circuit (the no-import-only
// tenant then mentions source_scan_consents); go back to one query per
// target (the 500-target count grows).
func TestIntegration_ImportOnly_CheckpointsAndDeclaredSegments(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	conn := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}
	raw := f.db.DB.DB

	f.segmentRow(t, tenant, "10.72.1.0/24", `{}`, "")
	f.segmentRow(t, tenant, "10.72.2.0/24", `{"source":"interrogation"}`, "")
	f.segmentRow(t, tenant, "10.72.3.0/24", `{}`, "imported")
	f.segmentRow(t, tenant, "10.72.4.0/24", `{"source":"interrogation","claimed":{"by":"`+uuid.NewString()+`"}}`, "")

	undeclared := f.importAsset(t, tenant, conn, "IO-CP-0", "10.72.0.5")
	inDeclared := f.importAsset(t, tenant, conn, "IO-CP-1", "10.72.1.5")
	inLearned := f.importAsset(t, tenant, conn, "IO-CP-2", "10.72.2.5")
	inImported := f.importAsset(t, tenant, conn, "IO-CP-3", "10.72.3.5")
	inClaimed := f.importAsset(t, tenant, conn, "IO-CP-4", "10.72.4.5")
	addrs := map[uuid.UUID]string{undeclared: "10.72.0.5", inDeclared: "10.72.1.5", inLearned: "10.72.2.5", inImported: "10.72.3.5", inClaimed: "10.72.4.5"}
	wantEligible := map[uuid.UUID]bool{inDeclared: true, inClaimed: true}

	check := func(phase string, consent bool) {
		t.Helper()
		got, refusals := f.selected(t, tenant)
		wantRefused := 0
		for id, addr := range addrs {
			want := consent || wantEligible[id]
			if !want {
				wantRefused++
			}
			if got[id] != want {
				t.Errorf("%s: EligibleTargets(%s) = %v, want %v", phase, addr, got[id], want)
			}
			err := dispatchguard.AuthorizeAutomaticScan(raw, automaticPayload(tenant, addr))
			if (err == nil) != want {
				t.Errorf("%s: AuthorizeAutomaticScan(%s) = %v, want allowed=%v", phase, addr, err, want)
			}
			if err != nil && !strings.Contains(err.Error(), "no eligible tenant asset") {
				t.Errorf("%s: refusal for %s changed: %v", phase, addr, err)
			}
		}
		if refusals[sharedautoscan.ReasonImportedWithoutConsent] != wantRefused {
			t.Errorf("%s: refusals = %v, want %d imported_without_scan_consent", phase, refusals, wantRefused)
		}
	}
	check("consent off", false)

	// The explicit path a person uses does not read the rule.
	if err := dispatchguard.AuthorizeTargets(raw, tenant.String(), []string{"10.72.0.5"}); err != nil {
		t.Errorf("a person's scan of an import-only address was refused: %v", err)
	}

	if _, err := f.svc.SetScanConsent(ctx, tenant, conn, true, uuid.New()); err != nil {
		t.Fatal(err)
	}
	check("consent on", true)

	// Scanned while consent held: the result is not independent evidence,
	// so withdrawing consent takes effect again.
	writeIdentifier(t, f, tenant, undeclared, identity.KindMACAddress, "02:00:00:72:00:05", identity.SourceMeasured, "scan:"+uuid.NewString())
	writeEndpoint(t, f, tenant, undeclared, "10.72.0.5", identity.SourceMeasured, "scan:"+uuid.NewString())
	if _, err := f.svc.SetScanConsent(ctx, tenant, conn, false, uuid.New()); err != nil {
		t.Fatal(err)
	}
	check("consent withdrawn after a scan", false)

	// A sensor seeing it clears the state for good.
	writeIdentifier(t, f, tenant, undeclared, identity.KindMACAddress, "02:00:00:72:01:05", identity.SourceMeasured, "sensor:"+uuid.NewString())
	got, _ := f.selected(t, tenant)
	if !got[undeclared] {
		t.Error("a sensor-measured identifier did not make the asset eligible")
	}
	if err := dispatchguard.AuthorizeAutomaticScan(raw, automaticPayload(tenant, "10.72.0.5")); err != nil {
		t.Errorf("a sensor-seen asset is still refused: %v", err)
	}

	// One job naming every target is authorized in one set-based lookup,
	// and the first refusal in target order is still the one returned.
	q := &countingQueryer{db: raw}
	err := dispatchguard.AuthorizeAutomaticScan(q, automaticPayload(tenant, "10.72.0.5", "10.72.1.5", "10.72.2.5", "203.0.113.9"))
	if err == nil || !strings.Contains(err.Error(), "no eligible tenant asset") {
		t.Errorf("mixed job: %v, want the learned-segment target's refusal first", err)
	}
	if q.mentions("source_scan_consents") != 1 {
		t.Errorf("mixed job ran the consent clause in %d queries, want 1:\n%s", q.mentions("source_scan_consents"), strings.Join(q.queries, "\n---\n"))
	}
}

// A 500-target job is authorized in the same number of queries as a 1-target
// one, and a tenant with no import-only asset never runs the consent clause.
func TestIntegration_ImportOnly_AuthorizationIsSetBased(t *testing.T) {
	f := newSourceFixture(t)
	raw := f.db.DB.DB
	for _, withImportOnly := range []bool{false, true} {
		tenant := f.tenant(t)
		var targets []string
		for i := 0; i < 500; i++ {
			addr := "10.73." + itoa(i/250) + "." + itoa(i%250+1)
			targets = append(targets, addr)
			if _, err := raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status,import_only_sources)
				VALUES($1,$2,$3,$4::inet,'server','hardware.computer.server','monitoring',$5)`,
				uuid.New(), tenant, "bulk-"+addr, addr, nullIf(!withImportOnly || i%2 == 1, pq.StringArray{"cmdb:bulk"})); err != nil {
				t.Fatal(err)
			}
		}
		if withImportOnly {
			if _, err := raw.Exec(`INSERT INTO source_scan_consents(tenant_id,source_ref,allow_active_scan) VALUES($1,'cmdb:bulk',true)`, tenant); err != nil {
				t.Fatal(err)
			}
		}
		one := &countingQueryer{db: raw}
		if err := dispatchguard.AuthorizeAutomaticScan(one, automaticPayload(tenant, targets[0])); err != nil {
			t.Fatalf("import-only=%v: one target: %v", withImportOnly, err)
		}
		many := &countingQueryer{db: raw}
		if err := dispatchguard.AuthorizeAutomaticScan(many, automaticPayload(tenant, targets...)); err != nil {
			t.Fatalf("import-only=%v: 500 targets: %v", withImportOnly, err)
		}
		if len(many.queries) != len(one.queries) || len(many.queries) > 4 {
			t.Errorf("import-only=%v: 500 targets took %d queries, one target %d; want the same, at most 4", withImportOnly, len(many.queries), len(one.queries))
		}
		if n := many.mentions("source_scan_consents"); (n > 0) != withImportOnly {
			t.Errorf("import-only=%v: the consent clause ran in %d queries", withImportOnly, n)
		}
		// The planner skips it the same way: refusals stay zero either way
		// (consent is on for the import-only half).
		if _, refusals := f.selected(t, tenant); refusals[sharedautoscan.ReasonImportedWithoutConsent] != 0 {
			t.Errorf("import-only=%v: planner refusals %v", withImportOnly, refusals)
		}
	}
}

func nullIf(null bool, v pq.StringArray) any {
	if null {
		return nil
	}
	return v
}

// derivedImportedWithoutConsentSQL is the rule as it was before the state was
// stored (shared/autoscan, through 4.4): kept here only, as the reference the
// stored rule and the upgrade backfill are checked against.
func derivedImportedWithoutConsentSQL(a string) string {
	r := strings.NewReplacer(
		"{a}", a,
		"{sheet}", "'"+identity.SpreadsheetImportSourceRef+"'",
		"{conn_ch}", identity.ConnectionSourceRefSQL("ch.source"),
	)
	return r.Replace(`(
	EXISTS (SELECT 1 FROM asset_history ch
	         WHERE ch.tenant_id = {a}.tenant_id AND ch.asset_id = {a}.id
	           AND ch.action = 'created' AND ch.changes_json->>'source_kind' = 'imported'
	           AND {conn_ch})
	AND NOT EXISTS (
	    SELECT 1 FROM asset_identifiers mi
	     WHERE mi.tenant_id = {a}.tenant_id AND mi.asset_id = {a}.id AND mi.source_kind = 'measured'
	       AND COALESCE(mi.source_ref, '') <> 'scan' AND COALESCE(mi.source_ref, '') NOT LIKE 'scan:%'
	    UNION ALL
	    SELECT 1 FROM asset_facts mf
	     WHERE mf.tenant_id = {a}.tenant_id AND mf.asset_id = {a}.id AND mf.source_kind = 'measured'
	       AND mf.source_ref <> 'scan' AND mf.source_ref NOT LIKE 'scan:%'
	    UNION ALL
	    SELECT 1 FROM asset_endpoints me
	     WHERE me.tenant_id = {a}.tenant_id AND me.asset_id = {a}.id AND me.source_kind = 'measured'
	       AND COALESCE(me.source_ref, '') <> 'scan' AND COALESCE(me.source_ref, '') NOT LIKE 'scan:%'
	    UNION ALL
	    SELECT 1 FROM asset_history sh
	     WHERE sh.tenant_id = {a}.tenant_id AND sh.asset_id = {a}.id AND sh.source = {sheet}
	       AND sh.action <> 'created')
	AND NOT EXISTS (
	    SELECT 1 FROM source_scan_consents sc
	     WHERE sc.tenant_id = {a}.tenant_id AND sc.allow_active_scan
	       AND sc.source_ref IN (
	           SELECT ch.source FROM asset_history ch
	            WHERE ch.tenant_id = {a}.tenant_id AND ch.asset_id = {a}.id
	              AND ch.action = 'created' AND ch.changes_json->>'source_kind' = 'imported'
	           UNION ALL
	           SELECT ii.source_ref FROM asset_identifiers ii
	            WHERE ii.tenant_id = {a}.tenant_id AND ii.asset_id = {a}.id AND ii.source_kind = 'imported'
	           UNION ALL
	           SELECT fi.source_ref FROM asset_facts fi
	            WHERE fi.tenant_id = {a}.tenant_id AND fi.asset_id = {a}.id AND fi.source_kind = 'imported'
	           UNION ALL
	           SELECT ei.source_ref FROM asset_endpoints ei
	            WHERE ei.tenant_id = {a}.tenant_id AND ei.asset_id = {a}.id AND ei.source_kind = 'imported'))
)`)
}

// backfillStatement is the one-time UPDATE of the POST-MIGRATIONS block
// "assets.import_only_sources", read out of the schema file so the test runs
// the text an upgrade runs.
func backfillStatement(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "database", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	start := strings.Index(s, "    UPDATE public.assets a SET import_only_sources = c.refs")
	if start < 0 {
		t.Fatal("the import_only_sources backfill is missing from schema.sql")
	}
	end := strings.Index(s[start:], ";")
	return s[start : start+end]
}

// The stored rule returns the old derived rule's verdict for every asset of a
// populated tenant built through the real write paths, under every consent
// state; and the upgrade backfill, run over the same tenant with the stored
// state wiped, reconstructs it. (The declared-segment narrowing is applied by
// the callers, not by the predicate, so it is not part of this comparison;
// TestIntegration_ImportOnly_CheckpointsAndDeclaredSegments covers it.)
//
// MUTATION (goes red): any clause of the backfill's evidence check dropped;
// the consent join reading only the creating connection.
func TestIntegration_ImportOnly_StoredRuleMatchesTheDerivedRule(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	conn1 := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}
	conn2 := identity.Source{Kind: identity.SourceImported, Ref: "netbox:" + uuid.NewString()}
	conn3 := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}
	assets := NewAssetService(f.db)

	n := 0
	next := func() (string, string) { n++; return "EQ-" + itoa(n), "10.74.0." + itoa(n) }
	for _, src := range []identity.Source{conn1, conn2} {
		serial, ip := next()
		f.importAsset(t, tenant, src, serial, ip) // untouched
		serial, ip = next()
		a := f.importAsset(t, tenant, src, serial, ip)
		writeIdentifier(t, f, tenant, a, identity.KindMACAddress, "02:00:00:74:00:"+itoa(10+n), identity.SourceMeasured, "sensor:x")
		serial, ip = next()
		a = f.importAsset(t, tenant, src, serial, ip)
		writeIdentifier(t, f, tenant, a, identity.KindMACAddress, "02:00:00:74:00:"+itoa(10+n), identity.SourceMeasured, "scan:x")
		writeFact(t, f, tenant, a, identity.SourceMeasured, "scan")
		serial, ip = next()
		a = f.importAsset(t, tenant, src, serial, ip)
		writeFact(t, f, tenant, a, identity.SourceMeasured, "agent:job:x")
		serial, ip = next()
		a = f.importAsset(t, tenant, src, serial, ip)
		writeEndpoint(t, f, tenant, a, ip, identity.SourceMeasured, "interrogation:x")
		serial, ip = next()
		a = f.importAsset(t, tenant, src, serial, ip)
		writeEndpoint(t, f, tenant, a, ip, identity.SourceMeasured, "scan:x")
		serial, ip = next()
		a = f.importAsset(t, tenant, src, serial, ip)
		writeIdentifier(t, f, tenant, a, identity.KindSerialNumber, serial+"-3", identity.SourceImported, conn3.Ref)
		serial, ip = next()
		a = f.importAsset(t, tenant, src, serial, ip)
		writeFact(t, f, tenant, a, identity.SourceImported, conn3.Ref)
		serial, ip = next()
		a = f.importAsset(t, tenant, src, serial, ip)
		writeEndpoint(t, f, tenant, a, ip, identity.SourceImported, conn3.Ref)
		// Listed by a person's spreadsheet under a new name, so the listing
		// writes a history row in either world.
		serial, ip = next()
		f.importAsset(t, tenant, src, serial, ip)
		assets.BulkCreateAssets(tenant, []models.AssetInput{sourceHost(serial, ip, "renamed-"+strings.ToLower(serial)).Input})
	}
	serial, ip := next()
	assets.BulkCreateAssets(tenant, []models.AssetInput{sourceHost(serial, ip, "sheet").Input})
	sensorIP, sensorHost := "10.74.1.1", "eq-sensor"
	if _, _, err := assets.CreateAssetFromSource(tenant, models.AssetInput{
		ClassKey: "server", IPAddress: &sensorIP, Hostname: &sensorHost, DisplayName: &sensorHost,
		Identifiers: []models.AssetIdentifierInput{{Kind: string(identity.KindSerialNumber), Value: "EQ-SENSOR"}},
	}, identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + uuid.NewString()}); err != nil {
		t.Fatal(err)
	}

	compare := func(phase string) {
		t.Helper()
		rows, err := f.db.Query(`SELECT a.id, host(a.primary_address), `+sharedautoscan.ImportedWithoutConsentSQL("a")+`, `+derivedImportedWithoutConsentSQL("a")+`
			FROM assets a WHERE a.tenant_id = $1`, tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		count, withheld := 0, 0
		for rows.Next() {
			var id uuid.UUID
			var addr sql.NullString
			var stored, derived bool
			if err := rows.Scan(&id, &addr, &stored, &derived); err != nil {
				t.Fatal(err)
			}
			count++
			if stored {
				withheld++
			}
			if stored != derived {
				t.Errorf("%s: asset %s (%s): stored rule %v, derived rule %v", phase, id, addr.String, stored, derived)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if count < 20 {
			t.Fatalf("%s: fixture has %d assets", phase, count)
		}
		t.Logf("%s: %d assets, %d withheld", phase, count, withheld)
	}
	states := func(prefix string) {
		t.Helper()
		compare(prefix + "no consent")
		for _, c := range []identity.Source{conn1, conn3, conn2} {
			if _, err := f.svc.SetScanConsent(ctx, tenant, c, true, uuid.New()); err != nil {
				t.Fatal(err)
			}
			compare(prefix + "consent on for " + c.Ref)
		}
		for _, c := range []identity.Source{conn1, conn2, conn3} {
			if _, err := f.svc.SetScanConsent(ctx, tenant, c, false, uuid.New()); err != nil {
				t.Fatal(err)
			}
		}
	}
	states("")

	// The upgrade backfill, over the same tenant with the state wiped.
	if _, err := f.db.Exec(`UPDATE assets SET import_only_sources = NULL WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(backfillStatement(t)+` AND a.tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	states("after backfill, ")
}
