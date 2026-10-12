package services

// The one deferral store and the one replay ( F8), driven through the
// real paths: IngestFindingsReport writes the held row, ApproveAssets and the
// identity evidence sweep replay it, and the schema's own adoption function
// moves the stores it replaced.
//
// Mutation log (each was run and went red, then restored):
//   - delete the replayDeferredCrypto call in ApproveAssets
//     → PendingAssetHeldThenReplayedOnApproval fails ("0 crypto
//     configurations after approval");
//   - delete the replayDueDeferredCrypto call in SweepIdentityEvidence
//     → EnforceHeldEvidenceReplaysWhenLinkedAndMonitoring fails;
//   - delete the POST-MIGRATIONS adoption block from schema.sql
//     → MigrationMovesLegacyStores fails (the function is not in the file).
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// deferralRowState counts what deferred_crypto_findings holds for a tenant.
type deferralRowState struct {
	assetHeld, observationHeld, replayed int
}

func deferralRows(t *testing.T, f leafLinkFixture) deferralRowState {
	t.Helper()
	var s deferralRowState
	if err := f.db.QueryRow(`SELECT
	   count(*) FILTER (WHERE replayed_at IS NULL AND observation_id IS NULL),
	   count(*) FILTER (WHERE replayed_at IS NULL AND observation_id IS NOT NULL),
	   count(*) FILTER (WHERE replayed_at IS NOT NULL)
	  FROM deferred_crypto_findings WHERE tenant_id=$1`, f.tenant).Scan(&s.assetHeld, &s.observationHeld, &s.replayed); err != nil {
		t.Fatal(err)
	}
	return s
}

func deferralCryptoCount(t *testing.T, f leafLinkFixture, asset uuid.UUID) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT count(*) FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=$2 AND deleted_at IS NULL`,
		f.tenant, asset).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func deferralCryptoAddedFor(lc *syncLifecycle, asset uuid.UUID) int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	n := 0
	for _, c := range lc.got {
		if p, ok := c.payload.(*invevents.CryptoConfigurationAddedPayload); ok && c.eventType == invevents.EventTypeCryptoConfigurationAdded && p.AssetID == asset {
			n++
		}
	}
	return n
}

// (a) A crypto finding for a new pending asset is held, not materialized;
// approval replays it through the live materialization, marks it replayed and
// publishes crypto.configuration_added; a second approval adds nothing.
func TestIntegration_DeferredCrypto_PendingAssetHeldThenReplayedOnApproval(t *testing.T) {
	f := newLeafLinkFixture(t)
	lc := &syncLifecycle{}
	f.svc.eventPublisher = &EventPublisherService{lifecycle: lc, publisher: &noOpPublisher{}}

	finding := leafCertFinding("deferral-a.example.test", "198.51.100.140", 443, hexFingerprint("deferral-a"))
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{finding}, identity.StatusPendingApproval)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].AssetID == "" {
		t.Fatalf("setup: want one asset, got %+v", report.Results)
	}
	asset := uuid.MustParse(report.Results[0].AssetID)

	if got := deferralRows(t, f); got != (deferralRowState{assetHeld: 1}) {
		t.Fatalf("after a pending ingest: %+v, want exactly one row held for the asset", got)
	}
	if n := deferralCryptoCount(t, f, asset); n != 0 {
		t.Fatalf("%d crypto configurations for an asset awaiting approval, want 0", n)
	}

	if err := f.svc.ApproveAssets(f.tenant, []uuid.UUID{asset}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if n := deferralCryptoCount(t, f, asset); n != 1 {
		t.Fatalf("%d crypto configurations after approval, want 1 replayed from the held row", n)
	}
	if got := deferralRows(t, f); got != (deferralRowState{replayed: 1}) {
		t.Fatalf("after approval: %+v, want the one row marked replayed", got)
	}
	var landedOn uuid.UUID
	if err := f.db.QueryRow(`SELECT asset_id FROM deferred_crypto_findings WHERE tenant_id=$1`, f.tenant).Scan(&landedOn); err != nil || landedOn != asset {
		t.Fatalf("replayed row names asset %s (err %v), want %s", landedOn, err, asset)
	}
	if n := deferralCryptoAddedFor(lc, asset); n != 1 {
		t.Fatalf("%d crypto.configuration_added events for the replay, want 1 — a replay publishes what a live ingest would", n)
	}

	// Idempotent: approving again replays nothing and creates nothing.
	if err := f.svc.ApproveAssets(f.tenant, []uuid.UUID{asset}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if n := deferralCryptoCount(t, f, asset); n != 1 {
		t.Fatalf("%d crypto configurations after a second approval, want still 1", n)
	}
	if got := deferralRows(t, f); got != (deferralRowState{replayed: 1}) {
		t.Fatalf("after a second approval: %+v, want unchanged", got)
	}
	if n := deferralCryptoAddedFor(lc, asset); n != 1 {
		t.Fatalf("%d crypto.configuration_added events after a second approval, want still 1", n)
	}

	// Once monitoring, the same finding materializes live and holds nothing.
	finding.RawData["observed_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{finding}, identity.StatusPendingApproval); err != nil {
		t.Fatal(err)
	}
	if got := deferralRows(t, f); got != (deferralRowState{replayed: 1}) {
		t.Fatalf("after ingesting onto a monitoring asset: %+v, want nothing new held", got)
	}
}

// (b) Under identity admission `enforce` the finding is held in the SAME table,
// waiting on its observation, and replays once that observation is linked to
// an asset that is monitoring — here approved by a transition that does not
// call the replay itself, so the identity evidence sweep is what replays it.
func TestIntegration_DeferredCrypto_EnforceHeldEvidenceReplaysWhenLinkedAndMonitoring(t *testing.T) {
	f := newLeafLinkFixture(t)
	// A declared segment, so the engine may admit a new asset there.
	f.svc.networkSegmentService = NewNetworkSegmentService(f.db, nil)
	if _, err := f.db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment)
 VALUES($1,$2,'Deferral test','cidr','198.51.100.0/24','production')`, uuid.New(), f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, f.tenant); err != nil {
		t.Fatal(err)
	}
	// Room for the one asset admission will create.
	if _, err := f.db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
 SELECT $1,id,'{"quantity":1}'::jsonb,'deferral test' FROM billable_items WHERE key='max_assets'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.identityEngine(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.svc.identityEng, err = identity.New(identity.Config{Repo: f.svc.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}

	finding := leafCertFinding("deferral-b.example.test", "198.51.100.141", 443, hexFingerprint("deferral-b"))
	finding.RawData["observed_at"] = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond).Format(time.RFC3339Nano)
	finding.RawData["discovery_id"] = "deferral-b-1"
	report, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{finding}, identity.StatusPendingApproval)
	if err != nil {
		t.Fatal(err)
	}
	var asset uuid.UUID
	if err := f.db.QueryRow(`SELECT id FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, f.tenant).Scan(&asset); err != nil {
		t.Fatalf("setup: want the one pending asset (report %+v): %v", report, err)
	}
	if got := deferralRows(t, f); got != (deferralRowState{observationHeld: 1}) {
		t.Fatalf("after an enforce-mode ingest: %+v, want one row held for the observation and none for the asset", got)
	}
	var payloads int
	if err := f.db.QueryRow(`SELECT count(*) FROM identity_observation_payloads WHERE tenant_id=$1`, f.tenant).Scan(&payloads); err != nil || payloads != 0 {
		t.Fatalf("%d identity_observation_payloads rows for a discovery finding (err %v), want 0 — crypto is held in one store", payloads, err)
	}

	// Pending: the sweep holds it.
	if n, err := f.svc.SweepIdentityEvidence(context.Background(), f.tenant); err != nil || n != 0 {
		t.Fatalf("sweep before approval replayed %d (err %v), want 0", n, err)
	}
	if n := deferralCryptoCount(t, f, asset); n != 0 {
		t.Fatalf("%d crypto configurations before approval, want 0", n)
	}

	// Approved by a segment rule / an Active Scan: nothing calls the replay
	// directly, so the sweep does.
	if _, err := f.db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, f.tenant, asset); err != nil {
		t.Fatal(err)
	}
	if n, err := f.svc.SweepIdentityEvidence(context.Background(), f.tenant); err != nil || n != 1 {
		t.Fatalf("sweep after approval replayed %d (err %v), want 1", n, err)
	}
	if n := deferralCryptoCount(t, f, asset); n != 1 {
		t.Fatalf("%d crypto configurations after the sweep, want 1", n)
	}
	if got := deferralRows(t, f); got != (deferralRowState{replayed: 1}) {
		t.Fatalf("after the sweep: %+v, want the held row replayed", got)
	}
	if n, err := f.svc.SweepIdentityEvidence(context.Background(), f.tenant); err != nil || n != 0 {
		t.Fatalf("a second sweep replayed %d (err %v), want 0", n, err)
	}
}

// deferralApplyAdoptionFunction executes the adoption function exactly as
// schema.sql's POST-MIGRATIONS block defines it, read from the file, so the
// test fails if the block is removed rather than passing on a database that
// still has the function from an earlier apply.
func deferralApplyAdoptionFunction(t *testing.T, f leafLinkFixture) {
	t.Helper()
	body := schemaSQL(t)
	const start = "CREATE OR REPLACE FUNCTION public.adopt_legacy_crypto_deferrals("
	i := strings.Index(body, start)
	if i < 0 {
		t.Fatal("schema.sql no longer defines public.adopt_legacy_crypto_deferrals — the POST-MIGRATIONS move of " +
			"the old deferral stores into deferred_crypto_findings is gone")
	}
	j := strings.Index(body[i:], "\n$$;\n")
	if j < 0 {
		t.Fatal("cannot find the end of public.adopt_legacy_crypto_deferrals in schema.sql")
	}
	if _, err := f.db.Exec(body[i : i+j+len("\n$$;")]); err != nil {
		t.Fatalf("apply the adoption function from schema.sql: %v", err)
	}
	if !strings.Contains(body[i+j:], "SELECT public.adopt_legacy_crypto_deferrals();") {
		t.Fatal("schema.sql defines the adoption function but never runs it on apply")
	}
}

// (c) The POST-MIGRATIONS block moves an asset's metadata array and an
// unmaterialized discovery payload into deferred_crypto_findings, exactly once,
// clears the metadata key, leaves host-observation payloads alone — and the
// moved rows replay through the real approval.
func TestIntegration_DeferredCrypto_MigrationMovesLegacyStores(t *testing.T) {
	f := newLeafLinkFixture(t)
	deferralApplyAdoptionFunction(t, f)
	ctx := context.Background()

	asset := seedAsset(t, f.db, f.tenant, "deferral-c.example.test", "server", "hardware.computer.server", "production", 0, 0)
	if _, err := f.db.Exec(`UPDATE assets SET asset_status='pending_approval' WHERE tenant_id=$1 AND id=$2`, f.tenant, asset); err != nil {
		t.Fatal(err)
	}
	first := leafCertFinding("deferral-c.example.test", "198.51.100.142", 443, hexFingerprint("deferral-c-443"))
	second := leafCertFinding("deferral-c.example.test", "198.51.100.142", 8443, hexFingerprint("deferral-c-8443"))
	for _, finding := range []IngestFinding{first, second} {
		// The engine attached these sockets when the findings were ingested.
		if err := f.svc.attachDecidedFindingEndpoint(ctx, f.tenant, asset, finding, identity.DecidedByLinkedObservation); err != nil {
			t.Fatal(err)
		}
	}
	legacy, err := json.Marshal(map[string]any{"deferred_findings": []IngestFinding{first, second}, "kept": "yes"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE assets SET metadata=$3 WHERE tenant_id=$1 AND id=$2`, f.tenant, asset, string(legacy)); err != nil {
		t.Fatal(err)
	}

	// An observation linked to the asset with one unmaterialized discovery
	// payload (no observed_at: the receipt supplies it) and one passive
	// host-observation payload, which stays where it is.
	seen := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Microsecond)
	obs := identity.Observation{TenantID: f.tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:deferral-c"}, ObservedAt: seen,
		Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "deferral-c.local"}}, Admission: identity.AdmissionEvidence{ReceiptID: uuid.NewString()}}
	repo := pgrepo.New(f.db.DB.DB)
	observation, err := repo.StoreObservation(ctx, obs, identity.AssessAdmission(obs))
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.LinkObservation(ctx, f.tenant.String(), observation, asset.String(), identity.IdentityEstablished); err != nil {
		t.Fatal(err)
	}
	third := leafCertFinding("deferral-c.example.test", "198.51.100.142", 9443, hexFingerprint("deferral-c-9443"))
	delete(third.RawData, "observed_at")
	payload, err := json.Marshal(third)
	if err != nil {
		t.Fatal(err)
	}
	receipt := identity.ObservationReceiptKey(obs)
	if _, err := f.db.Exec(`INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload) VALUES($1,$2,$3,$4),($1,$2,'host-receipt','{"kind":"host_observation"}')`,
		f.tenant, observation, receipt, string(payload)); err != nil {
		t.Fatal(err)
	}

	adopt := func() int {
		t.Helper()
		var moved int
		if err := database.WithTenantTx(ctx, f.db, f.tenant, func(tx *sqlx.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT public.adopt_legacy_crypto_deferrals($1)`, f.tenant).Scan(&moved)
		}); err != nil {
			t.Fatal(err)
		}
		return moved
	}
	if moved := adopt(); moved != 3 {
		t.Fatalf("moved %d rows, want 3 (two metadata entries and one payload)", moved)
	}
	if moved := adopt(); moved != 0 {
		t.Fatalf("a second run moved %d rows, want 0 — data moves exactly once", moved)
	}

	var hasKey bool
	var kept string
	if err := f.db.QueryRow(`SELECT metadata ? 'deferred_findings', COALESCE(metadata->>'kept','') FROM assets WHERE tenant_id=$1 AND id=$2`,
		f.tenant, asset).Scan(&hasKey, &kept); err != nil {
		t.Fatal(err)
	}
	if hasKey || kept != "yes" {
		t.Fatalf("metadata after the move: key present=%v, other key=%q — want the key stripped and nothing else touched", hasKey, kept)
	}
	if got := deferralRows(t, f); got != (deferralRowState{assetHeld: 2, observationHeld: 1}) {
		t.Fatalf("after the move: %+v, want two asset-gated rows and one observation-gated row", got)
	}
	var ports []int
	rows, err := f.db.Query(`SELECT (finding->>'port')::int FROM deferred_crypto_findings WHERE tenant_id=$1 AND observation_id IS NULL ORDER BY last_seen_at, created_at`, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		ports = append(ports, p)
	}
	_ = rows.Close()
	if len(ports) != 2 || ports[0] != 443 || ports[1] != 8443 {
		t.Fatalf("moved metadata entries in order %v, want [443 8443] (array order)", ports)
	}
	var key, observedAt string
	if err := f.db.QueryRow(`SELECT dedup_key, finding->'raw_data'->>'observed_at' FROM deferred_crypto_findings WHERE tenant_id=$1 AND observation_id=$2`,
		f.tenant, observation).Scan(&key, &observedAt); err != nil {
		t.Fatal(err)
	}
	if key != receipt {
		t.Fatalf("moved payload keyed %q, want its receipt %q", key, receipt)
	}
	if got, err := time.Parse(time.RFC3339Nano, observedAt); err != nil || !got.Equal(seen) {
		t.Fatalf("moved payload observed_at=%q (err %v), want the receipt's time %s", observedAt, err, seen)
	}
	var crypto, host int
	if err := f.db.QueryRow(`SELECT count(*) FILTER (WHERE receipt_key=$3), count(*) FILTER (WHERE receipt_key='host-receipt')
	 FROM identity_observation_payloads WHERE tenant_id=$1 AND observation_id=$2`, f.tenant, observation, receipt).Scan(&crypto, &host); err != nil {
		t.Fatal(err)
	}
	if crypto != 0 || host != 1 {
		t.Fatalf("payload rows left: crypto=%d host_observation=%d, want 0 and 1", crypto, host)
	}

	// The moved rows replay through the ordinary approval.
	if err := f.svc.ApproveAssets(f.tenant, []uuid.UUID{asset}, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if n := deferralCryptoCount(t, f, asset); n != 3 {
		t.Fatalf("%d crypto configurations after approving the migrated asset, want 3", n)
	}
	if got := deferralRows(t, f); got != (deferralRowState{replayed: 3}) {
		t.Fatalf("after approval: %+v, want all three moved rows replayed", got)
	}
}

// deferralBoundSetup creates one asset through a real pending ingest of a
// finding at ip, discards the asset-gated row that ingest held, and leaves the
// asset with the given status and exactly one ip_address identifier (ip). It
// returns the asset.
func deferralBoundSetup(t *testing.T, f leafLinkFixture, host, ip, status string) uuid.UUID {
	t.Helper()
	finding := leafCertFinding(host, ip, 443, hexFingerprint(host))
	if _, err := f.svc.IngestFindingsReport(f.tenant, []IngestFinding{finding}, identity.StatusPendingApproval); err != nil {
		t.Fatal(err)
	}
	var asset uuid.UUID
	if err := f.db.QueryRow(`SELECT id FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, f.tenant).Scan(&asset); err != nil {
		t.Fatalf("setup: want the one asset: %v", err)
	}
	for _, q := range []string{
		`DELETE FROM deferred_crypto_findings WHERE tenant_id=$1`,
		`DELETE FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address'`,
		`UPDATE assets SET primary_address=NULL WHERE tenant_id=$1`,
	} {
		if _, err := f.db.Exec(q, f.tenant); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Exec(`INSERT INTO asset_identifiers(tenant_id,asset_id,kind,value,scope) VALUES($1,$2,'ip_address',$3,'scope-a')`,
		f.tenant, asset, ip); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE assets SET asset_status=$3 WHERE tenant_id=$1 AND id=$2`, f.tenant, asset, status); err != nil {
		t.Fatal(err)
	}
	return asset
}

// deferralHoldObservation inserts an observation bound to asset with the given
// state/outcome and one held finding waiting on it, at findingIP.
func deferralHoldObservation(t *testing.T, f leafLinkFixture, asset uuid.UUID, state, outcome, host, findingIP string, direct bool) {
	t.Helper()
	evidence := `{"admission":{"direct":true}}`
	if !direct {
		evidence = `{"admission":{}}`
	}
	obs := uuid.New()
	var outcomeArg interface{}
	if outcome != "" {
		outcomeArg = outcome
	}
	if _, err := f.db.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,state,asset_id,resolution_outcome,first_seen_at,last_seen_at)
		VALUES($1,$2,$3,'sensor','deferral-test',$7::jsonb,$4,$5,$6,now(),now())`,
		f.tenant, obs, "fp-"+obs.String(), state, asset, outcomeArg, evidence); err != nil {
		t.Fatal(err)
	}
	finding := leafCertFinding(host, findingIP, 8443, hexFingerprint(host+findingIP))
	finding.RawData["observed_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	body, err := json.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO deferred_crypto_findings(tenant_id,observation_id,source_ref,dedup_key,finding)
		VALUES($1,$2,'deferral-test',$3,$4)`, f.tenant, obs, "receipt-"+obs.String(), string(body)); err != nil {
		t.Fatal(err)
	}
}

// A held observation finding is replayed onto a monitoring asset that owns the
// finding's address whether the observation was `supporting` or is still
// `unresolved`, and is not replayed for an address the asset does not own or an
// asset that is not monitoring. Driven through the per-minute sweep.
//
// Mutation log: restoring the pre-change claim (linked AND NOT supporting only)
// → SupportingOwnedAddress and UnresolvedOwnedAddress fail.
func TestIntegration_DeferredCrypto_BoundObservationOwnedAddress(t *testing.T) {
	cases := []struct {
		name, state, outcome, status, findingIP string
		trafficOnly, wantReplayed               bool
	}{
		{"SupportingOwnedAddress", "linked", "supporting", "monitoring", "192.0.2.10", false, true},
		{"SupportingForeignAddress", "linked", "supporting", "monitoring", "192.0.2.99", false, false},
		{"UnresolvedOwnedAddress", "unresolved", "", "monitoring", "192.0.2.10", false, true},
		{"UnresolvedForeignAddress", "unresolved", "", "monitoring", "192.0.2.99", false, false},
		{"PendingAssetOwnedAddress", "linked", "supporting", "pending_approval", "192.0.2.10", false, false},
		{"DismissedOwnedAddress", "dismissed", "", "monitoring", "192.0.2.10", false, false},
		{"SupportingTrafficOnlyOwnedAddress", "linked", "supporting", "monitoring", "192.0.2.10", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newLeafLinkFixture(t)
			asset := deferralBoundSetup(t, f, "bound-"+strings.ToLower(c.name)+".example.test", "192.0.2.10", c.status)
			deferralHoldObservation(t, f, asset, c.state, c.outcome, "bound-"+strings.ToLower(c.name)+".example.test", c.findingIP, !c.trafficOnly)

			n, err := f.svc.replayDueDeferredCrypto(context.Background(), f.tenant)
			if err != nil {
				t.Fatal(err)
			}
			want := deferralRowState{observationHeld: 1}
			wantCrypto := 0
			if c.wantReplayed {
				want = deferralRowState{replayed: 1}
				wantCrypto = 1
			}
			if got := deferralRows(t, f); got != want {
				t.Fatalf("rows after the sweep (replayed %d): %+v, want %+v", n, got, want)
			}
			if got := deferralCryptoCount(t, f, asset); got != wantCrypto {
				t.Fatalf("%d crypto configurations, want %d", got, wantCrypto)
			}
		})
	}
}

// The asset's primary address alone also proves ownership.
func TestIntegration_DeferredCrypto_BoundObservationPrimaryAddress(t *testing.T) {
	f := newLeafLinkFixture(t)
	asset := deferralBoundSetup(t, f, "bound-primary.example.test", "192.0.2.10", "monitoring")
	if _, err := f.db.Exec(`DELETE FROM asset_identifiers WHERE tenant_id=$1 AND kind='ip_address'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE assets SET primary_address='192.0.2.20' WHERE tenant_id=$1 AND id=$2`, f.tenant, asset); err != nil {
		t.Fatal(err)
	}
	deferralHoldObservation(t, f, asset, "linked", "supporting", "bound-primary.example.test", "192.0.2.20", true)
	if _, err := f.svc.replayDueDeferredCrypto(context.Background(), f.tenant); err != nil {
		t.Fatal(err)
	}
	if got := deferralRows(t, f); got != (deferralRowState{replayed: 1}) {
		t.Fatalf("rows: %+v, want the row replayed", got)
	}
}
