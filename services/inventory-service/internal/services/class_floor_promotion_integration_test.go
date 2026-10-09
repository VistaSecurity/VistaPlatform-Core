package services

// Floor promotion on the passive path and the floor sweep, end to end, against
// a real Postgres.
//
// What these pin is the WIRING: that the host-observation ingest offers the
// classifier's answer to classproposal.Promote for an asset the engine MATCHED,
// over the evidence the asset has ACCUMULATED rather than the one frame in
// hand; and that the sweep does the same for assets nothing observes any more.
// Promote's own guards are unit-tested in shared/identity/classproposal; the
// guards are re-driven here through the real ingest so deleting the call that
// reaches them fails something.
//
// Mutation-tested (see the PR): deleting the Promote call in
// classOutcomeForResolution turns the two promotion tests red; making
// accumulatedClassEvidence return the observation's evidence alone turns both
// union tests red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// assetClassRow is the class columns of one asset, read by hostname.
type assetClassRow struct {
	id               uuid.UUID
	class, kind, ref string
}

func floorAssetByHost(t *testing.T, db *database.DB, tenant uuid.UUID, hostname string) assetClassRow {
	t.Helper()
	var r assetClassRow
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT id, class_key, class_source_kind, COALESCE(class_source_ref, '')
			FROM assets WHERE tenant_id = $1 AND hostname = $2 AND deleted_at IS NULL`, tenant, hostname).
			Scan(&r.id, &r.class, &r.kind, &r.ref)
	})
	if err != nil {
		t.Fatalf("read asset %q: %v", hostname, err)
	}
	return r
}

// classifierHistory is the asset_class_history rows a MACHINE wrote for the
// asset — the ones a promotion writes. The creation row is `source =
// classifier` too but has no from_class_key, so it is excluded.
func classifierHistory(t *testing.T, db *database.DB, tenant, assetID uuid.UUID) []struct{ from, to, ref string } {
	t.Helper()
	var out []struct{ from, to, ref string }
	err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.Query(`SELECT from_class_key, to_class_key, COALESCE(evidence->>'class_source_ref', '')
			FROM asset_class_history
			WHERE tenant_id = $1 AND asset_id = $2 AND source = 'classifier' AND from_class_key IS NOT NULL
			ORDER BY created_at`, tenant, assetID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r struct{ from, to, ref string }
			if err := rows.Scan(&r.from, &r.to, &r.ref); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("read class history: %v", err)
	}
	return out
}

// freshClassifyingService is a second AssetService over the same database. Its
// rule engine loads lazily on first use, so it sees a rule a test inserted
// AFTER the fixture's service had already loaded the table — the catalogue
// change these tests stand on, without waiting for the refresher.
func freshClassifyingService(db *database.DB) *AssetService {
	algorithms := NewAlgorithmService(db)
	svc := &AssetService{db: db, algorithmService: algorithms, networkSegmentService: NewNetworkSegmentService(db, nil)}
	svc.SetExternalConnectionsService(NewExternalConnectionsService(db, algorithms))
	return svc
}

// insertTestRule adds a curated classification rule for the life of the test.
func insertTestRule(t *testing.T, db *database.DB, kind, pattern, class string, confidence float64) {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`INSERT INTO classification_rules (rule_kind, pattern, class_key, confidence)
		VALUES ($1, $2, $3, $4) RETURNING id`, kind, pattern, class, confidence).Scan(&id); err != nil {
		t.Fatalf("insert test rule %s %s: %v", kind, pattern, err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM classification_rules WHERE id = $1`, id) })
}

// --- (a) the passive path promotes a matched floor asset ----------------------

// Born `unknown_host` from an observation with no MAC — an mDNS answer that
// carried only a name and an address — then seen again in an ARP frame that
// carries a Cisco MAC. The engine MATCHES the second observation to the asset;
// the rules' `network_device` is promoted onto it, without Approvals.
func TestIntegration_FloorPromotion_PassiveMatchPromotesARuleClass(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	const host = "floor-a-switch"
	mac := "00:00:0c:a0:00:01"
	if ouiregistry.VendorForMAC(mac) != "Cisco Systems" {
		t.Fatalf("precondition: %s must be Cisco's in the registry", mac)
	}

	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, Addresses: addrsFor(t, "192.0.2.101"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	before := floorAssetByHost(t, db, tenant, host)
	if before.class != "unknown_host" {
		t.Fatalf("precondition: born %q, want unknown_host — the first observation carries nothing a rule reads", before.class)
	}

	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(t, "192.0.2.101"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-time.Minute),
	})

	after := floorAssetByHost(t, db, tenant, host)
	if after.id != before.id {
		t.Fatalf("the second observation resolved to another asset (%s, was %s); the fixture no longer exercises a MATCH", after.id, before.id)
	}
	if after.class != "network_device" {
		t.Errorf("class_key = %q, want network_device — a matched floor asset with a rule's answer must be promoted", after.class)
	}
	if after.kind != string(identity.ClassSourceRule) || !strings.HasPrefix(after.ref, "rule:") {
		t.Errorf("class provenance = %q/%q, want rule / rule:<…>", after.kind, after.ref)
	}
	hist := classifierHistory(t, db, tenant, after.id)
	if len(hist) != 1 || hist[0].from != "unknown_host" || hist[0].to != "network_device" || !strings.HasPrefix(hist[0].ref, "rule:") {
		t.Errorf("classifier class-history rows = %+v; want exactly one unknown_host -> network_device citing the rule", hist)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d class proposals; a promotion off the floor is not a question for Approvals", n)
	}
}

// --- (b) the union is what decides -------------------------------------------

// The stored mDNS services. The asset advertised a service in its first
// frame, when no rule covered it; the catalogue then gained a rule for it; the
// next frame carries the MAC and nothing else. Only the UNION of the stored
// net.mdns_services with the observation reaches the rule.
func TestIntegration_FloorPromotion_StoredServicesJoinTheObservation(t *testing.T) {
	_, db, tenant := newHostObsFixture(t)
	const host = "floor-b-printer"
	const service = "_vistafloortest-b._tcp"
	mac := "00:1b:21:b0:00:01" // Intel: a vendor-only registry answer, no class
	first := freshClassifyingService(db)
	ingestObservation(t, first, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: mac, Addresses: addrsFor(t, "192.0.2.102"),
		Hostnames: []string{host}, Services: []string{service},
		ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	if got := floorAssetByHost(t, db, tenant, host); got.class != "unknown_host" {
		t.Fatalf("precondition: born %q, want unknown_host", got.class)
	}

	insertTestRule(t, db, classify.KindMDNSService, service, "printer", 0.80)
	svc := freshClassifyingService(db)

	second := &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(t, "192.0.2.102"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-time.Minute),
	}
	// The other polarity, asserted rather than assumed: this observation ALONE
	// decides nothing, so a promotion below can only have come from the union.
	alone := *second
	resolveHostObservationVendor(&alone)
	if p := svc.classifyEvidence(context.Background(), hostObservationClassEvidence(&alone)); p.Class != "" {
		t.Fatalf("precondition: the second observation alone classifies as %q; the test no longer isolates the union", p.Class)
	}

	ingestObservation(t, svc, tenant, second)
	got := floorAssetByHost(t, db, tenant, host)
	if got.class != "printer" || got.kind != string(identity.ClassSourceRule) {
		t.Errorf("class = %q/%q, want printer/rule from the stored %s advertisement", got.class, got.kind, service)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d class proposals, want 0", n)
	}
}

// The stored MAC. The asset's MAC arrived in an earlier frame; the catalogue
// then gained a rule for its prefix; the next frame is an mDNS answer with no
// MAC at all. Only the stored mac_address identifier reaches the rule.
func TestIntegration_FloorPromotion_StoredMACJoinsTheObservation(t *testing.T) {
	_, db, tenant := newHostObsFixture(t)
	const host = "floor-b-mac"
	mac := "00:1b:21:b0:00:02" // Intel: vendor-only, so the asset is born on the floor
	ingestObservation(t, freshClassifyingService(db), tenant, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: mac, Addresses: addrsFor(t, "192.0.2.103"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	if got := floorAssetByHost(t, db, tenant, host); got.class != "unknown_host" {
		t.Fatalf("precondition: born %q, want unknown_host", got.class)
	}

	insertTestRule(t, db, classify.KindOUI, "001B21", "printer", 0.80)
	svc := freshClassifyingService(db)
	second := &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, Addresses: addrsFor(t, "192.0.2.103"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-time.Minute),
	}
	if p := svc.classifyEvidence(context.Background(), hostObservationClassEvidence(second)); p.Class != "" {
		t.Fatalf("precondition: the MAC-less observation alone classifies as %q", p.Class)
	}
	ingestObservation(t, svc, tenant, second)
	if got := floorAssetByHost(t, db, tenant, host); got.class != "printer" {
		t.Errorf("class = %q, want printer from the stored MAC's prefix rule", got.class)
	}
}

// --- (c) a declared class is untouched ---------------------------------------

// A person declared that they do not know what this is. That is an answer,
// and a rule does not overrule it — not by promotion and not by proposal.
func TestIntegration_FloorPromotion_ADeclaredFloorIsNeverPromoted(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	const host = "floor-c-declared"
	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: macUnassigned, Addresses: addrsFor(t, "192.0.2.104"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	execTenant(t, db, tenant, `UPDATE assets SET class_source_kind = 'declared', class_source_ref = 'user:someone'
		WHERE tenant_id = $1 AND hostname = '`+host+`'`)

	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: macUnassigned, Addresses: addrsFor(t, "192.0.2.104"),
		Hostnames: []string{host}, Services: []string{"_ipp._tcp"}, ObservedAt: time.Now().UTC().Add(-time.Minute),
	})
	got := floorAssetByHost(t, db, tenant, host)
	if got.class != "unknown_host" || got.kind != "declared" {
		t.Errorf("the declared class moved to %q/%q", got.class, got.kind)
	}
	if h := classifierHistory(t, db, tenant, got.id); len(h) != 0 {
		t.Errorf("classifier history on a declared asset: %+v", h)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d class proposals against a declared class, want 0", n)
	}
}

// --- (d) a rejected class is not re-applied ----------------------------------

// A reviewer said "not a printer" for this asset. The next observation's
// `_ipp._tcp` argues printer again; the asset stays on the floor.
func TestIntegration_FloorPromotion_ARejectedClassIsNotPromoted(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	const host = "floor-d-rejected"
	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: macUnassigned, Addresses: addrsFor(t, "192.0.2.105"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	asset := floorAssetByHost(t, db, tenant, host)

	// A printer proposal through the real writer, rejected through the real
	// decision path — so the `class_rejected` row is the one production stores.
	prop := classify.ClassProposal{Class: "printer", Confidence: 0.75,
		MatchedRules: []classify.RuleRef{{Kind: classify.KindMDNSService, Pattern: "_ipp._tcp", Class: "printer", Confidence: 0.75}}}
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		return classproposal.Record(context.Background(), tx, tenant, asset.id, identity.OutcomeMatched, prop)
	}); err != nil {
		t.Fatalf("seed the proposal: %v", err)
	}
	proposals := listClassProposals(t, db, tenant)
	if len(proposals) != 1 {
		t.Fatalf("seeded %d proposals, want 1", len(proposals))
	}
	if _, err := NewClassProposalService(db).Decide(context.Background(), tenant, proposals[0].ID,
		seedClassReviewer(t, db, tenant), false, ""); err != nil {
		t.Fatalf("reject: %v", err)
	}

	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceMDNS, MAC: macUnassigned, Addresses: addrsFor(t, "192.0.2.105"),
		Hostnames: []string{host}, Services: []string{"_ipp._tcp"}, ObservedAt: time.Now().UTC().Add(-time.Minute),
	})
	if got := floorAssetByHost(t, db, tenant, host); got.class != "unknown_host" {
		t.Errorf("class = %q; a class the reviewer rejected for this asset was applied anyway", got.class)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d pending proposals after the rejection, want 0", n)
	}
}

// (e) — a model's answer is proposed, never promoted — is
// TestIntegration_ClassifierModel_NeverSetsAClassOnAnExistingAsset: a MATCHED
// floor asset on the discovery-finding path, which now runs Promote before
// Record, and which asserts the class stays `unknown_host` with the model's
// proposal in Approvals.

// --- (f) the floor sweep -----------------------------------------------------

// The sweep promotes a pre-existing floor asset whose stored MAC a rule now
// classifies, leaves the others alone, raises no proposal — not even for the
// asset the rules argue about — and a second pass promotes nothing.
func TestIntegration_ClassFloorSweep_PromotesWhatTheRulesNowDecide(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ctx := context.Background()

	ingest := func(host, mac, addr string, services ...string) uuid.UUID {
		ingestObservation(t, svc, tenant, &hostobs.HostObservation{
			Source: hostobs.SourceMDNS, MAC: mac, Addresses: addrsFor(t, addr),
			Hostnames: []string{host}, Services: services, ObservedAt: time.Now().UTC().Add(-time.Minute),
		})
		return floorAssetByHost(t, db, tenant, host).id
	}
	// Back onto the floor, as an asset ingested before the rules could
	// classify it was left — and with no class history for the move, as such
	// an asset has none.
	toFloor := func(host string) {
		execTenant(t, db, tenant, fmt.Sprintf(`UPDATE assets SET class_key = 'unknown_host', class_path = '%s',
			class_source_kind = 'measured', class_source_ref = NULL, class_confidence = NULL
			WHERE tenant_id = $1 AND hostname = '%s'`, classPathForKey("unknown_host"), host))
	}

	classifiable := ingest("sweep-cisco", "00:00:0c:f0:00:01", "192.0.2.111")
	toFloor("sweep-cisco")
	unknowable := ingest("sweep-unknown", macUnassigned, "192.0.2.112")
	declared := ingest("sweep-declared", "00:00:0c:f0:00:02", "192.0.2.113")
	execTenant(t, db, tenant, fmt.Sprintf(`UPDATE assets SET class_key = 'unknown_host', class_path = '%s',
		class_source_kind = 'declared', class_source_ref = 'user:someone'
		WHERE tenant_id = $1 AND hostname = 'sweep-declared'`, classPathForKey("unknown_host")))
	// Cisco's network_device (0.70) against _ipp._tcp's printer (0.75): a
	// conflict, created on the floor with its proposal already in the queue.
	argued := ingest("sweep-argued", "00:00:0c:f0:00:03", "192.0.2.114", "_ipp._tcp")
	proposalsBefore := countClassProposals(t, db, tenant)

	res, err := svc.SweepClassFloor(ctx, tenant)
	if err != nil {
		t.Fatalf("SweepClassFloor: %v", err)
	}
	if res.Promoted != 1 || res.Conflicts != 1 || res.Considered != 3 {
		t.Errorf("first pass = %+v; want considered 3 (not the declared one), promoted 1, conflicts 1", res)
	}
	if got := floorAssetByHost(t, db, tenant, "sweep-cisco"); got.class != "network_device" || got.kind != "rule" {
		t.Errorf("the classifiable floor asset is %q/%q, want network_device/rule", got.class, got.kind)
	} else if h := classifierHistory(t, db, tenant, classifiable); len(h) != 1 || h[0].to != "network_device" {
		t.Errorf("classifier history = %+v, want one move to network_device", h)
	}
	for host, id := range map[string]uuid.UUID{"sweep-unknown": unknowable, "sweep-declared": declared, "sweep-argued": argued} {
		if got := floorAssetByHost(t, db, tenant, host); got.class != "unknown_host" {
			t.Errorf("%s moved to %q; the sweep promotes only a rule's decided answer", host, got.class)
		}
		if h := classifierHistory(t, db, tenant, id); len(h) != 0 {
			t.Errorf("%s has classifier history %+v", host, h)
		}
	}
	if n := countClassProposals(t, db, tenant); n != proposalsBefore {
		t.Errorf("pending proposals %d -> %d across the sweep; the sweep must never write to Approvals", proposalsBefore, n)
	}

	var considered, promoted, conflicts int
	if err := db.QueryRow(`SELECT assets_considered, assets_promoted, conflicts FROM class_floor_sweep_state WHERE tenant_id = $1`,
		tenant).Scan(&considered, &promoted, &conflicts); err != nil {
		t.Fatalf("no sweep state recorded: %v", err)
	}
	if considered != 3 || promoted != 1 || conflicts != 1 {
		t.Errorf("recorded state = %d/%d/%d, want 3/1/1", considered, promoted, conflicts)
	}

	again, err := svc.SweepClassFloor(ctx, tenant)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again.Promoted != 0 || again.Considered != 2 {
		t.Errorf("second pass = %+v; want considered 2, promoted 0", again)
	}

	tenants, err := ClassFloorSweepTenants(ctx, db.DB.DB)
	if err != nil {
		t.Fatal(err)
	}
	if !containsUUID(tenants, tenant) {
		t.Errorf("ClassFloorSweepTenants does not list live tenant %s", tenant)
	}
}

// The sweep is per tenant under RLS: another tenant's pass neither sees nor
// moves this tenant's floor.
func TestIntegration_ClassFloorSweep_IsTenantScoped(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: "00:00:0c:f1:00:01", Addresses: addrsFor(t, "192.0.2.121"),
		Hostnames: []string{"sweep-mine"}, ObservedAt: time.Now().UTC().Add(-time.Minute),
	})
	execTenant(t, db, tenant, fmt.Sprintf(`UPDATE assets SET class_key = 'unknown_host', class_path = '%s',
		class_source_kind = 'measured' WHERE tenant_id = $1`, classPathForKey("unknown_host")))

	other := testdb.NewTenant(t, testdb.Connect(t))
	res, err := svc.SweepClassFloor(context.Background(), other)
	if err != nil {
		t.Fatalf("SweepClassFloor(other): %v", err)
	}
	if res.Considered != 0 {
		t.Errorf("the other tenant's pass considered %d asset(s); RLS must scope the sweep", res.Considered)
	}
	if got := floorAssetByHost(t, db, tenant, "sweep-mine"); got.class != "unknown_host" {
		t.Errorf("another tenant's sweep moved this tenant's asset to %q", got.class)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM class_floor_sweep_state WHERE tenant_id = $1`, tenant).Scan(&n); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the other tenant's pass wrote this tenant's sweep state")
	}
}
