package producers

// The `hygiene` producer end to end, against a real Postgres under RLS.
//
// hygiene_test.go covers the ladder and the class set. What only a database can
// show is the rest: that each kind fires on the condition it names and stops
// when the condition is fixed, that a `relationship` subject can be written at
// all, that an archived asset stops being judged, and — the reachability half —
// that the Inventory Hygiene framework's two counting controls turn from NOT
// ASSESSED into a real number once this producer has run.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/riskrollup"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer/producertest"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// hygieneFixture is one tenant with a deliberately untidy inventory.
type hygieneFixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID

	// tidy has an owner, a real class, a location, and was seen this morning.
	tidy uuid.UUID
	// untidy has none of those and has not been seen for 100 days.
	untidy uuid.UUID
	// archived is out of scope entirely.
	archived uuid.UUID
	// staleEP and staleInstall hang off `tidy`, so the child stale findings are
	// not confused with the parent's.
	staleEP      uuid.UUID
	staleInstall uuid.UUID
	// orphanEdge points from `tidy` at `archived`.
	orphanEdge uuid.UUID
	liveEdge   uuid.UUID

	producer *HygieneProducer
}

func newHygieneFixture(t *testing.T) *hygieneFixture {
	t.Helper()
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	f := &hygieneFixture{owner: owner, app: app, tenant: tenant}

	f.tidy = uuid.New()
	exec(t, owner, `INSERT INTO assets
	    (id, tenant_id, hostname, display_name, class_key, class_path, asset_status,
	     owner_email, site, last_seen_at)
	    VALUES ($1, $2, 'tidy-1', 'tidy-1', 'server', 'hardware.computer.server', 'monitoring',
	            'ops@example.com', 'DC1', now())`, f.tidy, tenant)

	f.untidy = uuid.New()
	exec(t, owner, `INSERT INTO assets
	    (id, tenant_id, hostname, display_name, class_key, class_path, asset_status, last_seen_at)
	    VALUES ($1, $2, 'untidy-1', 'untidy-1', 'unknown_host', 'unknown_host', 'monitoring', $3)`,
		f.untidy, tenant, daysFromNow(-100))

	f.archived = uuid.New()
	exec(t, owner, `INSERT INTO assets
	    (id, tenant_id, hostname, display_name, class_key, class_path, asset_status, last_seen_at)
	    VALUES ($1, $2, 'gone-1', 'gone-1', 'server', 'hardware.computer.server', 'archived', $3)`,
		f.archived, tenant, daysFromNow(-400))

	// A socket and a package on the tidy host, both long unseen.
	f.staleEP = endpoint(t, owner, tenant, f.tidy, "198.51.100.20", 443, "tcp", "nginx", "banner", nil)
	exec(t, owner, `UPDATE asset_endpoints SET last_seen_at = $1 WHERE id = $2 AND tenant_id = $3`,
		daysFromNow(-200), f.staleEP, tenant)

	productID := uuid.New()
	exec(t, owner, `INSERT INTO software_products (id, tenant_id, name, vendor, version)
	                VALUES ($1, $2, 'openssl', 'OpenSSL', '1.1.1')`, productID, tenant)
	f.staleInstall = uuid.New()
	exec(t, owner, `INSERT INTO software_installs (id, tenant_id, asset_id, product_id, status, last_seen_at)
	                VALUES ($1, $2, $3, $4, 'active', $5)`,
		f.staleInstall, tenant, f.tidy, productID, daysFromNow(-95))

	// One edge into the archived asset, one between two live ones.
	f.orphanEdge = uuid.New()
	exec(t, owner, `INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type, status)
	                VALUES ($1, $2, $3, $4, 'connects_to', 'active')`,
		f.orphanEdge, tenant, f.tidy, f.archived)
	f.liveEdge = uuid.New()
	exec(t, owner, `INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type, status)
	                VALUES ($1, $2, $3, $4, 'connects_to', 'active')`,
		f.liveEdge, tenant, f.tidy, f.untidy)

	p, err := NewHygieneProducer(app)
	if err != nil {
		t.Fatalf("NewHygieneProducer: %v", err)
	}
	f.producer = p
	return f
}

// run is one pass, taken under the schema share lock and retried past the
// cross-binary races the shared test database produces. Both halves matter —
// see driftFixture.run for why the retry alone is not enough — and
// TestIntegration_Producers_PassHelpersTakeTheSchemaShareLock holds every
// helper in this package to the lock.
//
// Used wherever a pass is EXPECTED to succeed. The cases that expect an error
// call Run directly, because a retry there would hide the thing under test.
func (f *hygieneFixture) run(t *testing.T, ctx context.Context) HygieneRun {
	t.Helper()
	var out HygieneRun
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			var err error
			out, err = f.producer.Run(ctx, f.tenant)
			return err
		})
	})
	return out
}

// recomputeRisk runs the generic post-pass rollup the finding-producer job
// runs, under the same guard as a pass. The rollup is one statement over six
// tables, which is exactly the shape that deadlocks against a concurrent
// schema apply — that is how this file's InventoryHygieneControlsBecomeAssessed
// failed whenever this package and internal/services ran together.
func (f *hygieneFixture) recomputeRisk(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			return pgidentity.New(f.app).RunInTx(ctx, f.tenant.String(), func(r *pgidentity.Repository) error {
				_, err := riskrollup.Recompute(ctx, r.Tx(), f.tenant, uuid.Nil)
				return err
			})
		})
	})
}

func TestIntegration_HygieneProducer_WriterContract(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)

	// `stale` is the LADDER kind, so the suite exercises the registry-rung half
	// of validation with this producer's real numbers; `no_owner` is the second
	// kind that proves Sweep is scoped by kind and not only by producer.
	producertest.Run(t, producertest.Config{
		DB:          app,
		Owner:       owner,
		Producer:    findings.ProducerHygiene,
		Kind:        findings.KindStale,
		OtherKind:   findings.KindNoOwner,
		SubjectType: findings.SubjectAsset,
	})
}

func TestIntegration_HygieneProducer_RaisesEachKind(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	f.run(t, ctx)

	// --- the untidy asset carries the three record-quality kinds.
	for _, kind := range []string{findings.KindNoOwner, findings.KindNoClass, findings.KindNoLocation} {
		got := f.finding(t, kind, findings.SubjectAsset, f.untidy)
		if got == nil {
			t.Errorf("no %s finding on the untidy asset", kind)
			continue
		}
		if got.score != 0 {
			t.Errorf("%s scores %d; hygiene feeds no risk and must write 0", kind, got.score)
		}
		// The tidy asset must carry none of them. A hygiene producer that
		// raised on everything would be a producer nobody could act on.
		if other := f.finding(t, kind, findings.SubjectAsset, f.tidy); other != nil {
			t.Errorf("%s was raised on the tidy asset, which has an owner, a class and a site", kind)
		}
	}

	// --- the stale ladder, on all three subject types.
	for _, tc := range []struct {
		name        string
		subjectType string
		id          uuid.UUID
		wantRung    int
	}{
		{"asset, 100 days", findings.SubjectAsset, f.untidy, 1},
		{"endpoint, 200 days", findings.SubjectEndpoint, f.staleEP, 2},
		{"software install, 95 days", findings.SubjectSoftwareInstall, f.staleInstall, 1},
	} {
		got := f.finding(t, findings.KindStale, tc.subjectType, tc.id)
		if got == nil {
			t.Errorf("%s: no stale finding", tc.name)
			continue
		}
		k, _ := findings.Get(findings.ProducerHygiene, findings.KindStale)
		if got.severity != k.Rungs[tc.wantRung].Severity {
			t.Errorf("%s: severity %q, want the registry's rung %d (%q)",
				tc.name, got.severity, tc.wantRung, k.Rungs[tc.wantRung].Severity)
		}
	}
	if fresh := f.finding(t, findings.KindStale, findings.SubjectAsset, f.tidy); fresh != nil {
		t.Error("the asset seen this morning was reported stale")
	}

	// --- the child findings name their host, so the drawer has somewhere to go.
	ep := f.finding(t, findings.KindStale, findings.SubjectEndpoint, f.staleEP)
	if got := ep.evidence["asset_id"]; got != f.tidy.String() {
		t.Errorf("the endpoint's stale finding does not name its host: %v", got)
	}

	// --- the orphan edge, on a `relationship` subject.
	edge := f.finding(t, findings.KindOrphanRelationship, findings.SubjectRelationship, f.orphanEdge)
	if edge == nil {
		t.Fatal("no orphan_relationship finding for the edge pointing at the archived asset")
	}
	if got := edge.evidence["missing_asset_id"]; got != f.archived.String() {
		t.Errorf("evidence.missing_asset_id = %v, want the archived asset", got)
	}
	if got := edge.evidence["missing_reason"]; got != "archived" {
		t.Errorf("evidence.missing_reason = %v, want archived", got)
	}
	if got := edge.evidence["asset_id"]; got != f.tidy.String() {
		t.Errorf("evidence.asset_id = %v, want the SURVIVING asset — it is where the Findings drawer links to", got)
	}
	if live := f.finding(t, findings.KindOrphanRelationship, findings.SubjectRelationship, f.liveEdge); live != nil {
		t.Error("an edge between two live assets was reported as an orphan")
	}

	// --- the archived asset is judged for nothing at all.
	for _, kind := range hygieneKinds {
		if kind == findings.KindOrphanRelationship {
			continue
		}
		if got := f.finding(t, kind, findings.SubjectAsset, f.archived); got != nil {
			t.Errorf("%s was raised on an ARCHIVED asset; the tenant took it out of the queue", kind)
		}
	}

	// --- converged re-run.
	run2 := f.run(t, ctx)
	if run2.Resolved != 0 {
		t.Errorf("a converged re-run resolved %d findings; nothing changed", run2.Resolved)
	}
}

func TestIntegration_HygieneProducer_FixingTheRecordResolvesTheFinding(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	before := f.finding(t, findings.KindNoOwner, findings.SubjectAsset, f.untidy)
	if before == nil || before.state != producer.StateActive {
		t.Fatal("no active no_owner finding to start from")
	}

	// Somebody fills in the record: an owner, a class, a site, and a collector
	// sees the host again.
	exec(t, f.owner, `UPDATE assets
	    SET support_group = 'Platform', class_key = 'server', class_path = 'hardware.computer.server',
	        region = 'eu-west-1', last_seen_at = now()
	    WHERE id = $1 AND tenant_id = $2`, f.untidy, f.tenant)

	run := f.run(t, ctx)
	if run.Resolved < 4 {
		t.Errorf("run 2 resolved %d findings, want at least 4 (owner, class, location, stale)", run.Resolved)
	}
	for _, kind := range []string{findings.KindNoOwner, findings.KindNoClass, findings.KindNoLocation, findings.KindStale} {
		got := f.finding(t, kind, findings.SubjectAsset, f.untidy)
		if got == nil {
			t.Errorf("%s vanished; a fixed condition goes INACTIVE, the row is not deleted", kind)
			continue
		}
		if got.state != producer.StateInactive {
			t.Errorf("%s is %q after the record was fixed, want INACTIVE", kind, got.state)
		}
	}
	if got := f.finding(t, findings.KindNoOwner, findings.SubjectAsset, f.untidy); got.id != before.id {
		t.Error("the resolved finding is a different row; a condition that went away keeps its row")
	}
}

// A PENDING merge proposal puts BOTH halves of the pair in question, and
// deciding it resolves both findings.
func TestIntegration_HygieneProducer_DuplicateSuspectedFollowsTheProposal(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	proposalID := openMergeProposal(t, f.owner, f.tenant, f.untidy, []uuid.UUID{f.tidy})

	f.run(t, ctx)
	for _, id := range []uuid.UUID{f.untidy, f.tidy} {
		got := f.finding(t, findings.KindDuplicateSuspected, findings.SubjectAsset, id)
		if got == nil {
			t.Fatalf("no duplicate_suspected finding on asset %s; a suspected duplicate is a statement about a PAIR and both records have to show it", id)
		}
		if got.evidence["proposal_id"] != proposalID.String() {
			t.Errorf("evidence.proposal_id = %v, want %s", got.evidence["proposal_id"], proposalID)
		}
		if !strings.Contains(got.summary, "may be a duplicate of") {
			t.Errorf("summary %q does not read as the registry's title_template", got.summary)
		}
	}

	// A human decides it in Approvals: the row stays, its status moves.
	exec(t, f.owner, `UPDATE asset_history
	    SET changes_json = jsonb_set(changes_json, '{status}', '"kept_separate"')
	    WHERE id = $1 AND tenant_id = $2`, proposalID, f.tenant)

	run := f.run(t, ctx)
	if run.Resolved < 2 {
		t.Errorf("run 2 resolved %d findings, want at least 2 — deciding the proposal answers the question on both records", run.Resolved)
	}
	for _, id := range []uuid.UUID{f.untidy, f.tidy} {
		got := f.finding(t, findings.KindDuplicateSuspected, findings.SubjectAsset, id)
		if got == nil || got.state != producer.StateInactive {
			t.Errorf("duplicate_suspected on %s is %v after the proposal was decided, want INACTIVE", id, got)
		}
	}
}

// The ONE split in which assets get which kinds, pinned in both directions.
//
// The record-quality kinds and `stale` fire on `monitoring` assets only — what
// the Inventory Hygiene framework's four asset-shape measurements already scope
// themselves to, and the reason a tenant with a thousand unapproved discoveries
// does not wake up to three thousand hygiene findings about records nobody has
// accepted. `duplicate_suspected` is the exception, because the newly-seen half
// of a contested pair is by construction still `pending_approval` and is
// precisely the record in question.
//
// Neither half was pinned by anything: deleting the status check left every
// test green, and so did gating the duplicate kind on it.
func TestIntegration_HygieneProducer_TheApprovalQueueIsNotJudgedButItsDuplicatesAre(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	// A brand-new discovery: no owner, no class, no location, and last seen
	// long enough ago to be on the worst stale rung. Nothing about it has been
	// accepted into the estate yet.
	pending := uuid.New()
	exec(t, f.owner, `INSERT INTO assets
	    (id, tenant_id, hostname, display_name, class_key, class_path, asset_status, last_seen_at)
	    VALUES ($1, $2, 'new-obs-1', 'new-obs-1', 'unknown_host', 'unknown_host', 'pending_approval', $3)`,
		pending, f.tenant, daysFromNow(-400))

	f.run(t, ctx)
	for _, kind := range []string{
		findings.KindNoOwner, findings.KindNoClass, findings.KindNoLocation, findings.KindStale,
	} {
		if got := f.finding(t, kind, findings.SubjectAsset, pending); got != nil {
			t.Errorf("%s was raised on a record still waiting in Approvals; asking for the owner of "+
				"something nobody has accepted puts work in a queue the tenant has not opened yet", kind)
		}
	}

	// The same record, now named in a merge proposal. THIS one it must carry —
	// on both halves, and the pending half is the one actually in question.
	openMergeProposal(t, f.owner, f.tenant, pending, []uuid.UUID{f.tidy})
	f.run(t, ctx)
	if got := f.finding(t, findings.KindDuplicateSuspected, findings.SubjectAsset, pending); got == nil {
		t.Error("no duplicate_suspected finding on the pending_approval half of the pair — that is the " +
			"record the proposal is about, and restricting this kind to monitoring assets would raise it " +
			"only on the long-standing half")
	}
	if got := f.finding(t, findings.KindDuplicateSuspected, findings.SubjectAsset, f.tidy); got == nil {
		t.Error("no duplicate_suspected finding on the monitoring half of the pair")
	}
	// And the split still holds after the proposal: the pending record gets the
	// duplicate kind and none of the others.
	if got := f.finding(t, findings.KindNoOwner, findings.SubjectAsset, pending); got != nil {
		t.Error("no_owner appeared on the pending record once it was named in a proposal")
	}
}

// A relationship somebody REJECTED is a decision, not a dangling pointer.
//
// `readOrphanEdges` excludes them and says so; nothing pinned it, so the
// exclusion could have been dropped and the only symptom would be findings
// raised against edges a user already said no to.
func TestIntegration_HygieneProducer_RejectedEdgesAreNotOrphans(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	// Same shape as the fixture's orphan edge — into the archived asset — but
	// rejected. The only difference between the two rows is the status.
	rejected := uuid.New()
	exec(t, f.owner, `INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type, status)
	                  VALUES ($1, $2, $3, $4, 'connects_to', 'rejected')`,
		rejected, f.tenant, f.untidy, f.archived)

	f.run(t, ctx)
	if got := f.finding(t, findings.KindOrphanRelationship, findings.SubjectRelationship, rejected); got != nil {
		t.Error("a REJECTED relationship was reported as an orphan; somebody looked at that edge and said no, " +
			"and re-raising it puts a decided question back in the queue")
	}
	// The control: the identical edge that was never rejected IS an orphan, so
	// this test cannot pass by the producer having stopped reading edges at all.
	if got := f.finding(t, findings.KindOrphanRelationship, findings.SubjectRelationship, f.orphanEdge); got == nil {
		t.Fatal("the fixture's active orphan edge raised nothing")
	}
}

// A pass whose read FAILED must not sweep. Mutation-proven the same way as the
// configuration producer's: swallow the read error and every finding in the
// fixture goes INACTIVE.
func TestIntegration_HygieneProducer_AFailedPassDoesNotSweep(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	before := activeFindingsFor(t, f.owner, f.tenant, findings.ProducerHygiene)
	if len(before) == 0 {
		t.Fatal("the first pass raised nothing")
	}

	failing := &HygieneProducer{
		repo:   pgidentity.New(failingHandle(t)),
		writer: f.producer.writer,
		now:    time.Now,
	}
	// The THIRD query of the read: assets and endpoints are loaded, the
	// software installs never arrive — and the relationships and proposals
	// after them never even run. A partial answer.
	armQueryFailure(t, 3)
	_, err := failing.Run(ctx, f.tenant)
	if err == nil {
		t.Fatal("a pass whose read failed reported success")
	}
	if !errors.Is(err, errInjectedReadFailure) {
		t.Errorf("the error does not name what went wrong: %v", err)
	}
	if after := activeFindingsFor(t, f.owner, f.tenant, findings.ProducerHygiene); len(after) != len(before) {
		t.Fatalf("the failed pass changed the ACTIVE finding count from %d to %d", len(before), len(after))
	}
}

// The reachability half of the workstream: the Inventory Hygiene framework's
// two COUNTING controls (IH-005 suspected duplicates, IH-006 orphan
// relationships) must turn from NOT ASSESSED into a real number once this
// producer has run.
//
// Two claims, and the test keeps them apart because the product does:
//
//  1. The pass records coverage in `producer_assessments` — the FULL record of
//     who has looked, which the compliance `finding` shape gates on — and the
//     controls become answerable. Three-valued in both directions: before the
//     pass the measurement yields NO ROW; after it, a number, including an
//     honest ZERO for the asset with no orphan edges.
//  2. It does NOT reach `assets.risk_assessed_by`. That array is the
//     RISK-feeding subset the rollup derives, and the inventory UI reads a
//     non-empty one as "the risk score is a real answer"; every hygiene kind is
//     feeds_risk false, so an asset only this producer has visited must still
//     read NOT ASSESSED for risk.
//
// The statements are read from the compliance-engine's shipped SQL golden
// rather than written out here. A copy would be a second spelling of the query
// under test, and the whole failure mode this guards against is the two
// disagreeing.
func TestIntegration_HygieneProducer_InventoryHygieneControlsBecomeAssessed(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	openMergeProposal(t, f.owner, f.tenant, f.untidy, []uuid.UUID{f.tidy})

	dup := loadMeasurementSQL(t, "duplicate_suspected_count")
	orphan := loadMeasurementSQL(t, "orphan_relationship_count")

	// Before: nothing has evaluated these assets and the controls yield
	// NOTHING. Not "0 findings, therefore compliant" — nothing.
	if n := countMeasurementRows(t, f.owner, f.tenant, dup); n != 0 {
		t.Fatalf("IH-005 produced %d measurements before the producer ran; an asset nobody has evaluated must read NOT ASSESSED", n)
	}
	if n := countMeasurementRows(t, f.owner, f.tenant, orphan); n != 0 {
		t.Fatalf("IH-006 produced %d measurements before the producer ran", n)
	}

	run := f.run(t, ctx)
	if run.Assessed == 0 {
		t.Fatal("the pass claimed coverage of no asset; without it the Inventory Hygiene counting controls are not assessed forever")
	}
	// Every LIVE asset, and only those — the archived one is not read and so is
	// not claimed.
	if got := assessedAssets(t, f.owner, f.tenant, findings.ProducerHygiene); len(got) != 2 {
		t.Errorf("coverage names %d assets, want the 2 live ones (the archived asset must not be claimed): %v", len(got), got)
	}

	// Claim 2: run the recompute the job runs after every pass, and the RISK
	// array is STILL empty. Asserting this without running the rollup would be
	// vacuous — the array is derived, so nothing has written it yet either way.
	// Add `hygiene` to the rollup's risk-feeding producer set and this goes red.
	f.recomputeRisk(t)
	var arrAfterRun pq.StringArray
	var scoreAfterRun int
	if err := f.owner.QueryRow(`SELECT risk_assessed_by, risk_score FROM assets WHERE id = $1 AND tenant_id = $2`,
		f.untidy, f.tenant).Scan(&arrAfterRun, &scoreAfterRun); err != nil {
		t.Fatalf("reading risk_assessed_by: %v", err)
	}
	if len(arrAfterRun) != 0 {
		t.Fatalf("risk_assessed_by = %v after a hygiene pass and the recompute, want empty — hygiene feeds "+
			"no risk score, and the inventory UI reads a non-empty array as 'the risk score is a real answer'", arrAfterRun)
	}
	if scoreAfterRun != 0 {
		t.Errorf("the hygiene findings moved the risk score to %d; every hygiene kind is feeds_risk false", scoreAfterRun)
	}

	// A measurement per MONITORING asset, with the counts the producer wrote.
	dupValues := measurementValues(t, f.owner, f.tenant, dup)
	if len(dupValues) != 2 {
		t.Fatalf("IH-005 produced %d measurements, want 2 (the two monitoring assets)", len(dupValues))
	}
	for id, v := range dupValues {
		if v != 1 {
			t.Errorf("IH-005 counts %d suspected duplicates for %s, want 1", v, id)
		}
	}

	orphanValues := measurementValues(t, f.owner, f.tenant, orphan)
	if len(orphanValues) != 2 {
		t.Fatalf("IH-006 produced %d measurements, want 2", len(orphanValues))
	}
	// `tidy` is one end of the edge into the archived asset; `untidy` is not.
	if got := orphanValues[f.tidy.String()]; got != 1 {
		t.Errorf("IH-006 counts %d orphan edges for the asset that has one, want 1", got)
	}
	if got := orphanValues[f.untidy.String()]; got != 0 {
		t.Errorf("IH-006 counts %d orphan edges for an asset with none, want 0 — assessed clean is a real answer and is not the same as not assessed", got)
	}

	// A converged re-run keeps one coverage row per asset and the same counts.
	f.run(t, ctx)
	if got := assessedAssets(t, f.owner, f.tenant, findings.ProducerHygiene); len(got) != 2 {
		t.Errorf("coverage names %d assets after a second pass, want 2 — the upsert is keyed on (tenant, asset, producer)", len(got))
	}
	if got := measurementValues(t, f.owner, f.tenant, orphan)[f.tidy.String()]; got != 1 {
		t.Errorf("IH-006 counts %d after a converged re-run, want 1", got)
	}
}

// A pass whose WRITE PHASE failed claims no coverage.
//
// The contract on Writer.MarkAssessed asks every producer for this one, and
// asks for it specifically NOT driven by a cancelled context: a cancellation
// kills the read phase, so the write never runs and the assertion holds however
// the claim is arranged. Here the read completes and the failure is injected
// into the write transaction AFTER the coverage claim, which is the only shape
// that can tell a claim inside the transaction from one committed beside it.
func TestIntegration_HygieneProducer_AFailedWritePhaseClaimsNoCoverage(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	failing := &HygieneProducer{
		repo:   pgidentity.New(failingHandle(t)),
		writer: f.producer.writer,
		now:    time.Now,
	}
	// The read phase runs four queries (assets, endpoints, installs, edges) plus
	// the proposals read; the write phase's Upserts and the coverage INSERT are
	// Execs, and Sweep is the next QUERY. Arming the sweep's query makes the
	// write transaction roll back with the coverage claim already issued inside
	// it — which is exactly the case a claim committed separately would survive.
	armQueryFailure(t, hygieneSweepQueryOrdinal)
	if _, err := failing.Run(ctx, f.tenant); err == nil {
		t.Fatal("a pass whose write phase failed reported success")
	}

	if got := assessedAssets(t, f.owner, f.tenant, findings.ProducerHygiene); len(got) != 0 {
		t.Errorf("a failed write phase left %d coverage rows: %v. A claim that outlives the rollback of "+
			"the findings justifying it reads 'assessed, nothing found' forever", len(got), got)
	}
	// And nothing else landed either — the whole phase is one transaction.
	if n := len(activeFindingsFor(t, f.owner, f.tenant, findings.ProducerHygiene)); n != 0 {
		t.Errorf("a failed write phase left %d ACTIVE findings", n)
	}
}

// hygieneSweepQueryOrdinal is which QUERY of the pass the first Sweep is.
//
// The read phase issues five: assets, endpoints, software installs,
// relationships, merge proposals. Upsert and MarkAssessed go through Exec and
// are not counted. So the first Sweep is the sixth query, and arming it fails
// the write transaction with the coverage claim already inside it.
const hygieneSweepQueryOrdinal = 6

// assessedAssets is the set of assets one producer has claimed coverage of.
func assessedAssets(t *testing.T, db *sql.DB, tenant uuid.UUID, producerKey string) []string {
	t.Helper()
	var out []string
	testdb.RetryTransient(t, func() error {
		out = nil
		rows, err := db.Query(`SELECT asset_id::text FROM producer_assessments
		                       WHERE tenant_id = $1 AND producer = $2 ORDER BY asset_id`, tenant, producerKey)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out
}

// ---------------------------------------------------------- fixture helpers

func (f *hygieneFixture) finding(t *testing.T, kind, subjectType string, subjectID uuid.UUID) *storedFinding {
	t.Helper()
	return loadFinding(t, f.owner, f.tenant, findings.ProducerHygiene, kind, subjectType, subjectID)
}

// openMergeProposal writes the asset_history row the identification engine
// writes for a contested observation, and returns its id.
//
// Hand-built rather than driven through the engine: what is under test is the
// hygiene producer's reading of a PENDING proposal, and the engine needs a
// whole observation to produce one.
func openMergeProposal(t *testing.T, db *sql.DB, tenant, observation uuid.UUID, candidates []uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	parts := make([]string, 0, len(candidates))
	for _, c := range candidates {
		parts = append(parts, fmt.Sprintf(`{"asset_id":%q}`, c.String()))
	}
	payload := fmt.Sprintf(
		`{"kind":"merge_proposal","status":"pending","reason":"contested identifiers","observation_asset_id":%q,"fingerprint":%q,"candidates":[%s]}`,
		observation.String(), id.String(), strings.Join(parts, ","))
	exec(t, db, `INSERT INTO asset_history (id, tenant_id, asset_id, source, action, changes_json)
	             VALUES ($1, $2, $3, 'integration', $4, $5::jsonb)`,
		id, tenant, observation, string(identity.ActionMergeProposed), payload)
	return id
}

// loadMeasurementSQL reads one measurement type's compiled statement out of the
// compliance-engine's shipped golden, with the arguments its header records.
//
// The golden is generated by TestMeasurementSQLGolden from
// standards/measurement-types.yaml plus measurement_shapes.go, so executing it
// here runs the SAME statement a deployment runs. Writing the query out in this
// file instead would be a second spelling of the thing under test.
type measurementStatement struct {
	sql string
	// extraArgs is the shape's own parameter ($3): the producer for the finding
	// shape, the fact key for the fact shape.
	extraArgs []string
	// predArgs are the compiled predicate's parameters, $4 onwards.
	predArgs []string
}

func loadMeasurementSQL(t *testing.T, code string) measurementStatement {
	t.Helper()
	path := filepath.Join("..", "..", "..", "compliance-engine", "internal", "services",
		"testdata", "measurement_sql_golden.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the measurement SQL golden: %v", err)
	}

	var out measurementStatement
	var body []string
	inBlock := false
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "-- "+code+"  ["):
			inBlock = true
		case !inBlock:
			continue
		case strings.HasPrefix(line, "-- $3 = ["):
			out.extraArgs = bracketList(line)
		case strings.HasPrefix(line, "-- predicate args: ["):
			out.predArgs = bracketList(line)
		case strings.HasPrefix(line, "-- ====="):
			inBlock = false
		default:
			body = append(body, line)
		}
	}
	out.sql = strings.TrimSpace(strings.Join(body, "\n"))
	if out.sql == "" {
		t.Fatalf("measurement %q is not in the golden — regenerate it with -update-measurement-golden", code)
	}
	return out
}

func bracketList(line string) []string {
	i := strings.Index(line, "[")
	j := strings.LastIndex(line, "]")
	if i < 0 || j <= i {
		return nil
	}
	return strings.Fields(line[i+1 : j])
}

// args assembles the statement's parameters: $1 tenant, $2 the optional
// single-subject filter (nil here, meaning tenant-wide), then the shape's own
// and the predicate's.
func (m measurementStatement) args(tenant uuid.UUID) []any {
	out := []any{tenant, nil}
	for _, a := range m.extraArgs {
		out = append(out, a)
	}
	for _, a := range m.predArgs {
		out = append(out, a)
	}
	return out
}

func countMeasurementRows(t *testing.T, db *sql.DB, tenant uuid.UUID, m measurementStatement) int {
	t.Helper()
	return len(measurementValues(t, db, tenant, m))
}

// measurementValues runs the statement and returns subject_id → the measured
// integer (col_0, which is `finding_count` for the finding shape).
func measurementValues(t *testing.T, db *sql.DB, tenant uuid.UUID, m measurementStatement) map[string]int {
	t.Helper()
	out := map[string]int{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := db.Query(m.sql, m.args(tenant)...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		cols, err := rows.Columns()
		if err != nil {
			return err
		}
		if len(cols) < 4 {
			return fmt.Errorf("the measurement statement selects %d columns; subject_id, tenant_id, measured_at and the value are the first four", len(cols))
		}
		for rows.Next() {
			// The shape's column order is fixed: subject_id, tenant_id,
			// measured_at, then the value and the evidence projection. Only the
			// first and the fourth are read; the rest go into throwaways,
			// because Scan requires a destination for every column.
			var subject uuid.UUID
			var value int64
			cells := make([]any, len(cols))
			cells[0] = &subject
			cells[3] = &value
			for i := range cells {
				if cells[i] == nil {
					cells[i] = new(any)
				}
			}
			if err := rows.Scan(cells...); err != nil {
				return err
			}
			out[subject.String()] = int(value)
		}
		return rows.Err()
	})
	return out
}
