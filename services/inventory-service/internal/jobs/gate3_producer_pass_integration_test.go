package jobs

// Gate 3, half A: ONE realistic estate, EVERY producer, through the real job.
//
// Each producer has its own integration test, and each of those seeds the
// smallest inventory that producer has something to say about. None of them —
// and nothing else in the repository — ever runs the six together over one
// tenant through `runTenant`, which is the only thing that executes a producer
// in production. `producer_job_runs_test.go` is a SOURCE scan precisely because
// a driven pass needs a real database and four populated catalogues; this is
// that driven pass.
//
// What it proves, and why each half needs proving:
//
//  1. a full pass over `shared/testdb/estate` leaves EXACTLY the findings that
//     estate declares — not "at least", exactly, so a producer that starts
//     raising on the archived asset or on the approval queue fails here;
//  2. the coverage record matches, per producer, which is what makes every
//     downstream three-valued answer possible;
//  3. the eol.* FACTS land, including the one on the asset with no finding —
//     the supported operating system, whose date is what lets LC-001 report
//     PASS rather than NOT ASSESSED over in half B;
//  4. `assets.risk_score` and `assets.risk_assessed_by` are what the rollup
//     makes of all of it, including the two assets that must stay at NOT
//     ASSESSED for risk;
//  5. the dashboard's Inventory-health facets agree with the same estate.
//
// Half B (`compliance-engine/internal/services/gate3_frameworks_integration_test.go`)
// takes it from here: it applies the same declared output and runs the real
// reconcile over it. The two modules cannot import each other — the producers
// and the evaluator are both in `internal/` packages of different modules — so
// THIS test is what keeps the estate's declaration honest, and therefore what
// keeps half B's inputs real. See the package doc on shared/testdb/estate.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/estate"
)

// gate3Fixture is the estate plus the real job over it.
type gate3Fixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID
	est    *estate.Estate
	job    *FindingProducerJob
}

func newGate3Fixture(t *testing.T) *gate3Fixture {
	t.Helper()
	owner := testdb.Connect(t)
	// No testdb.ApplySchema: the runner applies scripts/database/schema.sql once
	// per database, and re-applying it per fixture takes ACCESS EXCLUSIVE locks
	// across the whole schema while other package binaries of the same
	// `go test./...` run are querying it.
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	est := estate.Seed(t, owner, tenant)

	// The REAL constructor, with the two handles main.go gives it: the
	// RLS-subject handle the producers write on, and the bypass handle for the
	// platform catalogues and the tenant enumeration.
	job, err := NewFindingProducerJob(app, owner)
	if err != nil {
		t.Fatalf("NewFindingProducerJob: %v", err)
	}
	return &gate3Fixture{owner: owner, app: app, tenant: tenant, est: est, job: job}
}

// run is one whole-tenant pass through the production entry point.
//
// Retried past the cross-binary races the shared integration database produces:
// `go test ./...` runs package binaries concurrently against one Postgres and a
// neighbouring package applying the schema takes ACCESS EXCLUSIVE locks across
// it. Each producer's write phase is one transaction, so a deadlock rolled it
// back and a retry starts from the same state. Only transient races are
// retried; a real failure is deterministic and still fails.
func (f *gate3Fixture) run(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			if ok := f.job.runTenant(ctx, f.tenant); !ok {
				return fmt.Errorf("runTenant reported a producer failure; see the job log above")
			}
			return nil
		})
	})
}

// TestIntegration_Gate3_FullProducerPassOverTheReferenceEstate is the headline.
func TestIntegration_Gate3_FullProducerPassOverTheReferenceEstate(t *testing.T) {
	f := newGate3Fixture(t)
	f.run(t)

	assertFindings(t, f)
	assertCoverage(t, f)
	assertEOLFacts(t, f)
	assertRiskRollup(t, f)
	assertInventoryHealthFacets(t, f)

	// Convergence: a second pass over an unchanged estate resolves nothing and
	// leaves the same set. A producer whose sweep and upsert disagree shows up
	// here as findings flapping between ACTIVE and INACTIVE on every nightly
	// run — which on a screen is a tenant's triage state being reset nightly.
	f.run(t)
	assertFindings(t, f)
	assertCoverage(t, f)
}

// --------------------------------------------------------------- findings --

func assertFindings(t *testing.T, f *gate3Fixture) {
	t.Helper()
	got := activeFindings(t, f.owner, f.tenant)

	want := map[string][2]any{}
	for _, e := range f.est.ExpectedFindings() {
		severity, score := f.est.Verdict(t, e)
		want[e.Key()] = [2]any{severity, score}
	}

	for key, pair := range want {
		row, ok := got[key]
		if !ok {
			t.Errorf("no ACTIVE finding for %s — the producer that owns it either did not run or stopped raising", key)
			continue
		}
		if row.severity != pair[0] || row.score != pair[1] {
			t.Errorf("%s is (%s, %d), want (%s, %d)", key, row.severity, row.score, pair[0], pair[1])
		}
	}
	// EXACTLY, not at least. An extra finding is a producer judging something
	// it should not — the archived asset, the approval queue, the loopback
	// socket — and "at least" is the assertion shape that never notices.
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected ACTIVE finding %s; the estate declares %d findings and the pass wrote %d",
				key, len(want), len(got))
		}
	}
}

type storedFinding struct {
	severity string
	score    int
}

func activeFindings(t *testing.T, db *sql.DB, tenant uuid.UUID) map[string]storedFinding {
	t.Helper()
	out := map[string]storedFinding{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := db.Query(`
			SELECT producer, kind, subject_type, subject_id, severity, score
			FROM findings
			WHERE tenant_id = $1 AND detection_state = 'ACTIVE'`, tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var producer, kind, subjectType, severity string
			var subject uuid.UUID
			var score int
			if err := rows.Scan(&producer, &kind, &subjectType, &subject, &severity, &score); err != nil {
				return err
			}
			key := estate.Finding{Producer: producer, Kind: kind, SubjectType: subjectType, Subject: subject}.Key()
			out[key] = storedFinding{severity: severity, score: score}
		}
		return rows.Err()
	})
	return out
}

// --------------------------------------------------------------- coverage --

func assertCoverage(t *testing.T, f *gate3Fixture) {
	t.Helper()
	got := map[string][]string{}
	testdb.RetryTransient(t, func() error {
		clear(got)
		rows, err := f.owner.Query(`SELECT producer, asset_id::text FROM producer_assessments
		                            WHERE tenant_id = $1 ORDER BY producer, asset_id`, f.tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var producer, asset string
			if err := rows.Scan(&producer, &asset); err != nil {
				return err
			}
			got[producer] = append(got[producer], asset)
		}
		return rows.Err()
	})

	want := map[string][]string{}
	for producerKey, assets := range f.est.ExpectedCoverage() {
		ids := make([]string, 0, len(assets))
		for _, id := range assets {
			ids = append(ids, id.String())
		}
		sort.Strings(ids)
		want[producerKey] = ids
	}
	for producerKey, ids := range got {
		sort.Strings(ids)
		got[producerKey] = ids
	}

	for producerKey, wantIDs := range want {
		gotIDs := got[producerKey]
		if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
			t.Errorf("%s claimed coverage of %v, want %v — coverage is a RECORD of who looked, and every "+
				"three-valued answer downstream is derived from it",
				producerKey, f.est.Label(gotIDs), f.est.Label(wantIDs))
		}
	}
	for producerKey := range got {
		if _, ok := want[producerKey]; !ok {
			t.Errorf("a producer the estate does not expect claimed coverage: %s", producerKey)
		}
	}
}

// ------------------------------------------------------------- eol facts ---

func assertEOLFacts(t *testing.T, f *gate3Fixture) {
	t.Helper()
	type factRow struct{ value, sourceRef string }
	got := map[string]factRow{}
	testdb.RetryTransient(t, func() error {
		clear(got)
		rows, err := f.owner.Query(`
			SELECT asset_id::text, key, value #>> '{}', source_ref
			FROM asset_facts
			WHERE tenant_id = $1 AND key LIKE 'eol.%'`, f.tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var asset, key, value, sourceRef string
			if err := rows.Scan(&asset, &key, &value, &sourceRef); err != nil {
				return err
			}
			got[asset+" "+key] = factRow{value: value, sourceRef: sourceRef}
		}
		return rows.Err()
	})

	want := map[string]bool{}
	for _, wantFact := range f.est.ExpectedFacts() {
		key := wantFact.Asset.String() + " " + wantFact.Key
		want[key] = true
		row, ok := got[key]
		if !ok {
			t.Errorf("no %s fact on %s — the finding says there is a problem, the FACT says what the date "+
				"is, and the asset page shows the second whether or not there is a first",
				wantFact.Key, f.est.Name(wantFact.Asset))
			continue
		}
		// The value is a date string; compare the day, which is all
		// `eol_catalogue.eol_date` carries.
		if !strings.HasPrefix(row.value, wantFact.Date.Format("2006-01-02")) {
			t.Errorf("%s on %s = %q, want the catalogue's %s",
				wantFact.Key, f.est.Name(wantFact.Asset), row.value, wantFact.Date.Format("2006-01-02"))
		}
		if row.sourceRef != wantFact.SourceRef {
			t.Errorf("%s on %s cites %q, want %q — a disputed date has to lead back to the exact catalogue row",
				wantFact.Key, f.est.Name(wantFact.Asset), row.sourceRef, wantFact.SourceRef)
		}
	}
	for key := range got {
		if !want[key] {
			t.Errorf("unexpected eol fact %q; a fact for a product the catalogue did not resolve would be an "+
				"invented date", key)
		}
	}
}

// ----------------------------------------------------------------- rollup --

func assertRiskRollup(t *testing.T, f *gate3Fixture) {
	t.Helper()

	// The expected score of every asset, derived from the estate's declared
	// findings rather than restated: MAX over the risk-FEEDING findings whose
	// subject belongs to the asset.
	//
	// The mapping from subject to asset is spelled out per subject rather than
	// looked up, because it is the claim: a finding on an INSTALL and a finding
	// on a CONFIGURATION both belong to their host, and a rollup that only
	// looked at asset-subject findings would silently report web-01 as clean
	// while its openssl install carried a 9.8.
	owner := map[uuid.UUID]uuid.UUID{
		f.est.Web:            f.est.Web,
		f.est.DB:             f.est.DB,
		f.est.Printer:        f.est.Printer,
		f.est.Switch:         f.est.Switch,
		f.est.WebDup:         f.est.WebDup,
		f.est.OpenSSLInstall: f.est.Web,
		f.est.WeakConfig:     f.est.Web,
		f.est.TelnetPort:     f.est.Switch,
		f.est.OrphanEdge:     uuid.Nil, // a relationship belongs to no single asset
	}
	wantScore := map[uuid.UUID]int{}
	for _, e := range f.est.ExpectedFindings() {
		if !findings.FeedsRisk(e.Producer, e.Kind) {
			continue
		}
		host, ok := owner[e.Subject]
		if !ok || host == uuid.Nil {
			continue
		}
		_, score := f.est.Verdict(t, e)
		if score > wantScore[host] {
			wantScore[host] = score
		}
	}

	// And the coverage array: the RISK-FEEDING subset of the coverage record.
	// `hygiene` is deliberately absent from every one of these, which is what
	// keeps printer-7 reading NOT ASSESSED for risk even though a producer has
	// looked at it four times.
	riskFeeding := map[string]bool{}
	for _, p := range findings.RiskFeedingProducers() {
		riskFeeding[p] = true
	}
	wantAssessedBy := map[uuid.UUID][]string{}
	for producerKey, assets := range f.est.ExpectedCoverage() {
		if !riskFeeding[producerKey] {
			continue
		}
		for _, id := range assets {
			wantAssessedBy[id] = append(wantAssessedBy[id], producerKey)
		}
	}

	for _, id := range []uuid.UUID{f.est.Web, f.est.DB, f.est.Printer, f.est.Switch, f.est.WebDup} {
		var score int
		var assessedBy pq.StringArray
		if err := f.owner.QueryRow(`SELECT risk_score, risk_assessed_by FROM assets WHERE tenant_id = $1 AND id = $2`,
			f.tenant, id).Scan(&score, &assessedBy); err != nil {
			t.Fatalf("reading the rollup for %s: %v", f.est.Name(id), err)
		}
		if score != wantScore[id] {
			t.Errorf("%s risk_score = %d, want %d (MAX over its open risk-feeding findings, asset plus its "+
				"endpoints, configurations, certificates and software installs)",
				f.est.Name(id), score, wantScore[id])
		}
		got := []string(assessedBy)
		want := append([]string(nil), wantAssessedBy[id]...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s risk_assessed_by = %v, want %v", f.est.Name(id), got, want)
		}
	}

	// The two three-valued cases, stated separately because they are the ones a
	// reader has to be able to tell apart on a screen.
	var printerScore int
	var printerAssessed pq.StringArray
	if err := f.owner.QueryRow(`SELECT risk_score, risk_assessed_by FROM assets WHERE tenant_id = $1 AND id = $2`,
		f.tenant, f.est.Printer).Scan(&printerScore, &printerAssessed); err != nil {
		t.Fatalf("reading printer-7's rollup: %v", err)
	}
	if printerScore != 0 || len(printerAssessed) != 0 {
		t.Errorf("printer-7 is (%d, %v); it carries four hygiene findings, all feeds_risk false, and no "+
			"risk-feeding producer has anything to say about it — so it must read NOT ASSESSED for risk, "+
			"which is score 0 with an EMPTY array", printerScore, []string(printerAssessed))
	}
	var dupAssessed pq.StringArray
	if err := f.owner.QueryRow(`SELECT risk_assessed_by FROM assets WHERE tenant_id = $1 AND id = $2`,
		f.tenant, f.est.WebDup).Scan(&dupAssessed); err != nil {
		t.Fatalf("reading web-01-dup's rollup: %v", err)
	}
	if len(dupAssessed) != 0 {
		t.Errorf("the pending_approval half of the merge pair is assessed by %v; nothing has accepted it "+
			"into the estate yet", []string(dupAssessed))
	}
}

// ------------------------------------------------- dashboard: facet counts --

// assertInventoryHealthFacets checks the numbers the Dashboard's Inventory
// health hero reads (ADR-0006 D5, workstream 3.8) against the same estate.
//
// The hero reads three facet levels plus the Inventory Hygiene framework score
// (which is half B's). Two of the three levels are pure `assets` columns; the
// third — `risk` — is the one the producer pass moves, and it is read through
// the SAME service method the HTTP handler calls, so a facet query that stopped
// reading the persisted rollup fails here.
func assertInventoryHealthFacets(t *testing.T, f *gate3Fixture) {
	t.Helper()
	svc := services.NewAssetService(&database.DB{DB: sqlx.NewDb(f.owner, "postgres")})

	bucket := func(level, key string) int {
		t.Helper()
		var buckets []models.AssetFacetBucket
		testdb.RetryTransient(t, func() error {
			var err error
			buckets, err = svc.GetAssetFacets(f.tenant, models.AssetFilters{}, level, 50)
			return err
		})
		for _, b := range buckets {
			if b.Key == key {
				return b.Count
			}
		}
		return 0
	}

	// Class roots partition the estate exactly — the hero sums them for its
	// total — and the facet is hierarchical, so `hardware` counts every one of
	// its descendants once.
	if got := bucket("class", "hardware"); got != 3 {
		t.Errorf("class facet `hardware` = %d, want 3 (web-01, db-01, sw-01) — printer-7 is unclassified and "+
			"the archived and pending assets are out of the monitoring population", got)
	}
	if got := bucket("class", "unknown_host"); got != 1 {
		t.Errorf("class facet `unknown_host` = %d, want 1 (printer-7)", got)
	}

	// The risk facet reads `assets.risk_score` + `risk_assessed_by`, which only
	// the post-pass rollup writes. Before phase 3 every one of these assets
	// would have banded `not_assessed`.
	if got := bucket("risk", "critical"); got != 1 {
		t.Errorf("risk facet `critical` = %d, want 1 (web-01, at the openssl advisory's 98)", got)
	}
	if got := bucket("risk", "not_assessed"); got != 1 {
		t.Errorf("risk facet `not_assessed` = %d, want 1 (printer-7) — a facet that banded it Low or "+
			"Informational would be reporting 'nobody looked' as 'nothing wrong'", got)
	}

	// `has_findings` is the facet workstream 3.1 restored. Every monitoring
	// asset in this estate carries at least one finding except db-01... which
	// carries the hardware one, so all four do.
	if got := bucket("has_findings", "true"); got != 4 {
		t.Errorf("has_findings `true` = %d, want 4 — every monitoring asset in the estate has at least one "+
			"open finding after a full pass", got)
	}
}

// ------------------------------------------------------------- mutation ----

// TestIntegration_Gate3_SkippingOneProducerChangesTheAnswer is the mutation
// arm. It runs the pass exactly as `runTenant` does, minus ONE producer, and
// asserts the answer moves — both the number and the coverage.
//
// Without it the headline test is compatible with a rollup that ignores the
// producers entirely: every assertion above would still pass if the scores
// happened to be right for another reason. Two producers are skipped in turn
// because they fail differently: dropping `vulnerability` must change the
// SCORE (the advisory is the estate's worst number), and dropping `crypto` must
// change the COVERAGE (it is the only producer that assesses web-01's
// cryptography, so the score has to stop claiming to be a crypto answer).
func TestIntegration_Gate3_SkippingOneProducerChangesTheAnswer(t *testing.T) {
	ctx := context.Background()

	t.Run("without the vulnerability producer the score drops to the next worst finding", func(t *testing.T) {
		f := newGate3Fixture(t)
		f.runWithout(t, ctx, findings.ProducerVulnerability)

		score, assessedBy := f.rollup(t, f.est.Web)
		if score != estate.WeakAlgorithmRisk {
			t.Errorf("web-01 scores %d without the vulnerability pass, want %d — the CVE was the worst "+
				"finding on the asset, so removing it must expose the next one rather than leave the "+
				"number where it was",
				score, estate.WeakAlgorithmRisk)
		}
		if contains(assessedBy, findings.ProducerVulnerability) {
			t.Errorf("risk_assessed_by still claims %q after a pass that never ran it: %v — an asset that "+
				"reads 'assessed' for a producer that did not look is the exact three-valued collapse "+
				"this column exists to prevent", findings.ProducerVulnerability, assessedBy)
		}
	})

	t.Run("without the crypto producer the coverage stops claiming a crypto answer", func(t *testing.T) {
		f := newGate3Fixture(t)
		f.runWithout(t, ctx, findings.ProducerCrypto)

		_, assessedBy := f.rollup(t, f.est.Web)
		if contains(assessedBy, findings.ProducerCrypto) {
			t.Errorf("risk_assessed_by = %v after a pass with no crypto producer", assessedBy)
		}
		if got := activeFindings(t, f.owner, f.tenant); len(got) != len(f.est.ExpectedFindings())-1 {
			t.Errorf("the pass left %d findings, want %d — exactly the weak_configuration one fewer",
				len(got), len(f.est.ExpectedFindings())-1)
		}
	})
}

// runWithout runs every producer the job holds EXCEPT one, in `runTenant`'s
// order, then the same post-pass recompute.
//
// Deliberately a copy of runTenant's body rather than a flag on the job: the
// production path must not grow a "skip this producer" switch that exists only
// for a test, and what is under test here is the CONSEQUENCE of a producer not
// having spoken — which is the same whether it was skipped, crashed, or was
// never wired up ('s shape).
func (f *gate3Fixture) runWithout(t *testing.T, ctx context.Context, skip string) {
	t.Helper()
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			if skip != findings.ProducerEOL {
				if _, err := f.job.eol.Run(ctx, f.tenant); err != nil {
					return err
				}
			}
			if skip != findings.ProducerVulnerability {
				if _, err := f.job.vuln.Run(ctx, f.tenant); err != nil {
					return err
				}
			}
			if skip != findings.ProducerCrypto {
				if _, err := f.job.crypto.Run(ctx, f.tenant); err != nil {
					return err
				}
			}
			if skip != findings.ProducerConfiguration {
				if _, err := f.job.config.Run(ctx, f.tenant); err != nil {
					return err
				}
			}
			if skip != findings.ProducerHygiene {
				if _, err := f.job.hygiene.Run(ctx, f.tenant); err != nil {
					return err
				}
			}
			if skip != findings.ProducerDrift {
				if _, err := f.job.drift.Run(ctx, f.tenant); err != nil {
					return err
				}
			}
			return f.job.recomputeRisk(ctx, f.tenant)
		})
	})
}

func (f *gate3Fixture) rollup(t *testing.T, asset uuid.UUID) (int, []string) {
	t.Helper()
	var score int
	var assessedBy pq.StringArray
	if err := f.owner.QueryRow(`SELECT risk_score, risk_assessed_by FROM assets WHERE tenant_id = $1 AND id = $2`,
		f.tenant, asset).Scan(&score, &assessedBy); err != nil {
		t.Fatalf("reading the rollup: %v", err)
	}
	return score, []string(assessedBy)
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
