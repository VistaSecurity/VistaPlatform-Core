package services

// Gate 3, half B: the two inventory frameworks SCORE a whole seeded estate.
//
// `hygiene_lifecycle_integration_test.go` beside this one pins each control in
// isolation, one scenario per tenant, against inputs written by hand. That is
// the right shape for "does IH-003 accept a region as a location" and the wrong
// shape for the gate, which asks something else: put ONE realistic estate in
// front of the real reconcile and check that all ten controls and both score
// rollups come out right together.
//
// The inputs are not hand-written here. They come from `shared/testdb/estate`,
// whose declared producer output is asserted against the REAL producers by half
// A (`inventory-service/internal/jobs/gate3_producer_pass_integration_test.go`).
// The two modules cannot import each other — producers and evaluator are both
// in `internal/` packages of different Go modules — so that is how the
// compliance half is kept honest about what it is scoring. A producer that
// changed its mind fails half A first, which is what forces this file's inputs
// to change with it.
//
// The mutation arm is the reason the gate asks for this at all: skip a producer
// and its controls must go NOT ASSESSED and the framework score must MOVE.
// Inventory Hygiene gets BETTER when the hygiene producer stops running — 14
// becomes 25 — because the two controls that were failing stop being counted
// at all. That is the three-valued collapse this platform keeps paying for,
// rendered as a number going up, and it is exactly what the score rollup has to
// keep visible through `controls_not_assessed` rather than hide.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/estate"
)

type gate3Fixture struct {
	db       *sqlx.DB
	tenant   uuid.UUID
	est      *estate.Estate
	eval     *RuleEvaluator
	findings *FindingsService
}

// newGate3Fixture seeds the estate and, unless `skip` names them, the output a
// full producer pass over it leaves behind.
func newGate3Fixture(t *testing.T, skip ...string) *gate3Fixture {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	est := estate.Seed(t, raw, tenant)
	est.ApplyProducerOutput(t, raw, skip...)

	extractor := NewMeasurementExtractor(db)
	evaluator := NewRuleEvaluator(db, extractor)
	return &gate3Fixture{
		db: db, tenant: tenant, est: est, eval: evaluator,
		findings: NewFindingsService(db, db, evaluator, nil, NewEvaluationService(db, evaluator), nil),
	}
}

func (f *gate3Fixture) controlID(t *testing.T, framework, control string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.db.Get(&id, `
		SELECT c.id FROM platform_framework_controls c
		JOIN platform_frameworks fw ON fw.id = c.framework_id
		WHERE fw.code = $1 AND c.control_id = $2`, framework, control); err != nil {
		t.Fatalf("seeded control %s/%s not found: %v", framework, control, err)
	}
	return id
}

func (f *gate3Fixture) status(t *testing.T, framework, control string) *EvaluationResult {
	t.Helper()
	res, err := f.eval.EvaluateControl(f.tenant, f.controlID(t, framework, control), "platform")
	if err != nil {
		t.Fatalf("evaluate %s/%s: %v", framework, control, err)
	}
	return res
}

// score reads the materialized rollup the reconcile writes. A nil score is the
// honest answer for a framework with nothing assessed, and the column is
// nullable precisely so it cannot be reported as 0 or 100.
type rollup struct {
	Score       *int `db:"score"`
	Total       int  `db:"controls_total"`
	Passing     int  `db:"controls_passing"`
	Failing     int  `db:"controls_failing"`
	NotAssessed int  `db:"controls_not_assessed"`
}

func (f *gate3Fixture) rollup(t *testing.T, framework string) rollup {
	t.Helper()
	var out rollup
	if err := f.db.Get(&out, `
		SELECT s.score, s.controls_total, s.controls_passing, s.controls_failing, s.controls_not_assessed
		FROM tenant_framework_scores s
		JOIN platform_frameworks fw ON fw.id = s.platform_framework_id
		WHERE s.tenant_id = $1 AND fw.code = $2`, f.tenant, framework); err != nil {
		t.Fatalf("no tenant_framework_scores row for %s: %v — a published framework with no rollup shows "+
			"the tenant a dash where a preview score belongs", framework, err)
	}
	return out
}

func (f *gate3Fixture) reconcile(t *testing.T) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		_, err := f.findings.EvaluateTenantFrameworks(context.Background(), f.tenant)
		return err
	})
}

func wantStatus(t *testing.T, res *EvaluationResult, control, want, why string) {
	t.Helper()
	if res.Status != want {
		t.Errorf("%s is %q (reason %q, %d finding(s)), want %q — %s",
			control, res.Status, res.NotAssessedReason, len(res.Findings), want, why)
	}
}

// TestIntegration_Gate3_InventoryFrameworksScoreTheEstate is the headline: all
// ten controls and both rollups, over one estate, after the real reconcile.
func TestIntegration_Gate3_InventoryFrameworksScoreTheEstate(t *testing.T) {
	f := newGate3Fixture(t)

	// --- Inventory Hygiene, control by control.
	//
	// The population is the tenant's MONITORING assets: web-01, db-01,
	// printer-7 and sw-01. web-01-dup is still in Approvals and is scored by
	// none of these, which is what stops a tenant's hygiene score from being a
	// function of how much they have scanned lately.
	wantStatus(t, f.status(t, "inventory-hygiene", "IH-001"), "IH-001", "fail",
		"printer-7 names neither an owner nor a support group")
	wantStatus(t, f.status(t, "inventory-hygiene", "IH-002"), "IH-002", "fail",
		"printer-7 is still on the unknown_host placeholder")
	wantStatus(t, f.status(t, "inventory-hygiene", "IH-003"), "IH-003", "fail",
		"printer-7 records no site, region, zone or location")
	wantStatus(t, f.status(t, "inventory-hygiene", "IH-004"), "IH-004", "pass",
		"every monitoring asset was seen today. The estate's stale subject is a software "+
			"INSTALL, and this control is about the asset RECORD")
	wantStatus(t, f.status(t, "inventory-hygiene", "IH-005"), "IH-005", "fail",
		"web-01 is named in an open merge proposal, so the hygiene producer raised duplicate_suspected on it")
	wantStatus(t, f.status(t, "inventory-hygiene", "IH-006"), "IH-006", "fail",
		"web-01's relationship into the archived ghost-01 is an orphan; the finding's subject is the "+
			"RELATIONSHIP and the control has to reach it through the asset's edges")

	// --- Lifecycle, control by control.
	wantStatus(t, f.status(t, "lifecycle", "LC-001"), "LC-001", "fail",
		"web-01's operating system passed end of life 200 days ago")
	wantStatus(t, f.status(t, "lifecycle", "LC-002"), "LC-002", "fail",
		"the ninety-day ladder is cumulative, so an operating system already past end of life fails it too")
	wantStatus(t, f.status(t, "lifecycle", "LC-003"), "LC-003", "fail",
		"web-01's openssl install passed end of life 40 days ago")
	wantStatus(t, f.status(t, "lifecycle", "LC-004"), "LC-004", "fail",
		"db-01's chassis is 800 days past vendor end of support")

	// The db-01 half of LC-001 is the one worth stating on its own: it is a
	// resolved date that has NOT passed. If the eol producer wrote no fact for
	// a supported product, this asset would read NOT ASSESSED and the framework
	// could never tell "we checked and it is fine" from "we never asked".
	assertAssetPasses(t, f, "lifecycle", "LC-001", f.est.DB)

	// --- the two rollups the reconcile materializes.
	f.reconcile(t)

	hygiene := f.rollup(t, "inventory-hygiene")
	assertRollup(t, "inventory-hygiene", hygiene, rollup{
		// One control passes (IH-004, Low, weight 1) out of a total assessed
		// weight of 7 — IH-001/2/3/6 Low at 1 each and IH-005 Med at 2.
		Score: intp(14), Total: 6, Passing: 1, Failing: 5, NotAssessed: 0,
	})

	lifecycle := f.rollup(t, "lifecycle")
	assertRollup(t, "lifecycle", lifecycle, rollup{
		// Every Lifecycle control fails on this estate, so the score is a real
		// zero — assessed and bad — which the mutation below distinguishes from
		// the nil that means nothing was assessed at all.
		Score: intp(0), Total: 4, Passing: 0, Failing: 4, NotAssessed: 0,
	})
}

// TestIntegration_Gate3_SkippingAProducerTakesItsControlsToNotAssessed is the
// mutation arm the gate asks for.
func TestIntegration_Gate3_SkippingAProducerTakesItsControlsToNotAssessed(t *testing.T) {
	t.Run("without the hygiene producer the counting controls stop being answerable and the score goes UP", func(t *testing.T) {
		f := newGate3Fixture(t, findings.ProducerHygiene)

		// The four record-quality controls are unmoved: they read the asset ROW
		// and are answerable with or without a producer pass. That is what makes
		// the next two a real signal rather than the whole framework going dark.
		wantStatus(t, f.status(t, "inventory-hygiene", "IH-001"), "IH-001", "fail", "still read from the asset row")
		wantStatus(t, f.status(t, "inventory-hygiene", "IH-004"), "IH-004", "pass", "still read from the asset row")

		for _, control := range []string{"IH-005", "IH-006"} {
			res := f.status(t, "inventory-hygiene", control)
			wantStatus(t, res, control, "not_assessed",
				"nothing has looked for duplicates or orphan edges on these assets. Reporting PASS here is "+
					"the check-that-cannot-fail shape: every install without the producer would score 100")
			if res.Score != nil {
				t.Errorf("%s has a score of %d; a control nobody assessed has none", control, *res.Score)
			}
		}

		f.reconcile(t)
		got := f.rollup(t, "inventory-hygiene")
		assertRollup(t, "inventory-hygiene (no hygiene producer)", got, rollup{
			// 1 passing weight over 4 assessed weight. The score went UP from 14
			// because the two failing controls stopped being counted — which is
			// why controls_not_assessed has to travel beside it.
			Score: intp(25), Total: 6, Passing: 1, Failing: 3, NotAssessed: 2,
		})
	})

	t.Run("without the eol producer the Lifecycle framework has no score at all", func(t *testing.T) {
		f := newGate3Fixture(t, findings.ProducerEOL)

		for _, control := range []string{"LC-001", "LC-002", "LC-003", "LC-004"} {
			res := f.status(t, "lifecycle", control)
			wantStatus(t, res, control, "not_assessed",
				"every Lifecycle control measures an eol.* fact the producer resolves from the catalogue. "+
					"With no pass there is no fact, and 'we could not find out' is not 'it is supported'")
		}

		f.reconcile(t)
		got := f.rollup(t, "lifecycle")
		if got.Score != nil {
			t.Errorf("Lifecycle scores %d with nothing assessed, want no score at all — a framework whose "+
				"every control is unassessable must show a dash, not a number", *got.Score)
		}
		assertRollup(t, "lifecycle (no eol producer)", got, rollup{
			Score: nil, Total: 4, Passing: 0, Failing: 0, NotAssessed: 4,
		})
	})
}

// assertAssetPasses checks that one named asset is NOT among a control's
// violating subjects, and that the control had something to say about it.
func assertAssetPasses(t *testing.T, f *gate3Fixture, framework, control string, asset uuid.UUID) {
	t.Helper()
	res := f.status(t, framework, control)
	for _, finding := range res.Findings {
		if finding.SubjectID == asset {
			t.Errorf("%s/%s reports %s as violating; its end-of-life date is in the future",
				framework, control, f.est.Name(asset))
		}
	}
	// And the measurement exists at all — otherwise "not among the violations"
	// is satisfied by never having measured it.
	var n int
	if err := f.db.Get(&n, `SELECT count(*) FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = 'eol.os.date'`, f.tenant, asset); err != nil {
		t.Fatalf("counting eol facts: %v", err)
	}
	if n == 0 {
		t.Errorf("%s has no eol.os.date fact, so %s/%s passing over it means nothing",
			f.est.Name(asset), framework, control)
	}
}

func assertRollup(t *testing.T, what string, got, want rollup) {
	t.Helper()
	switch {
	case want.Score == nil && got.Score != nil:
		t.Errorf("%s scores %d, want no score", what, *got.Score)
	case want.Score != nil && got.Score == nil:
		t.Errorf("%s has no score, want %d", what, *want.Score)
	case want.Score != nil && got.Score != nil && *want.Score != *got.Score:
		t.Errorf("%s scores %d, want %d", what, *got.Score, *want.Score)
	}
	if got.Total != want.Total || got.Passing != want.Passing ||
		got.Failing != want.Failing || got.NotAssessed != want.NotAssessed {
		t.Errorf("%s breakdown = total %d / passing %d / failing %d / not assessed %d, "+
			"want total %d / passing %d / failing %d / not assessed %d",
			what, got.Total, got.Passing, got.Failing, got.NotAssessed,
			want.Total, want.Passing, want.Failing, want.NotAssessed)
	}
}

func intp(v int) *int { return &v }
