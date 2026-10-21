package services

// The consistency guard between the two scoring paths: the LIVE evaluation
// (RuleEvaluator, which runs every extraction) and the MATERIALIZED rollup
// (tenant_framework_scores, folded by loadControlAssessments without running
// any) must agree on every control's result and on the framework percentage,
// for assets inside and outside each control's population.
//
// The population is the subjects a control is ABOUT. Three controls with three
// different population rules carry the weight here:
//
//	IH-001  asset shape    `where: status:monitoring`            — an asset still
//	                                                                in Approvals is out
//	IH-008  finding shape  `subject_where: … exists(rack.id)`    — an unracked asset is out
//	IH-013  finding shape  `subject_where: … exists(warranty_end)` — no warranty date is out
//
// Before the probe was built from the extraction's own population, the stored
// path answered IH-008 and IH-013 with "did the hygiene producer assess any
// asset?" and IH-001 with "does the tenant have any live asset?", so every one
// of the out-of-population scenarios below scored PASS in the rollup while the
// live evaluator said NOT ASSESSED — an empty DCIM record scored higher than a
// populated one.
//
// The whole Inventory Hygiene framework is compared, not just the three: the
// percentage is the number a tenant sees, and it is only consistent if every
// control is.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type populationAsset struct {
	name     string
	status   string // asset_status; "" = monitoring
	owner    bool
	racked   bool // in a rack, at a unit position
	warranty *time.Time
	findings []string // hygiene kinds open against the asset
}

type populationScenario struct {
	name   string
	assets []populationAsset
	// want is the per-control result BOTH paths must report, for the three
	// controls whose population is under test. The rest of the framework is
	// held to "both paths agree" without a pinned value.
	want map[string]string
}

func TestIntegration_ScorePopulation_LiveAndStoredAgree(t *testing.T) {
	f := newInventoryFrameworkFixture(t)
	var frameworkID uuid.UUID
	if err := f.db.Get(&frameworkID, `SELECT id FROM platform_frameworks WHERE code = 'inventory-hygiene'`); err != nil {
		t.Fatalf("seeded inventory-hygiene framework: %v", err)
	}
	future := time.Now().AddDate(1, 0, 0)
	past := time.Now().AddDate(0, -2, 0)

	scenarios := []populationScenario{{
		name: "outside every population: an unapproved asset with no rack and no warranty date",
		assets: []populationAsset{
			{name: "pending-1", status: "pending_approval", owner: false},
		},
		want: map[string]string{"IH-001": statusNotAssessed, "IH-008": statusNotAssessed, "IH-013": statusNotAssessed},
	}, {
		name: "inside IH-001 only: monitored and owned, but nothing racked and no warranty recorded",
		assets: []populationAsset{
			{name: "owned-1", owner: true},
		},
		want: map[string]string{"IH-001": statusPass, "IH-008": statusNotAssessed, "IH-013": statusNotAssessed},
	}, {
		name: "inside every population and clean",
		assets: []populationAsset{
			{name: "good-1", owner: true, racked: true, warranty: &future},
		},
		want: map[string]string{"IH-001": statusPass, "IH-008": statusPass, "IH-013": statusPass},
	}, {
		name: "inside every population and violating each",
		assets: []populationAsset{
			{name: "bad-1", owner: false, racked: true, warranty: &past,
				findings: []string{"no_rack_position", "warranty_expired"}},
		},
		want: map[string]string{"IH-001": statusFail, "IH-008": statusFail, "IH-013": statusFail},
	}, {
		name: "mixed: one clean asset in each population beside one outside them",
		assets: []populationAsset{
			{name: "good-2", owner: true, racked: true, warranty: &future},
			{name: "bare-2", owner: true},
			{name: "pending-2", status: "pending_approval"},
		},
		want: map[string]string{"IH-001": statusPass, "IH-008": statusPass, "IH-013": statusPass},
	}}

	controls := f.hygieneControls(t, frameworkID)
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tenant := f.tenant(t)
			f.seedPopulationAssets(t, tenant, sc.assets)

			// Live: every control through the evaluator that runs extraction.
			live := map[string]string{}
			var liveOutcomes []controlOutcome
			for _, c := range controls {
				res, err := f.eval.EvaluateControl(tenant, c.ID, "platform")
				if err != nil {
					t.Fatalf("live evaluate %s: %v", c.ControlID, err)
				}
				live[c.ControlID] = strings.ToUpper(res.Status)
				liveOutcomes = append(liveOutcomes, controlOutcome{BaselineSeverity: c.BaselineSeverity, Status: live[c.ControlID]})
			}
			liveScore, err := frameworkScore(liveOutcomes)
			if err != nil {
				t.Fatalf("fold live outcomes: %v", err)
			}

			// Materialized: the real reconcile writes the findings and the
			// rollup; the per-control answer is the loader every read path uses.
			findings := NewFindingsService(f.db, f.db, f.eval, nil, NewEvaluationService(f.db, f.eval), nil)
			testdb.RetryTransient(t, func() error {
				_, err := findings.EvaluateTenantFrameworks(context.Background(), tenant)
				return err
			})
			ids := make([]uuid.UUID, len(controls))
			for i, c := range controls {
				ids[i] = c.ID
			}
			stored, err := loadControlAssessments(context.Background(), f.db.DB, tenant, ids, "platform")
			if err != nil {
				t.Fatalf("load stored assessments: %v", err)
			}

			for _, c := range controls {
				if got := stored[c.ID].Status; got != live[c.ControlID] {
					t.Errorf("%s: stored %s (reason %q) but live %s — the two paths disagree about this "+
						"control's population", c.ControlID, got, stored[c.ID].Reason, live[c.ControlID])
				}
			}
			for control, want := range sc.want {
				if live[control] != want {
					t.Errorf("%s: live %s, want %s", control, live[control], want)
				}
			}

			var rollup struct {
				Score       *int `db:"score"`
				Passing     int  `db:"controls_passing"`
				Failing     int  `db:"controls_failing"`
				NotAssessed int  `db:"controls_not_assessed"`
			}
			if err := f.db.Get(&rollup, `SELECT score, controls_passing, controls_failing, controls_not_assessed
				FROM tenant_framework_scores WHERE tenant_id = $1 AND platform_framework_id = $2`,
				tenant, frameworkID); err != nil {
				t.Fatalf("read rollup: %v", err)
			}
			if fmtScore(rollup.Score) != fmtScore(liveScore.Score) ||
				rollup.Passing != liveScore.Passing || rollup.Failing != liveScore.Failing ||
				rollup.NotAssessed != liveScore.NotAssessed {
				t.Errorf("framework: stored %s (%d pass / %d fail / %d not assessed), live %s (%d / %d / %d)",
					fmtScore(rollup.Score), rollup.Passing, rollup.Failing, rollup.NotAssessed,
					fmtScore(liveScore.Score), liveScore.Passing, liveScore.Failing, liveScore.NotAssessed)
			}
		})
	}
}

func fmtScore(s *int) string {
	if s == nil {
		return "no score"
	}
	return strconv.Itoa(*s)
}

func (f *inventoryFrameworkFixture) hygieneControls(t *testing.T, frameworkID uuid.UUID) []models.Control {
	t.Helper()
	var controls []models.Control
	if err := f.db.Select(&controls, `
		SELECT id, control_id, baseline_severity FROM platform_framework_controls
		WHERE framework_id = $1 ORDER BY control_id`, frameworkID); err != nil {
		t.Fatalf("load hygiene controls: %v", err)
	}
	if len(controls) < 15 {
		t.Fatalf("inventory-hygiene has %d controls; the seed lost some", len(controls))
	}
	return controls
}

// seedPopulationAssets writes each asset with exactly the record the scenario
// names, marks every one assessed by the hygiene producer (so the producer gate
// is never what decides — only the population is), and opens the named
// hygiene findings against it.
func (f *inventoryFrameworkFixture) seedPopulationAssets(t *testing.T, tenant uuid.UUID, assets []populationAsset) {
	t.Helper()
	site := testdb.EnsureSite(t, f.db, tenant, "DC-"+uuid.NewString()[:8])
	rack := uuid.New()
	if _, err := f.db.Exec(`INSERT INTO racks (id, tenant_id, name, site_id) VALUES ($1, $2, 'R-01', $3)`,
		rack, tenant, site); err != nil {
		t.Fatalf("seed rack: %v", err)
	}
	for i, a := range assets {
		status := a.status
		if status == "" {
			status = "monitoring"
		}
		var owner, rackID, position, face, warranty any
		if a.owner {
			owner = "ops@example.com"
		}
		if a.racked {
			rackID, position, face = rack, 1+2*i, "front"
		}
		if a.warranty != nil {
			warranty = *a.warranty
		}
		var id uuid.UUID
		if err := f.db.QueryRow(`
			INSERT INTO assets (tenant_id, class_key, class_path, hostname, display_name, asset_status,
				last_seen_at, owner_email, site_id, rack_id, position, face, warranty_end)
			VALUES ($1, 'server', 'hardware.computer.server', $2, $2, $3, now(), $4, $5, $6, $7, $8, $9)
			RETURNING id`,
			tenant, a.name, status, owner, site, rackID, position, face, warranty).Scan(&id); err != nil {
			t.Fatalf("seed asset %s: %v", a.name, err)
		}
		if _, err := f.db.Exec(`INSERT INTO producer_assessments (tenant_id, asset_id, producer)
			VALUES ($1, $2, 'hygiene') ON CONFLICT DO NOTHING`, tenant, id); err != nil {
			t.Fatalf("seed coverage %s: %v", a.name, err)
		}
		for _, kind := range a.findings {
			f.finding(t, tenant, id, "asset", "hygiene", kind)
		}
	}
}
