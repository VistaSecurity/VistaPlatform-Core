package services

// Evaluation engine primitive (ADR-0014: Compliance Evaluation & Materialization Model).
//
// This file holds the compliance evaluation engine primitives.
//
//   - EvaluateAsset (ADR-0015) reconciles ONE asset against every published
//     framework's controls — the per-asset path every asset/cert-change event uses.
//   - EvaluateTenantFrameworks reconciles a whole tenant — used by framework-change
//     and manual re-eval triggers via the reconcile worker.
//
// Both persist findings for EVERY published framework (ADR-0015 supersedes ADR-0014's
// activated-only write gate; drill-down is gated at the read layer) and write a
// per-(tenant, framework) score rollup, so unactivated frameworks show an instant
// preview score. Measurement extraction is shared (extract-once / fold-all).

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// controlAsset is a (control, asset) pair — the unit of reconciliation.
type controlAsset struct {
	ControlID uuid.UUID
	AssetID   uuid.UUID
}

// EvaluationSummary reports what a tenant reconcile did (for logging and tests).
type EvaluationSummary struct {
	FrameworksEvaluated int
	ControlsEvaluated   int
	FindingsActivated   int
	FindingsInactivated int
}

// reconcilePlan diffs the currently-stored ACTIVE (control, asset) findings against
// the newly-computed violation set and returns which pairs to (re)activate and which
// stale ones to mark inactive. Pure function — the heart of the ADR-0014 idempotent
// reconcile, unit-tested without a database. Re-running with the same inputs yields
// the same plan (convergence); a pair that both violates now and is already active is
// still "activated" (upsert is idempotent), and a previously-active pair that no longer
// violates is inactivated exactly once.
func reconcilePlan(storedActive, newViolations map[controlAsset]bool) (toActivate, toInactivate []controlAsset) {
	for ca := range newViolations {
		toActivate = append(toActivate, ca)
	}
	for ca := range storedActive {
		if !newViolations[ca] {
			toInactivate = append(toInactivate, ca)
		}
	}
	return toActivate, toInactivate
}

// buildAssetViolations collapses per-control evaluation results into the violation
// set for a SINGLE asset: one (control, asset) pair per violating control, keeping
// the first finding as the representative carried onto upsert (severity/evidence).
// Pure (no DB) — the asset filter and per-pair dedup are the per-asset reconcile's
// new logic (ADR-0015). The asset filter is defensive: EvaluateControlsBatchForAsset
// already scopes extraction to the asset, but a stray cross-asset finding must never
// leak into another asset's reconcile.
func buildAssetViolations(results map[uuid.UUID]*EvaluationResult, assetID uuid.UUID) (map[controlAsset]bool, map[controlAsset]models.ComplianceFinding) {
	newViolations := map[controlAsset]bool{}
	findingByPair := map[controlAsset]models.ComplianceFinding{}
	for controlID, res := range results {
		if res == nil {
			continue
		}
		for _, f := range res.Findings {
			if f.AssetID != assetID {
				continue
			}
			ca := controlAsset{ControlID: controlID, AssetID: assetID}
			newViolations[ca] = true
			if _, seen := findingByPair[ca]; !seen {
				findingByPair[ca] = f
			}
		}
	}
	return newViolations, findingByPair
}

// activationBatch turns a reconcile plan's activation list into the batched-write input,
// carrying each pair's representative finding (severity / summary / evidence).
func activationBatch(toActivate []controlAsset, findingByPair map[controlAsset]models.ComplianceFinding) []findingUpsert {
	items := make([]findingUpsert, 0, len(toActivate))
	for _, ca := range toActivate {
		f := findingByPair[ca]
		items = append(items, findingUpsert{
			ControlID:      ca.ControlID,
			AssetID:        ca.AssetID,
			Finding:        &f,
			DetectionState: "ACTIVE",
		})
	}
	return items
}

// logFindingWrites reports what a pass actually wrote. `skipped` is the W2-13 signal: on
// a converged tenant it should dominate, because a reconcile that changes nothing should
// cost no row versions.
func logFindingWrites(path string, tenantID uuid.UUID, stats findingWriteStats) {
	if stats.Processed() == 0 && stats.Failed == 0 {
		return
	}
	log.Printf("[EvalEngine] %s finding writes tenant=%s created=%d updated=%d skipped=%d failed=%d",
		path, tenantID, stats.Created, stats.Updated, stats.Skipped, stats.Failed)
}

// EvaluateTenantFrameworks is the evaluation engine primitive. See file header.
func (s *FindingsService) EvaluateTenantFrameworks(ctx context.Context, tenantID uuid.UUID) (*EvaluationSummary, error) {
	summary := &EvaluationSummary{}

	// All published frameworks — evaluated for rollups/preview regardless of activation.
	type pubFramework struct {
		ID uuid.UUID `db:"id"`
	}
	var published []pubFramework
	if err := s.db.SelectContext(ctx, &published, `SELECT id FROM platform_frameworks WHERE status = 'published'`); err != nil {
		return nil, fmt.Errorf("failed to list published frameworks: %w", err)
	}
	if len(published) == 0 {
		return summary, nil
	}

	// ADR-0015: persist findings for EVERY published framework (not only activated).
	// Per-asset reconcile bounds write volume, and score rollups (including unactivated
	// preview scores) derive uniformly from persisted findings. "Detailed drill-down is
	// the reward for activation" is enforced at the read/UI layer, not by withholding
	// the persisted finding.

	// Load controls per framework + a flat list for one shared-extraction batch.
	controlsByFramework := make(map[uuid.UUID][]models.Control, len(published))
	var allControls []models.Control
	for _, fw := range published {
		controls, err := s.evaluationService.getControlsForFramework(fw.ID, models.ScenarioFilters{}, "platform")
		if err != nil {
			log.Printf("[EvalEngine] ERROR: controls for framework %s: %v", fw.ID, err)
			continue
		}
		controlsByFramework[fw.ID] = controls
		allControls = append(allControls, controls...)
	}
	summary.FrameworksEvaluated = len(controlsByFramework)
	summary.ControlsEvaluated = len(allControls)

	// Extract-once / fold-all across every published control.
	results, err := s.ruleEvaluator.EvaluateControlsBatch(tenantID, allControls, "platform")
	if err != nil {
		return nil, fmt.Errorf("batch evaluation failed: %w", err)
	}

	// New violation set across ALL published frameworks (ADR-0015: persist for all).
	// Keep one representative finding per pair to carry severity/evidence on upsert.
	newViolations := map[controlAsset]bool{}
	findingByPair := map[controlAsset]models.ComplianceFinding{}
	for _, controls := range controlsByFramework {
		for _, control := range controls {
			res := results[control.ID]
			if res == nil {
				continue
			}
			for _, f := range res.Findings {
				ca := controlAsset{ControlID: control.ID, AssetID: f.AssetID}
				newViolations[ca] = true
				if _, seen := findingByPair[ca]; !seen {
					findingByPair[ca] = f
				}
			}
		}
	}

	// Currently-stored ACTIVE findings for this tenant.
	storedActive := map[controlAsset]bool{}
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT control_id, asset_id FROM compliance_findings WHERE tenant_id = $1 AND detection_state = 'ACTIVE'`, tenantID)
		if err != nil {
			return fmt.Errorf("failed to load active findings: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var ca controlAsset
			if err := rows.Scan(&ca.ControlID, &ca.AssetID); err == nil {
				storedActive[ca] = true
			}
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}

	toActivate, toInactivate := reconcilePlan(storedActive, newViolations)
	stats := s.upsertFindings(ctx, tenantID, activationBatch(toActivate, findingByPair))
	summary.FindingsActivated = stats.Processed()
	for _, ca := range toInactivate {
		if err := s.markFindingInactive(ctx, tenantID, ca.ControlID, ca.AssetID); err != nil {
			log.Printf("[EvalEngine] mark inactive failed (control=%s asset=%s): %v", ca.ControlID, ca.AssetID, err)
			continue
		}
		summary.FindingsInactivated++
	}
	logFindingWrites("tenant", tenantID, stats)

	// Score rollups for EVERY published framework (preview score for unactivated too),
	// recomputed from the findings just persisted above — the same DB fold the scoped
	// and per-asset paths use. Folding the in-memory `results` here instead would be a
	// second implementation of the scoring model, which is precisely how the rollup
	// and the live evaluation drifted apart in the first place.
	for fwID, controls := range controlsByFramework {
		if err := s.recomputeFrameworkScore(ctx, tenantID, fwID, controls); err != nil {
			log.Printf("[EvalEngine] score rollup failed (framework=%s): %v", fwID, err)
		}
	}

	log.Printf("[EvalEngine] tenant=%s frameworks=%d controls=%d activated=+%d inactivated=%d",
		tenantID, summary.FrameworksEvaluated, summary.ControlsEvaluated, summary.FindingsActivated, summary.FindingsInactivated)
	return summary, nil
}

// EvaluateTenantFrameworkScoped reconciles ONE published framework's findings for a
// tenant, instead of the whole tenant × every published framework ( control-scoped
// fan-out). Used by framework publish and per-tenant activation: those only change the
// controls of the framework being touched, so re-evaluating the rest is wasted work.
//
// Correctness vs. the full path:
//   - Extraction is naturally bounded — the lazy cachedExtractor only pulls the
//     measurement-type codes THIS framework's controls reference, so a cert-only
//     framework never reads tls/asset measurements (the asset-data narrowing the
//     inverse index would give, for free).
//   - Stale-finding inactivation is restricted to THIS framework's controls (the
//     storedActive query is filtered by framework_id), so other frameworks' findings
//     are never touched.
//   - Only this framework's score rollup is refreshed.
//
// Idempotent: re-running converges (reconcilePlan + upsert/inactivate), exactly like
// the full path.
func (s *FindingsService) EvaluateTenantFrameworkScoped(ctx context.Context, tenantID, frameworkID uuid.UUID) (*EvaluationSummary, error) {
	summary := &EvaluationSummary{}

	// Only published frameworks materialize findings (matches the full path's gate).
	var published bool
	if err := s.db.GetContext(ctx, &published,
		`SELECT EXISTS(SELECT 1 FROM platform_frameworks WHERE id = $1 AND status = 'published')`,
		frameworkID); err != nil {
		return nil, fmt.Errorf("check framework %s published: %w", frameworkID, err)
	}
	if !published {
		return summary, nil
	}

	controls, err := s.evaluationService.getControlsForFramework(frameworkID, models.ScenarioFilters{}, "platform")
	if err != nil {
		return nil, fmt.Errorf("controls for framework %s: %w", frameworkID, err)
	}
	if len(controls) == 0 {
		return summary, nil
	}
	summary.FrameworksEvaluated = 1
	summary.ControlsEvaluated = len(controls)

	// Extract-once / fold-all across THIS framework's controls only.
	results, err := s.ruleEvaluator.EvaluateControlsBatch(tenantID, controls, "platform")
	if err != nil {
		return nil, fmt.Errorf("scoped batch evaluation failed: %w", err)
	}

	// New violation set across this framework's controls; keep one representative
	// finding per pair to carry severity/evidence on upsert.
	newViolations := map[controlAsset]bool{}
	findingByPair := map[controlAsset]models.ComplianceFinding{}
	for _, control := range controls {
		res := results[control.ID]
		if res == nil {
			continue
		}
		for _, f := range res.Findings {
			ca := controlAsset{ControlID: control.ID, AssetID: f.AssetID}
			newViolations[ca] = true
			if _, seen := findingByPair[ca]; !seen {
				findingByPair[ca] = f
			}
		}
	}

	// Currently-stored ACTIVE findings RESTRICTED to this framework's controls, so the
	// reconcile never inactivates another framework's findings. compliance_findings.
	// control_id == platform_framework_controls.id, so the subquery scopes precisely.
	storedActive := map[controlAsset]bool{}
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT control_id, asset_id FROM compliance_findings
		  WHERE tenant_id = $1 AND detection_state = 'ACTIVE'
		    AND control_id IN (SELECT id FROM platform_framework_controls WHERE framework_id = $2)`,
			tenantID, frameworkID)
		if err != nil {
			return fmt.Errorf("failed to load active findings for framework: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var ca controlAsset
			if err := rows.Scan(&ca.ControlID, &ca.AssetID); err == nil {
				storedActive[ca] = true
			}
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}

	toActivate, toInactivate := reconcilePlan(storedActive, newViolations)
	stats := s.upsertFindings(ctx, tenantID, activationBatch(toActivate, findingByPair))
	summary.FindingsActivated = stats.Processed()
	for _, ca := range toInactivate {
		if err := s.markFindingInactive(ctx, tenantID, ca.ControlID, ca.AssetID); err != nil {
			log.Printf("[EvalEngine] mark inactive failed (control=%s asset=%s): %v", ca.ControlID, ca.AssetID, err)
			continue
		}
		summary.FindingsInactivated++
	}
	logFindingWrites("scoped", tenantID, stats)

	// Refresh only this framework's score rollup, from persisted findings (DB fold).
	if err := s.recomputeFrameworkScore(ctx, tenantID, frameworkID, controls); err != nil {
		log.Printf("[EvalEngine] score rollup failed (framework=%s): %v", frameworkID, err)
	}

	log.Printf("[EvalEngine] scoped tenant=%s framework=%s controls=%d activated=+%d inactivated=%d",
		tenantID, frameworkID, summary.ControlsEvaluated, summary.FindingsActivated, summary.FindingsInactivated)
	return summary, nil
}

// upsertFrameworkScore writes the per-(tenant, framework) score rollup consumed by
// posture scorecards and the available-framework preview score.
// score is NULLable: a framework with no assessed control has no score, and the
// column carries that honestly rather than storing 0 or 100.
func (s *FindingsService) upsertFrameworkScore(ctx context.Context, tenantID, frameworkID uuid.UUID, b scoreBreakdown) error {
	return shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
		INSERT INTO tenant_framework_scores (tenant_id, platform_framework_id, score, controls_total, controls_passing, controls_failing, controls_not_assessed, computed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, platform_framework_id) DO UPDATE SET
			score = EXCLUDED.score,
			controls_total = EXCLUDED.controls_total,
			controls_passing = EXCLUDED.controls_passing,
			controls_failing = EXCLUDED.controls_failing,
			controls_not_assessed = EXCLUDED.controls_not_assessed,
			computed_at = EXCLUDED.computed_at
	`, tenantID, frameworkID, b.Score, b.Total, b.Passing, b.Failing, b.NotAssessed, time.Now())
		return err
	})
}

// EvaluateAsset reconciles a SINGLE asset's compliance findings against every
// published platform framework's controls, then refreshes the score rollups of
// EVERY published framework (ADR-0015 per-asset reconcile). Bounded to one asset —
// never the tenant cross-product — this is the primitive every asset/cert-change
// event funnels through. Idempotent: re-running converges (reconcilePlan +
// upsert/inactivate).
//
// Rollups deliberately refresh for ALL published frameworks, not only the ones
// whose findings changed: a framework the tenant fully passes never produces a
// finding, so an affected-only refresh left it with no tenant_framework_scores
// row at all and its card showed "—" instead of a preview score. Each refresh is
// one grouped query over already-persisted findings, so the delta is a handful of
// cheap DB folds per asset event, never a re-evaluation.
func (s *FindingsService) EvaluateAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*EvaluationSummary, error) {
	summary := &EvaluationSummary{}

	type pubFramework struct {
		ID uuid.UUID `db:"id"`
	}
	var published []pubFramework
	if err := s.db.SelectContext(ctx, &published, `SELECT id FROM platform_frameworks WHERE status = 'published'`); err != nil {
		return nil, fmt.Errorf("failed to list published frameworks: %w", err)
	}
	if len(published) == 0 {
		return summary, nil
	}

	// Controls per framework + a flat list for one shared-extraction batch.
	controlsByFramework := make(map[uuid.UUID][]models.Control, len(published))
	var allControls []models.Control
	for _, fw := range published {
		controls, err := s.evaluationService.getControlsForFramework(fw.ID, models.ScenarioFilters{}, "platform")
		if err != nil {
			log.Printf("[EvalEngine] ERROR: controls for framework %s: %v", fw.ID, err)
			continue
		}
		controlsByFramework[fw.ID] = controls
		allControls = append(allControls, controls...)
	}
	summary.FrameworksEvaluated = len(controlsByFramework)
	summary.ControlsEvaluated = len(allControls)

	// Extract THIS asset's measurement values once; fold all controls over them.
	results, err := s.ruleEvaluator.EvaluateControlsBatchForAsset(tenantID, assetID, allControls, "platform")
	if err != nil {
		return nil, fmt.Errorf("per-asset evaluation failed: %w", err)
	}

	// New violation set for THIS asset across all published controls.
	newViolations, findingByPair := buildAssetViolations(results, assetID)

	// Currently-stored ACTIVE findings for THIS asset only.
	storedActive := map[controlAsset]bool{}
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT control_id FROM compliance_findings WHERE tenant_id = $1 AND asset_id = $2 AND detection_state = 'ACTIVE'`, tenantID, assetID)
		if err != nil {
			return fmt.Errorf("failed to load active findings for asset: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			ca := controlAsset{AssetID: assetID}
			if err := rows.Scan(&ca.ControlID); err == nil {
				storedActive[ca] = true
			}
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}

	toActivate, toInactivate := reconcilePlan(storedActive, newViolations)
	stats := s.upsertFindings(ctx, tenantID, activationBatch(toActivate, findingByPair))
	summary.FindingsActivated = stats.Processed()
	for _, ca := range toInactivate {
		if err := s.markFindingInactive(ctx, tenantID, ca.ControlID, ca.AssetID); err != nil {
			log.Printf("[EvalEngine] mark inactive failed (control=%s asset=%s): %v", ca.ControlID, ca.AssetID, err)
			continue
		}
		summary.FindingsInactivated++
	}
	logFindingWrites("per-asset", tenantID, stats)

	// Refresh score rollups for EVERY published framework from PERSISTED findings (a DB
	// fold, not a re-evaluation) — see the doc comment for why not affected-only.
	for fwID, controls := range controlsByFramework {
		if err := s.recomputeFrameworkScore(ctx, tenantID, fwID, controls); err != nil {
			log.Printf("[EvalEngine] score rollup failed (framework=%s): %v", fwID, err)
		}
	}

	log.Printf("[EvalEngine] per-asset tenant=%s asset=%s controls=%d activated=+%d inactivated=%d frameworks=%d",
		tenantID, assetID, summary.ControlsEvaluated, summary.FindingsActivated, summary.FindingsInactivated, len(controlsByFramework))
	return summary, nil
}

// recomputeFrameworkScore rebuilds the per-(tenant, framework) rollup from the
// materialized findings. A bounded DB fold over compliance_findings (one grouped
// query over the affected framework's controls), not a re-evaluation of inventory.
//
// The arithmetic is frameworkScore's — the same severity-weighted model the live
// evaluation uses — so the rollup and the summary page can no longer report two
// different numbers for the same tenant+framework. Control status comes from the
// worst ACTIVE, non-suppressed finding, again matching the live path.
func (s *FindingsService) recomputeFrameworkScore(ctx context.Context, tenantID, frameworkID uuid.UUID, controls []models.Control) error {
	if len(controls) == 0 {
		// A framework with no controls has nothing to assess: no score, not 100.
		return s.upsertFrameworkScore(ctx, tenantID, frameworkID, scoreBreakdown{})
	}
	controlIDs := make([]uuid.UUID, len(controls))
	for i, c := range controls {
		controlIDs[i] = c.ID
	}
	assessments, err := loadControlAssessments(ctx, s.db.DB, tenantID, controlIDs, "platform")
	if err != nil {
		return err
	}
	outcomes := outcomesFromAssessments(controls,
		func(c models.Control) uuid.UUID { return c.ID },
		func(c models.Control) string { return c.BaselineSeverity },
		assessments)
	return s.upsertFrameworkScore(ctx, tenantID, frameworkID, frameworkScore(outcomes))
}
