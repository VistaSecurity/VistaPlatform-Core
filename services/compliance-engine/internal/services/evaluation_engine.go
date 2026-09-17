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
//
// KNOWN GAP (audit finding B-05,: despite its name,
// EvaluateTenantFrameworks never touches tenant-authored frameworks
// (`tenant_frameworks`, i.e. Custom Policies) — every call below to
// getControlsForFramework / EvaluateControlsBatch(ForAsset) passes the
// literal "platform", and this file has no "tenant" call path at all. It
// only walks `platform_frameworks WHERE status = 'published'`. Custom
// policies are therefore never scored and never produce a finding, for any
// tenant. Compounding it, tenant_framework_scores' primary key is
// (tenant_id, platform_framework_id) — there is no row shape a
// custom-policy score could occupy without a schema change.
// The frontend-v2 authoring UI is gated off pending the real fix (do not
// re-enable it without this file changing too). for the full
// evidence and what the real fix needs — it is a spec-first change, not a
// literal swap.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// controlSubject is a (control, subject) pair — the unit of reconciliation.
//
// The subject is whatever the measurement was taken on: an asset or a
// certificate (workstream 3.1 / ADR-0005 D3). It was called controlAsset while
// the row it wrote was called compliance_findings.asset_id, and on a live
// tenant about three in four of those ids were a certificate's.
type controlSubject struct {
	ControlID uuid.UUID
	SubjectID uuid.UUID
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
func reconcilePlan(storedActive, newViolations map[controlSubject]bool) (toActivate, toInactivate []controlSubject) {
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
func buildAssetViolations(results map[uuid.UUID]*EvaluationResult, assetID uuid.UUID) (map[controlSubject]bool, map[controlSubject]models.ComplianceFinding) {
	newViolations := map[controlSubject]bool{}
	findingByPair := map[controlSubject]models.ComplianceFinding{}
	for controlID, res := range results {
		if res == nil {
			continue
		}
		for _, f := range res.Findings {
			if f.SubjectID != assetID {
				continue
			}
			ca := controlSubject{ControlID: controlID, SubjectID: assetID}
			newViolations[ca] = true
			if prior, seen := findingByPair[ca]; !seen {
				findingByPair[ca] = f
			} else {
				mergeSubjectEvidence(&prior, &f)
				findingByPair[ca] = prior
			}
		}
	}
	return newViolations, findingByPair
}

// activationBatch turns a reconcile plan's activation list into the batched-write input,
// carrying each pair's representative finding (severity / summary / evidence).
func activationBatch(toActivate []controlSubject, findingByPair map[controlSubject]models.ComplianceFinding) []findingUpsert {
	items := make([]findingUpsert, 0, len(toActivate))
	for _, ca := range toActivate {
		f := findingByPair[ca]
		items = append(items, findingUpsert{
			ControlID:      ca.ControlID,
			SubjectID:      ca.SubjectID,
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
	// NOTE: `published` above is queried from platform_frameworks only, and every
	// "platform" literal in this file (here and below) is why — see the file
	// header (B-05 /). Custom Policies (tenant_frameworks) are not in
	// `published` and are never enumerated here.
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
	newViolations := map[controlSubject]bool{}
	findingByPair := map[controlSubject]models.ComplianceFinding{}
	for _, controls := range controlsByFramework {
		for _, control := range controls {
			res := results[control.ID]
			if res == nil {
				continue
			}
			for _, f := range res.Findings {
				ca := controlSubject{ControlID: control.ID, SubjectID: f.SubjectID}
				newViolations[ca] = true
				if prior, seen := findingByPair[ca]; !seen {
					findingByPair[ca] = f
				} else {
					mergeSubjectEvidence(&prior, &f)
					findingByPair[ca] = prior
				}
			}
		}
	}

	// Currently-stored ACTIVE findings for this tenant.
	storedActive := map[controlSubject]bool{}
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT control_id, subject_id FROM findings
		  WHERE tenant_id = $1 AND detection_state = 'ACTIVE'
		    AND `+complianceProducerScope("findings"), tenantID)
		if err != nil {
			return fmt.Errorf("failed to load active findings: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var ca controlSubject
			if err := rows.Scan(&ca.ControlID, &ca.SubjectID); err == nil {
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
		if err := s.markFindingInactive(ctx, tenantID, ca.ControlID, ca.SubjectID); err != nil {
			log.Printf("[EvalEngine] mark inactive failed (control=%s subject=%s): %v", ca.ControlID, ca.SubjectID, err)
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
	newViolations := map[controlSubject]bool{}
	findingByPair := map[controlSubject]models.ComplianceFinding{}
	for _, control := range controls {
		res := results[control.ID]
		if res == nil {
			continue
		}
		for _, f := range res.Findings {
			ca := controlSubject{ControlID: control.ID, SubjectID: f.SubjectID}
			newViolations[ca] = true
			if prior, seen := findingByPair[ca]; !seen {
				findingByPair[ca] = f
			} else {
				mergeSubjectEvidence(&prior, &f)
				findingByPair[ca] = prior
			}
		}
	}

	// Currently-stored ACTIVE findings RESTRICTED to this framework's controls, so the
	// reconcile never inactivates another framework's findings. findings.control_id
	// == platform_framework_controls.id, so the subquery scopes precisely.
	storedActive := map[controlSubject]bool{}
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT control_id, subject_id FROM findings
		  WHERE tenant_id = $1 AND detection_state = 'ACTIVE'
		    AND `+complianceProducerScope("findings")+`
		    AND control_id IN (SELECT id FROM platform_framework_controls WHERE framework_id = $2)`,
			tenantID, frameworkID)
		if err != nil {
			return fmt.Errorf("failed to load active findings for framework: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var ca controlSubject
			if err := rows.Scan(&ca.ControlID, &ca.SubjectID); err == nil {
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
		if err := s.markFindingInactive(ctx, tenantID, ca.ControlID, ca.SubjectID); err != nil {
			log.Printf("[EvalEngine] mark inactive failed (control=%s subject=%s): %v", ca.ControlID, ca.SubjectID, err)
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

// EvaluateAsset reconciles an asset's compliance findings against every published
// platform framework's controls, then refreshes the score rollups of EVERY
// published framework (ADR-0015 per-asset reconcile). Bounded — never the tenant
// cross-product — this is the primitive every asset-change event funnels through.
// Idempotent: re-running converges (reconcilePlan + upsert/inactivate).
//
// "An asset" here is the asset AND the certificates bound to it, because a
// certificate is part of the cryptographic surface an asset change moves — the
// same reason OnCertificateChanged fans a certificate out to its assets. Without
// that fan-out the pass was not merely incomplete, it was WRONG: the certificate
// shape's per-subject filter is `c.id = $2`, so handing it an ASSET id matches no
// certificate, every certificate control yields zero measurement values and no
// finding, and the rollup below then reads that absence as PASS (the scope probe
// is tenant-wide, so it confirms the tenant HAS certificates and the control is
// not even recorded as not-assessed). A tenant whose only certificate had 56 days
// of validity left therefore scored 100/100 on "Certificate expires within 90
// days" — a verdict published by a pass that structurally could not have looked
// at the subject it was about.
//
// Rollups deliberately refresh for ALL published frameworks, not only the ones
// whose findings changed: a framework the tenant fully passes never produces a
// finding, so an affected-only refresh left it with no tenant_framework_scores
// row at all and its card showed "—" instead of a preview score. Each refresh is
// one grouped query over already-persisted findings, so the delta is a handful of
// cheap DB folds per asset event, never a re-evaluation. That is exactly why the
// SUBJECT set has to be complete: the fold cannot tell "evaluated and clean" from
// "never looked at".
func (s *FindingsService) EvaluateAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*EvaluationSummary, error) {
	certIDs, err := s.certificatesForAsset(ctx, tenantID, assetID)
	if err != nil {
		// Linkage unknown — fall back to a tenant-wide (coalesced) reconcile rather
		// than publishing certificate verdicts this pass did not compute.
		log.Printf("[EvalEngine] WARN: asset→certificate lookup failed (asset=%s): %v; falling back to tenant reconcile", assetID, err)
		return s.reconcileTenantAfterFanOut(ctx, tenantID, "asset_cert_lookup_failed")
	}
	if len(certIDs) > assetCertFanOutLimit {
		return s.reconcileTenantAfterFanOut(ctx, tenantID, "asset_cert_fan_out_over_limit")
	}
	subjects := append([]uuid.UUID{assetID}, certIDs...)
	return s.evaluateSubjects(ctx, tenantID, subjects, "per-asset")
}

// assetCertFanOutLimit caps how many of an asset's certificates one asset-change
// event reconciles subject-by-subject before falling back to a single (coalesced)
// whole-tenant pass. The mirror of certFanOutLimit, and the same trade: a
// per-subject pass re-extracts that subject's measurements, so past a few dozen
// subjects one shared-extraction tenant pass is the cheaper shape. Well above the
// common case — a host serves a handful of leaf certificates.
const assetCertFanOutLimit = 32

// reconcileTenantAfterFanOut runs the whole-tenant fallback through the coalescer,
// for a per-subject pass that could not bound itself.
func (s *FindingsService) reconcileTenantAfterFanOut(ctx context.Context, tenantID uuid.UUID, reason string) (*EvaluationSummary, error) {
	summary, coalesced, err := s.ReconcileTenantCoalesced(ctx, tenantID, uuid.Nil)
	if err != nil {
		return nil, fmt.Errorf("tenant evaluation failed (%s): %w", reason, err)
	}
	if coalesced {
		log.Printf("[EvalEngine] per-subject reconcile coalesced into an in-flight tenant pass: tenant=%s reason=%s", tenantID, reason)
		return &EvaluationSummary{}, nil
	}
	log.Printf("[EvalEngine] per-subject reconcile escalated to tenant-wide: tenant=%s reason=%s activated=+%d inactivated=%d",
		tenantID, reason, summary.FindingsActivated, summary.FindingsInactivated)
	return summary, nil
}

// evaluateSubjects is the bounded reconcile primitive: it folds every published
// framework's controls over each named SUBJECT (an asset id, a certificate id, or
// a mix of both), reconciles the findings of exactly those subjects, and refreshes
// every published framework's score rollup once at the end.
//
// Subject-scoped, not asset-scoped: stale-finding inactivation is restricted to
// `subject_id = ANY(subjects)`, so a pass can never retire a finding about
// something it did not evaluate.
func (s *FindingsService) evaluateSubjects(ctx context.Context, tenantID uuid.UUID, subjects []uuid.UUID, path string) (*EvaluationSummary, error) {
	summary := &EvaluationSummary{}
	if len(subjects) == 0 {
		return summary, nil
	}

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

	// Extract EACH subject's measurement values once; fold all controls over them.
	newViolations := map[controlSubject]bool{}
	findingByPair := map[controlSubject]models.ComplianceFinding{}
	for _, subject := range subjects {
		results, err := s.ruleEvaluator.EvaluateControlsBatchForAsset(tenantID, subject, allControls, "platform")
		if err != nil {
			return nil, fmt.Errorf("per-subject evaluation failed (subject=%s): %w", subject, err)
		}
		violations, findings := buildAssetViolations(results, subject)
		for ca := range violations {
			newViolations[ca] = true
		}
		for ca, f := range findings {
			if prior, seen := findingByPair[ca]; seen {
				mergeSubjectEvidence(&prior, &f)
				findingByPair[ca] = prior
				continue
			}
			findingByPair[ca] = f
		}
	}

	// Currently-stored ACTIVE findings for THESE subjects only.
	subjectIDs := make([]string, len(subjects))
	for i, id := range subjects {
		subjectIDs[i] = id.String()
	}
	storedActive := map[controlSubject]bool{}
	if err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT control_id, subject_id FROM findings
		  WHERE tenant_id = $1 AND subject_id = ANY($2) AND detection_state = 'ACTIVE'
		    AND `+complianceProducerScope("findings"), tenantID, pq.Array(subjectIDs))
		if err != nil {
			return fmt.Errorf("failed to load active findings for subjects: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var ca controlSubject
			if err := rows.Scan(&ca.ControlID, &ca.SubjectID); err == nil {
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
		if err := s.markFindingInactive(ctx, tenantID, ca.ControlID, ca.SubjectID); err != nil {
			log.Printf("[EvalEngine] mark inactive failed (control=%s subject=%s): %v", ca.ControlID, ca.SubjectID, err)
			continue
		}
		summary.FindingsInactivated++
	}
	logFindingWrites(path, tenantID, stats)

	// Refresh score rollups for EVERY published framework from PERSISTED findings (a DB
	// fold, not a re-evaluation) — see the doc comment for why not affected-only.
	for fwID, controls := range controlsByFramework {
		if err := s.recomputeFrameworkScore(ctx, tenantID, fwID, controls); err != nil {
			log.Printf("[EvalEngine] score rollup failed (framework=%s): %v", fwID, err)
		}
	}

	log.Printf("[EvalEngine] %s tenant=%s subjects=%d controls=%d activated=+%d inactivated=%d frameworks=%d",
		path, tenantID, len(subjects), summary.ControlsEvaluated, summary.FindingsActivated, summary.FindingsInactivated, len(controlsByFramework))
	return summary, nil
}

// recomputeFrameworkScore rebuilds the per-(tenant, framework) rollup from the
// materialized findings. A bounded DB fold over `findings` (one grouped query
// over the affected framework's controls), not a re-evaluation of inventory.
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
	// evaluatedAt = now: this fold runs immediately after the reconcile evaluated
	// these controls, and the rollup timestamp it is about to write does not exist
	// yet. Passing it stops a control the reconcile just checked from being scored
	// as "not evaluated since it changed" for one extra pass.
	assessments, err := loadControlAssessmentsAt(ctx, s.db.DB, tenantID, controlIDs, "platform", time.Now())
	if err != nil {
		return err
	}
	outcomes := outcomesFromAssessments(controls,
		func(c models.Control) uuid.UUID { return c.ID },
		func(c models.Control) string { return c.BaselineSeverity },
		assessments)
	breakdown, err := frameworkScore(outcomes)
	if err != nil {
		return err
	}
	return s.upsertFrameworkScore(ctx, tenantID, frameworkID, breakdown)
}

// certBandReconcileChunk bounds how many certificate subjects one evaluateSubjects
// call carries. Chunking, not a tenant-wide fallback: the per-event fan-out limits
// (certFanOutLimit / assetCertFanOutLimit) exist because an ingest burst fires
// thousands of events, so past a few dozen subjects one shared-extraction tenant
// pass is cheaper. A band scan runs once per interval, and its subject count is
// bounded by "certificates inside the widest compliance band" — for a tenant with
// 10k assets and 300 certificates about to expire, 300 per-subject extractions are
// far cheaper than one pass over every published control × every asset. So the
// large set is split rather than escalated.
//
// Chunking is safe because evaluateSubjects scopes stale-finding inactivation to
// `subject_id = ANY(subjects)`: a chunk can only retire findings about its own
// certificates. Each chunk also refreshes the score rollups, and the rollup is a
// fold over ALREADY-PERSISTED findings, so the last chunk's refresh reflects every
// chunk's writes — the end state does not depend on the chunk boundary.
const certBandReconcileChunk = 64

// ReconcileCertificates reconciles a named set of CERTIFICATE subjects and refreshes
// the score rollups, without an inventory change having occurred.
//
// It is the entry point for time-driven re-evaluation. `cert_expiration_days` is the
// platform's only purely time-dependent measurement — it decreases every day with no
// inventory change — while materialization is otherwise event-driven by design. A
// certificate that crosses a compliance threshold (90 days, 30 days) while nothing
// about it changes raises no event, so without this the stored finding keeps whatever
// verdict the last reconcile computed and tenant_framework_scores keeps reporting it.
//
// Certificates only: passing an asset id here would be a bug, because the `certificate`
// measurement shape filters `c.id = $2` and an asset id matches no certificate — the
// exact shape of, where a pass published a verdict about a subject it had
// structurally never looked at. Callers select subjects from `certificates`.
func (s *FindingsService) ReconcileCertificates(ctx context.Context, tenantID uuid.UUID, certIDs []uuid.UUID, path string) (*EvaluationSummary, error) {
	total := &EvaluationSummary{}
	for start := 0; start < len(certIDs); start += certBandReconcileChunk {
		end := min(start+certBandReconcileChunk, len(certIDs))
		summary, err := s.evaluateSubjects(ctx, tenantID, certIDs[start:end], path)
		if err != nil {
			return nil, fmt.Errorf("certificate reconcile failed (tenant=%s, subjects=%d..%d of %d): %w",
				tenantID, start, end, len(certIDs), err)
		}
		// Frameworks/controls are the same set every chunk; findings accumulate.
		total.FrameworksEvaluated = summary.FrameworksEvaluated
		total.ControlsEvaluated = summary.ControlsEvaluated
		total.FindingsActivated += summary.FindingsActivated
		total.FindingsInactivated += summary.FindingsInactivated
	}
	return total, nil
}
