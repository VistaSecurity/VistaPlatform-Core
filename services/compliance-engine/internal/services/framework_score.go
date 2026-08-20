package services

// The ONE framework-scoring model.
//
// Before this file there were two: the live evaluation (EvaluateFramework)
// scored severity-weighted, while the materialized rollup (tenant_framework_scores)
// and the /frameworks/context scorecard scored by flat control count. The same
// tenant+framework therefore reported different numbers depending on which path
// served the page — 20 vs 50 on the fixture in evaluation_integration_test.go.
//
// CLAUDE.md ("Framework Architecture → Weighted scoring") documents the weighted
// model as the product's definition, so the flat paths delegate here rather than
// the other way round. ADR-0014 left "pass-count vs severity-weighted" as an open
// question; this resolves it in favour of the already-documented answer.
//
// Everything that turns control outcomes into a score goes through frameworkScore.
// Adding a fourth caller is fine; recomputing the arithmetic locally is not.
//
// # Control status is derived from violations, never from severity
//
// A control FAILS iff it has at least one ACTIVE, non-SUPPRESSED finding. Severity
// is the control's WEIGHT (severityToWeight) and nothing else — it has no say in
// pass/fail. This is the XCCDF (NIST IR 7275) separation of `result` from
// `severity` from `weight`, and it replaces statusForWorstSeverity, under which a
// violated Low-baseline control reported PASS: cert-expiry-90-day emitted two
// ACTIVE findings and simultaneously reported "score 100, 1/1 controls passing".
//
// # NOT_ASSESSED is a real state, and it is not a pass
//
// Three distinct "we did not check" cases all used to score as a clean pass at
// 100: a control with no measurements configured, an extraction that returned no
// values, and an extraction that errored (the error was discarded by a bare
// `continue`). A half-authored framework, an empty inventory and a broken
// extractor were therefore indistinguishable from genuinely clean — the same trap
// CLAUDE.md already documents for risk scores ("score 0 means NOT ASSESSED, not
// safe"). Not-assessed controls are excluded from BOTH sides of the score
// fraction, matching XCCDF's treatment of notapplicable/notchecked, and when
// NOTHING was assessed the framework has no score at all (nil) rather than 100.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// Control status values. These travel in API responses and are compared against
// in three services' worth of call sites; they are constants rather than string
// literals because a lowercase literal comparison against these UPPERCASE values
// is exactly how the multi-framework endpoint came to report 0 passing / 0
// failing controls forever.
//
// WARN was removed in. It was only ever reachable from a Med-baseline
// severity, earned no score weight, and read to users as "not failing" while
// failing the arithmetic — the same ambiguity the severity-derived status had.
const (
	statusPass        = "PASS"
	statusFail        = "FAIL"
	statusNotAssessed = "NOT_ASSESSED"
)

// Machine-readable reasons a control was not assessed. One user-facing bucket
// ("Not assessed"), three reasons, because an operator debugging a framework
// needs to tell a half-authored control apart from an empty inventory apart from
// a broken extractor (spec D2).
const (
	reasonNoMeasurements = "no_measurements"  // no measurements configured on the control
	reasonNothingInScope = "nothing_in_scope" // measurement extraction produced no values
	reasonCheckError     = "check_error"      // extraction failed; logged and counted, never silent
	reasonNotEvaluated   = "not_evaluated"    // control changed since the tenant's last evaluation of it
)

// controlAssessment is one control's outcome plus, when it was NOT assessed, why.
type controlAssessment struct {
	Status string // statusPass / statusFail / statusNotAssessed
	Reason string // "" unless Status == statusNotAssessed
}

// controlOutcome is one control's contribution to a framework score.
type controlOutcome struct {
	// BaselineSeverity drives the weight (Critical=4x … Low=1x).
	BaselineSeverity string
	// Status is one of statusPass / statusFail / statusNotAssessed.
	Status string
}

// scoreBreakdown is a framework's score plus the control tally behind it.
//
// Score is a POINTER because "no score" is a real answer: when no control was
// assessed there is nothing to average, and any sentinel integer would be read as
// a posture claim. nil renders as "—".
//
// Passing + Failing + NotAssessed == Total. Passing + Failing is the ASSESSED
// subset, and the score's denominator.
type scoreBreakdown struct {
	Score       *int
	Total       int
	Passing     int
	Failing     int
	NotAssessed int
}

// frameworkScore folds control outcomes into the canonical severity-weighted
// framework score plus the control counts that accompany it.
//
// Not-assessed controls are excluded from BOTH the numerator and the denominator
// (XCCDF's flat model scores over the *applicable* rules). Including them as
// failures would punish a tenant for an empty inventory; including them as passes
// is the bug this replaces.
//
// A framework with no ASSESSED controls — including one with no controls at all —
// has no score. It used to return 100, which is the loudest possible way of
// saying "we did not look".
func frameworkScore(outcomes []controlOutcome) scoreBreakdown {
	b := scoreBreakdown{Total: len(outcomes)}
	var totalWeight, passWeight int
	for _, o := range outcomes {
		if o.Status == statusNotAssessed {
			b.NotAssessed++
			continue
		}
		w := severityToWeight(o.BaselineSeverity)
		totalWeight += w
		if o.Status == statusPass {
			b.Passing++
			passWeight += w
		} else {
			b.Failing++
		}
	}
	if totalWeight == 0 {
		return b // nothing assessed → no score
	}
	score := (passWeight * 100) / totalWeight
	b.Score = &score
	return b
}

// statusForFindings is the whole of the pass/fail rule: a control FAILS iff it
// was violated. Shared by the live path (calculateControlStatus, which folds
// findings in memory), the materialized path (loadControlAssessments, which folds
// them in SQL) and the rule evaluator (which counts the violations it just
// produced), so the three cannot drift.
func statusForFindings(hasFindings bool) string {
	if hasFindings {
		return statusFail
	}
	return statusPass
}

// loadControlAssessments returns each given control's status — and, when it was
// not assessed, why — derived from the tenant's MATERIALIZED state.
//
// Three DB facts, one transaction:
//
//  1. Does the control have an ACTIVE, non-SUPPRESSED finding? (→ FAIL, and proof
//     it WAS assessed.) Omitting the suppression filter was half of an earlier
//     score divergence: an explicitly accepted risk still dragged the rollup down
//     while the summary page showed the control clean.
//  2. Does the control have any measurements configured? (→ reasonNoMeasurements.)
//  3. Does the tenant have ANY inventory a measurement could read? (→
//     reasonNothingInScope.)
//
// Fact 3 deserves its own note, because it is an implication rather than a
// measurement. Every extractor in measurement_extractor.go reads from
// crypto_implementations or certificates (network_assets appears only as a JOIN),
// so an empty pair means every extraction returns zero values and NOTHING can be
// in scope. It is sound but incomplete: it cannot see a control whose particular
// measurement finds nothing on a tenant that does have other inventory. The
// deliberate direction of that incompleteness is towards today's behaviour (PASS),
// never towards a false "not assessed", and the check is intentionally NOT
// filtered by deleted_at so it stays a superset of what extractors can see.
//
// # Fact 4: a configured measurement is not an evaluation (B-08)
//
// Facts 1–3 still let a control that has NEVER BEEN EVALUATED report PASS: having
// a measurement row plus a tenant with any inventory was enough. So a platform
// admin adding a Critical control to the already-published Best Practices
// framework instantly RAISED every tenant's score — weight 4 added to both sides
// of the fraction as a free pass, for a control nothing had ever run. Tightening
// a threshold was the same shape: the stored rollup did not move, and the number
// it showed was a claim about the OLD predicate.
//
// The fourth fact closes it without a schema change: compare the control's
// evaluable content against tenant_framework_scores.computed_at, which the
// reconcile stamps for this (tenant, framework) every time it folds the framework.
// If the content is newer than the last fold, this tenant has not been evaluated
// against it and we say so.
//
// It FAILS OPEN when there is no rollup row at all. "Never folded" is not the same
// claim as "folded before this control existed", and a tenant with no rollup is
// already covered by fact 3 in the case that matters (no inventory → nothing in
// scope). Treating a missing row as staleness would put every control of every
// framework into NOT_ASSESSED on any install whose rollups have not been written
// yet — a far bigger and less defensible move than the one bug being closed.
//
// "Evaluable content" is deliberately `GREATEST(control.created_at,
// MAX(measurement.updated_at))` and NOT control.updated_at:
//
//   - created_at answers "is this control new?" and never moves afterwards.
//   - measurement.updated_at answers "did a predicate/threshold change?" — the
//     trigger update_control_measurements_updated_at maintains it.
//   - control.updated_at is unusable here because seed.sql re-runs on EVERY helm
//     upgrade and its `ON CONFLICT ... DO UPDATE SET ..., updated_at = NOW()`
//     bumps every seeded control's updated_at. Keying on it would flip every
//     framework on every install to NOT_ASSESSED (score "—") until the next
//     reconcile, for an edit that changed only a title. Titles and descriptions
//     are not evaluable content; baseline_severity is the control's WEIGHT, not
//     its verdict.
//
// The check is scoped to PLATFORM frameworks, because tenant_framework_scores is
// keyed by platform_framework_id and the reconcile evaluates published platform
// frameworks only. Applying it to tenant-authored custom policies would flip all
// of them to NOT_ASSESSED — arguably honest, but a much larger change than this
// one, and it belongs with the separate decision about making custom policies
// evaluate at all.
//
// Note the ordering in the switch below: a violation (fact 1) still wins, because
// a stored finding is itself proof the control was evaluated. The new fact can
// only move a would-be PASS to NOT_ASSESSED — never to FAIL, and never the other
// way.
//
// The remaining gap — per-control emptiness and extraction errors — is only
// observable where extraction actually runs, i.e. the rule evaluator, which
// reports both (see evaluateControlCached). Closing it in the materialized path
// would mean persisting per-control assessment state; that is a schema-shaped
// follow-up, not something to fake here.
func loadControlAssessments(ctx context.Context, db *sql.DB, tenantID uuid.UUID, controlIDs []uuid.UUID, frameworkType string) (map[uuid.UUID]controlAssessment, error) {
	return loadControlAssessmentsAt(ctx, db, tenantID, controlIDs, frameworkType, time.Time{})
}

// loadControlAssessmentsAt is loadControlAssessments for a caller that has JUST
// evaluated these controls and has not yet stamped the rollup.
//
// Without it fact 4 is self-defeating: recomputeFrameworkScore folds the findings
// the reconcile just wrote, but tenant_framework_scores.computed_at still holds
// the PREVIOUS fold's timestamp at that moment, so a control the reconcile had
// genuinely just evaluated would be recorded as not-evaluated and only come right
// on the following pass. evaluatedAt is that in-flight evaluation's instant; the
// zero value means "no evaluation in flight; judge by the stored rollup alone",
// which is what every read path passes.
func loadControlAssessmentsAt(ctx context.Context, db *sql.DB, tenantID uuid.UUID, controlIDs []uuid.UUID, frameworkType string, evaluatedAt time.Time) (map[uuid.UUID]controlAssessment, error) {
	assessments := make(map[uuid.UUID]controlAssessment, len(controlIDs))
	if len(controlIDs) == 0 {
		return assessments, nil
	}
	if frameworkType == "" {
		frameworkType = "platform"
	}

	ids := make([]string, len(controlIDs))
	for i, id := range controlIDs {
		ids[i] = id.String()
	}

	violated := make(map[uuid.UUID]bool, len(controlIDs))
	measured := make(map[uuid.UUID]bool, len(controlIDs))
	unevaluated := make(map[uuid.UUID]bool, len(controlIDs))
	var hasInventory bool

	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT control_id
			FROM compliance_findings
			WHERE tenant_id = $1
			  AND control_id = ANY($2)
			  AND detection_state = 'ACTIVE'
			  AND (workflow_status <> 'SUPPRESSED' OR workflow_status IS NULL)
		`, tenantID, pq.Array(ids))
		if err != nil {
			return fmt.Errorf("load violated controls: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var controlID uuid.UUID
			if err := rows.Scan(&controlID); err != nil {
				return fmt.Errorf("scan violated control: %w", err)
			}
			violated[controlID] = true
		}
		if err := rows.Err(); err != nil {
			return err
		}

		mrows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT control_id
			FROM control_measurements
			WHERE control_id = ANY($1) AND framework_type = $2
		`, pq.Array(ids), frameworkType)
		if err != nil {
			return fmt.Errorf("load configured measurements: %w", err)
		}
		defer func() { _ = mrows.Close() }()
		for mrows.Next() {
			var controlID uuid.UUID
			if err := mrows.Scan(&controlID); err != nil {
				return fmt.Errorf("scan configured measurement: %w", err)
			}
			measured[controlID] = true
		}
		if err := mrows.Err(); err != nil {
			return err
		}

		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
					SELECT 1
					FROM crypto_implementations ci
					JOIN network_assets na ON na.id = ci.asset_id
					WHERE ci.tenant_id = $1
						AND na.tenant_id = $1
						AND ci.deleted_at IS NULL
						AND na.deleted_at IS NULL
				)
			    OR EXISTS (SELECT 1 FROM certificates WHERE tenant_id = $1)
		`, tenantID).Scan(&hasInventory); err != nil {
			return err
		}

		// Fact 4 — platform frameworks only (see the doc comment). 'epoch' floors
		// the nullable timestamps so a NULL never silently wins a comparison.
		if frameworkType != "platform" {
			return nil
		}
		urows, err := tx.QueryContext(ctx, `
			SELECT pfc.id
			FROM platform_framework_controls pfc
			LEFT JOIN control_measurements cm
			  ON cm.control_id = pfc.id AND cm.framework_type = 'platform'
			LEFT JOIN tenant_framework_scores tfs
			  ON tfs.platform_framework_id = pfc.framework_id AND tfs.tenant_id = $1
			WHERE pfc.id = ANY($2)
			GROUP BY pfc.id, pfc.created_at, tfs.computed_at
			HAVING tfs.computed_at IS NOT NULL
			   AND GREATEST(tfs.computed_at, $3::timestamptz) < GREATEST(
			         COALESCE(pfc.created_at, 'epoch'::timestamptz),
			         COALESCE(MAX(cm.updated_at), 'epoch'::timestamptz))
		`, tenantID, pq.Array(ids), evaluatedAt)
		if err != nil {
			return fmt.Errorf("load unevaluated controls: %w", err)
		}
		defer func() { _ = urows.Close() }()
		for urows.Next() {
			var controlID uuid.UUID
			if err := urows.Scan(&controlID); err != nil {
				return fmt.Errorf("scan unevaluated control: %w", err)
			}
			unevaluated[controlID] = true
		}
		return urows.Err()
	})
	if err != nil {
		return nil, err
	}

	for _, id := range controlIDs {
		switch {
		case violated[id]:
			// A finding is proof the control was checked, whatever else is true.
			assessments[id] = controlAssessment{Status: statusFail}
		case !measured[id]:
			assessments[id] = controlAssessment{Status: statusNotAssessed, Reason: reasonNoMeasurements}
		case !hasInventory:
			assessments[id] = controlAssessment{Status: statusNotAssessed, Reason: reasonNothingInScope}
		case unevaluated[id]:
			assessments[id] = controlAssessment{Status: statusNotAssessed, Reason: reasonNotEvaluated}
		default:
			assessments[id] = controlAssessment{Status: statusPass}
		}
	}
	return assessments, nil
}

// outcomesFromAssessments pairs each control's baseline severity (its weight)
// with its assessed status, in the caller's control order.
func outcomesFromAssessments[T any](controls []T, id func(T) uuid.UUID, severity func(T) string, assessments map[uuid.UUID]controlAssessment) []controlOutcome {
	outcomes := make([]controlOutcome, 0, len(controls))
	for _, c := range controls {
		a, ok := assessments[id(c)]
		if !ok {
			// An unknown control was never assessed — say so rather than
			// defaulting to PASS, which is the shape of the bug being fixed.
			a = controlAssessment{Status: statusNotAssessed, Reason: reasonNoMeasurements}
		}
		outcomes = append(outcomes, controlOutcome{BaselineSeverity: severity(c), Status: a.Status})
	}
	return outcomes
}
