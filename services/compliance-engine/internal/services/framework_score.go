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

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// Control status values. These travel in API responses and are compared against
// in three services' worth of call sites; they are constants rather than string
// literals because a lowercase literal comparison against these UPPERCASE values
// is exactly how the multi-framework endpoint came to report 0 passing / 0
// failing controls forever.
const (
	statusPass = "PASS"
	statusWarn = "WARN"
	statusFail = "FAIL"
)

// controlOutcome is one control's contribution to a framework score.
type controlOutcome struct {
	// BaselineSeverity drives the weight (Critical=4x … Low=1x).
	BaselineSeverity string
	// Status is one of statusPass / statusWarn / statusFail.
	Status string
}

// frameworkScore folds control outcomes into the canonical severity-weighted
// framework score plus the control counts that accompany it.
//
// Only statusPass earns weight. statusWarn earns none — that is the live path's
// long-standing behaviour (its passWeight accumulator only ever credited PASS),
// and it is why `passing + failing == total` here: for scoring purposes a control
// either fully counts or does not, so "failing" is the complement of passing
// rather than the strict FAIL count. Callers that need the strict FAIL count
// (e.g. KPISummary.FailingControls) count it themselves.
//
// A framework with no controls scores 100: there is nothing to violate.
func frameworkScore(outcomes []controlOutcome) (score, total, passing, failing int) {
	total = len(outcomes)
	if total == 0 {
		return 100, 0, 0, 0
	}
	var totalWeight, passWeight int
	for _, o := range outcomes {
		w := severityToWeight(o.BaselineSeverity)
		totalWeight += w
		if o.Status == statusPass {
			passing++
			passWeight += w
		}
	}
	failing = total - passing
	if totalWeight > 0 {
		score = (passWeight * 100) / totalWeight
	}
	return score, total, passing, failing
}

// statusForWorstSeverity maps a control's worst ACTIVE finding severity to the
// control's status. Shared by the live path (calculateControlStatus, which folds
// findings in memory) and the materialized path (loadControlStatuses, which folds
// them in SQL) so the two cannot drift.
//
// An empty severity means "no findings" — a clean pass.
func statusForWorstSeverity(worst string) string {
	switch worst {
	case "Critical", "High":
		return statusFail
	case "Med":
		return statusWarn
	default:
		return statusPass
	}
}

// severityRankSQL ranks finding severity inside SQL so a single grouped query can
// return each control's worst ACTIVE severity. Kept next to severityToWeight and
// statusForWorstSeverity so the three orderings stay visibly in step.
const severityRankSQL = `CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Med' THEN 2 ELSE 1 END`

// loadControlStatuses returns the status of each given control derived from the
// tenant's MATERIALIZED findings — one grouped query, not a count per control.
//
// It applies the same two filters the live path's getFindingsForControl applies:
// detection_state = 'ACTIVE', and SUPPRESSED findings excluded. Omitting the
// suppression filter was the second half of the score divergence: an explicitly
// accepted risk still dragged the rollup down while the summary page showed the
// control clean.
//
// Controls with no findings are absent from the query result and default to
// statusPass.
func loadControlStatuses(ctx context.Context, db *sql.DB, tenantID uuid.UUID, controlIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	statuses := make(map[uuid.UUID]string, len(controlIDs))
	for _, id := range controlIDs {
		statuses[id] = statusPass
	}
	if len(controlIDs) == 0 {
		return statuses, nil
	}

	ids := make([]string, len(controlIDs))
	for i, id := range controlIDs {
		ids[i] = id.String()
	}

	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT control_id, MAX(`+severityRankSQL+`) AS worst
			FROM compliance_findings
			WHERE tenant_id = $1
			  AND control_id = ANY($2)
			  AND detection_state = 'ACTIVE'
			  AND (workflow_status <> 'SUPPRESSED' OR workflow_status IS NULL)
			GROUP BY control_id
		`, tenantID, pq.Array(ids))
		if err != nil {
			return fmt.Errorf("load control statuses: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var controlID uuid.UUID
			var worst int
			if err := rows.Scan(&controlID, &worst); err != nil {
				return fmt.Errorf("scan control status: %w", err)
			}
			// severityFromRank (findings_service.go) inverts severityRankSQL.
			statuses[controlID] = statusForWorstSeverity(severityFromRank(worst))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return statuses, nil
}
