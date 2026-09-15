package services

// "Could this control's measurements have read anything?", per measurement
// SHAPE — fact 3 of loadControlAssessments.
//
// The materialized scoring path never runs an extraction (that is the whole
// point of it), so it cannot know that a particular measurement found nothing.
// What it CAN know cheaply is whether the tables that measurement's shape reads
// hold anything for this tenant at all, and that is a sound superset: if the
// shape's own FROM/WHERE can yield no row, the extraction certainly found
// nothing and the control was not assessed.
//
// Each probe here mirrors one entry of `measurementShapes` in
// measurement_shapes.go — its `From` and its `Base` predicates, minus the
// per-subject `$2` filter, which narrows a tenant-wide question to one subject
// and has no place in it. Keeping them in step is the whole contract:
//
//   - a probe LOOSER than its shape reports PASS over data no extractor can
// read — the bug, and the Lifecycle-scores-100 bug the Gate 3 proof
//     found;
//   - a probe TIGHTER than its shape reports NOT ASSESSED over data an
//     extractor reads perfectly well, which is the same dishonesty pointed the
//     other way and is why `TestScopeProbe_MirrorsItsShape` exists.
//
// The parameterised shapes (`fact`, `finding`) get one probe per distinct fact
// key / producer, because "does this tenant have ANY fact" is not the question
// — `eol.os.date` and `os.name` are different answers and LC-001 depends on the
// first.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// scopeProbeKey identifies one probe: a shape, plus the shape's own parameter
// where it has one (the fact key, the producer). The zero value is the
// fail-open probe — see [scopeProbeFor].
type scopeProbeKey struct {
	Shape string
	Arg   string
}

// alwaysInScope is the key a measurement gets when nothing here can place it:
// a `measurement_types` row with no registry definition (hand-seeded, or added
// to the catalogue ahead of the generator), or a registry shape with no probe.
//
// It resolves to TRUE, deliberately. An unplaceable measurement is a gap in
// this file's knowledge, not evidence about the tenant, and the honest
// direction for a gap in OUR knowledge is to leave the control's status where
// it was rather than to assert NOT ASSESSED about a measurement that may well
// be reading real rows. The tightening direction is guarded instead by
// TestScopeProbeCoversEveryShape, which fails when a registry shape has no
// probe — so a real shape can never silently fall through to here.
var alwaysInScope = scopeProbeKey{Shape: ""}

// scopeProbes is the SQL per shape. `$1` is the tenant; a probe whose key
// carries an Arg gets it as `$2`.
//
// Mirrors measurementShapes: see the file comment.
var scopeProbes = map[string]string{
	// certificate: `certificates c` with `c.tenant_id = $1`.
	"certificate": `SELECT EXISTS (SELECT 1 FROM certificates c WHERE c.tenant_id = $1)`,

	// crypto_configuration: `crypto_implementations ci JOIN assets na ...`,
	// both deleted_at IS NULL. The endpoint LEFT JOIN is outer, so it cannot
	// remove a row and the probe need not carry it.
	"crypto_configuration": `SELECT EXISTS (
		SELECT 1 FROM crypto_implementations ci
		JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id
		WHERE ci.tenant_id = $1 AND na.tenant_id = $1
		  AND ci.deleted_at IS NULL AND na.deleted_at IS NULL)`,

	// asset: `assets a` with `a.deleted_at IS NULL`.
	"asset": `SELECT EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL)`,

	// fact: `asset_facts af JOIN assets a ...` for ONE key, excluding facts
	// past their expires_at — an expired fact has stopped being an answer, and
	// a probe that counted it would report a control assessable that the
	// extractor finds nothing for.
	"fact": `SELECT EXISTS (
		SELECT 1 FROM asset_facts af
		JOIN assets a ON a.tenant_id = af.tenant_id AND a.id = af.asset_id
		WHERE af.tenant_id = $1 AND a.deleted_at IS NULL AND af.key = $2
		  AND (af.expires_at IS NULL OR af.expires_at > now()))`,

	// finding: `assets a` gated on a completed pass by ONE producer. This is
	// the coverage RECORD (`producer_assessments`), not `assets.risk_assessed_by`
	// — the array is its risk-feeding subset, so gating on it would make every
	// `assessed_by: hygiene` control permanently unassessable.
	"finding": `SELECT EXISTS (
		SELECT 1 FROM assets a
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
		  AND EXISTS (SELECT 1 FROM producer_assessments pa
		              WHERE pa.tenant_id = a.tenant_id AND pa.asset_id = a.id AND pa.producer = $2))`,
}

// scopeProbeFor maps a measurement type code onto the probe its shape needs.
func scopeProbeFor(code string) scopeProbeKey {
	def, ok := MeasurementTypeByCode(code)
	if !ok {
		return alwaysInScope
	}
	if _, ok := scopeProbes[def.Source.Shape]; !ok {
		return alwaysInScope
	}
	switch def.Source.Shape {
	case "fact":
		return scopeProbeKey{Shape: "fact", Arg: def.Source.FactKey}
	case "finding":
		return scopeProbeKey{Shape: "finding", Arg: def.Source.AssessedBy}
	default:
		return scopeProbeKey{Shape: def.Source.Shape}
	}
}

// loadScopeProbes evaluates every distinct probe the given controls need, in
// ONE round trip, and records the answers in `satisfied`.
//
// One query rather than one per probe because this runs inside the reconcile's
// hot path: the distinct probe count is bounded by the registry (five shapes,
// one entry per distinct fact key and producer), so the UNION is small and
// every branch is an EXISTS that stops at the first row.
func loadScopeProbes(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID,
	needs map[uuid.UUID][]scopeProbeKey, satisfied map[scopeProbeKey]bool) error {

	distinct := map[scopeProbeKey]bool{}
	for _, keys := range needs {
		for _, k := range keys {
			if k == alwaysInScope {
				satisfied[k] = true
				continue
			}
			distinct[k] = true
		}
	}
	if len(distinct) == 0 {
		return nil
	}

	ordered := make([]scopeProbeKey, 0, len(distinct))
	for k := range distinct {
		ordered = append(ordered, k)
	}
	// Sorted so the emitted SQL is stable — a query text that changes per call
	// defeats Postgres's plan cache and makes the statement unreadable in a log.
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Shape != ordered[j].Shape {
			return ordered[i].Shape < ordered[j].Shape
		}
		return ordered[i].Arg < ordered[j].Arg
	})

	args := []any{tenantID}
	var branches []string
	for i, k := range ordered {
		probe := scopeProbes[k.Shape]
		if k.Arg != "" {
			args = append(args, k.Arg)
			probe = strings.ReplaceAll(probe, "$2", fmt.Sprintf("$%d", len(args)))
		}
		// The ordinal identifies the row; the key itself never reaches the SQL.
		branches = append(branches, fmt.Sprintf("SELECT %d AS n, (%s) AS ok", i, probe))
	}

	rows, err := tx.QueryContext(ctx, strings.Join(branches, "\nUNION ALL\n"), args...)
	if err != nil {
		return fmt.Errorf("probe measurement scope: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n int
		var ok bool
		if err := rows.Scan(&n, &ok); err != nil {
			return fmt.Errorf("scan measurement scope probe: %w", err)
		}
		if n >= 0 && n < len(ordered) {
			satisfied[ordered[n]] = ok
		}
	}
	return rows.Err()
}

// anySatisfied reports whether at least one of a control's measurements has
// something to read.
//
// A control with no probes at all (its measurements were all unplaceable, or it
// has none) returns false and is handled by the earlier `!measured` arm; the
// distinction matters because the two carry different reasons.
func anySatisfied(keys []scopeProbeKey, satisfied map[scopeProbeKey]bool) bool {
	for _, k := range keys {
		if satisfied[k] {
			return true
		}
	}
	return false
}
