package services

// "Could this control's measurements have read anything?" — fact 3 of
// loadControlAssessments, asked per MEASUREMENT TYPE against that row's own
// population.
//
// The materialized scoring path never runs an extraction (that is the whole
// point of it), so it cannot know which values a measurement found. What it CAN
// know cheaply is whether the measurement's POPULATION — the subjects a control
// over it is about — holds anything for this tenant at all. If it does not, the
// live evaluator finds no value to judge and reports the control NOT ASSESSED,
// and the stored score must say the same.
//
// # One population rule, shared with the live evaluator
//
// The probe is not written here. It is measurementPlan.populationSQL, built in
// buildMeasurementPlan from the SAME measurementPopulation string as the
// extraction statement the live evaluator runs: the shape's FROM and base
// predicates, the row's `subject_where`, and (outside the finding shape) its
// `where`. A change to who is in scope therefore moves both paths at once.
//
// It used to be a hand-written probe per SHAPE, which asked a coarser question
// than the extractor: "did the hygiene producer assess ANY asset" for every
// `finding`-shape row, "does the tenant have ANY live asset" for every `asset`
// row. A rack-position control therefore passed in tenant_framework_scores on an
// estate with no racks, a warranty control on an estate with no warranty dates,
// and Inventory Hygiene scored 73 on the Gate 3 estate while the live evaluator
// read eight of its controls NOT ASSESSED (the honest rollup is 25). An empty
// inventory scored higher than a populated one.
//
// The probe is a SUPERSET of the extraction only where extraction runs Go code
// the database cannot: a row filter, or a transform that rejects a non-NULL
// value (see populationProbeSQL). Everything SQL decides, it decides the same.

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// scopeProbeKey identifies one probe: the measurement type code whose
// population it asks about. The zero value is the fail-open probe — see
// [scopeProbeFor].
type scopeProbeKey struct {
	Code string
}

// alwaysInScope is the key a measurement gets when nothing here can place it:
// a `measurement_types` row with no registry definition (hand-seeded, or added
// to the catalogue ahead of the generator), or a registry row that does not
// compile.
//
// It resolves to TRUE, deliberately. An unplaceable measurement is a gap in
// this file's knowledge, not evidence about the tenant, and the honest
// direction for a gap in OUR knowledge is to leave the control's status where
// it was rather than to assert NOT ASSESSED about a measurement that may well
// be reading real rows. The shipped registry has no such row —
// TestMeasurementRegistryCompiles and TestScopeProbeForEveryRegistryMeasurement
// fail otherwise — so in production only hand-seeded types reach here.
var alwaysInScope = scopeProbeKey{}

// populationPlans is the shipped registry, compiled once for the probes. The
// registry is generated code and never changes at run time, so unlike the
// catalogue endpoint there is nothing a cache could serve stale.
var populationPlans = sync.OnceValue(func() map[string]*measurementPlan {
	plans, _ := compileMeasurementRegistry(measurementTypeRegistry)
	return plans
})

// scopeProbeFor maps a measurement type code onto its population probe.
func scopeProbeFor(code string) scopeProbeKey {
	if _, ok := populationPlans()[code]; !ok {
		return alwaysInScope
	}
	return scopeProbeKey{Code: code}
}

// placeholder matches a bind parameter. Every `$` in a plan's SQL is one: the
// shapes' text carries no other, and the query compiler emits values as
// parameters, never as literals.
var placeholder = regexp.MustCompile(`\$(\d+)`)

// rebaseParams renumbers every `$n` in a statement to `$n+offset`, so several
// plans — each numbered from $1 — can share one round trip.
func rebaseParams(stmt string, offset int) string {
	if offset == 0 {
		return stmt
	}
	return placeholder.ReplaceAllStringFunc(stmt, func(m string) string {
		n, err := strconv.Atoi(m[1:])
		if err != nil {
			return m // unreachable: the pattern only matches digits
		}
		return "$" + strconv.Itoa(n+offset)
	})
}

// populationArgs are a plan's bind parameters for a TENANT-WIDE run: tenant,
// a NULL single-subject filter, then the shape's and the predicates' own.
// The same order extract() binds them in.
func populationArgs(plan *measurementPlan, tenantID uuid.UUID) []any {
	args := append([]any{tenantID, nil}, plan.extraArgs...)
	return append(args, plan.predArgs...)
}

// loadScopeProbes evaluates every distinct probe the given controls need, in
// ONE round trip, and records the answers in `satisfied`.
//
// One query rather than one per probe because this runs inside the reconcile's
// hot path. Each branch is an EXISTS that stops at the first row; the distinct
// probe count is bounded by the registry.
func loadScopeProbes(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID,
	needs map[uuid.UUID][]scopeProbeKey, satisfied map[scopeProbeKey]bool) error {

	plans := populationPlans()
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
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Code < ordered[j].Code })

	var args []any
	var branches []string
	for i, k := range ordered {
		plan := plans[k.Code]
		probe := rebaseParams(plan.populationSQL, len(args))
		args = append(args, populationArgs(plan, tenantID)...)
		// The ordinal identifies the row; the code itself never reaches the SQL.
		branches = append(branches, fmt.Sprintf("SELECT %d AS n, (%s) AS ok", i, probe))
	}

	rows, err := tx.QueryContext(ctx, strings.Join(branches, "\nUNION ALL\n"), args...)
	if err != nil {
		return fmt.Errorf("probe measurement population: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n int
		var ok bool
		if err := rows.Scan(&n, &ok); err != nil {
			return fmt.Errorf("scan measurement population probe: %w", err)
		}
		if n >= 0 && n < len(ordered) {
			satisfied[ordered[n]] = ok
		}
	}
	return rows.Err()
}

// anySatisfied reports whether at least one of a control's measurements has
// something in its population to judge.
//
// A control with no probes at all (it has no measurements) returns false and
// is handled by the earlier `!measured` arm; the distinction matters because
// the two carry different reasons.
func anySatisfied(keys []scopeProbeKey, satisfied map[scopeProbeKey]bool) bool {
	for _, k := range keys {
		if satisfied[k] {
			return true
		}
	}
	return false
}
