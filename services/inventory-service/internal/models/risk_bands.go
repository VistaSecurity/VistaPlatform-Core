package models

import (
	"fmt"
	"strings"
)

// Risk severity bands — the single source of truth for turning a 0–100
// risk_score into a qualitative level, in Go and in SQL.
//
// WHY THESE NUMBERS: they are the CVSS v3.1/v4.0 qualitative severity ratings
// (None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0)
// scaled ×10. No standards body publishes a 0–100 score for cryptographic
// configuration — NIST SP 800-57 / SP 800-131A define algorithm *strength* and
// *transition status*, not an endpoint score — so the score's INPUTS are
// standards-anchored while the qualitative banding follows the one published,
// widely-recognized convention for exactly this job. Anchoring to CVSS means the
// bands are citable rather than invented.
//
// Naming note: CVSS calls the zero band "None"; this product has always
// displayed "Informational", so that label is kept. Same band, product wording.
//
// WHY IT IS GENERATED: this ladder used to be hand-copied into eight SQL
// queries plus a Go function, and they drifted — the summary and facet counters
// banded High at >= 70 while every badge banded it at >= 60, so an asset
// scoring 60–69 rendered "High" but was counted "Medium" and was dropped by the
// "High" facet filter. Everything now derives from RiskBands, so a boundary can
// only be changed in one place. TestRiskBands_* pins the Go and SQL forms
// against each other over the whole 0–100 range.
type RiskBand struct {
	// Label is the user-facing level name.
	Label string
	// Min is the inclusive lower bound of the band. The band's upper bound is
	// the next-higher band's Min (exclusive); the top band is unbounded.
	Min int
}

// RiskBands are ordered highest-first. Order is load-bearing: the SQL/Go
// resolution below walks it top-down and takes the first match.
var RiskBands = []RiskBand{
	{Label: "Critical", Min: 90},
	{Label: "High", Min: 70},
	{Label: "Medium", Min: 40},
	{Label: "Low", Min: 1},
	{Label: "Informational", Min: 0},
}

// GetRiskLevel maps a numeric risk score to its qualitative band.
func GetRiskLevel(score int) string {
	for _, b := range RiskBands {
		if score >= b.Min {
			return b.Label
		}
	}
	// Unreachable: the last band has Min 0 and scores are non-negative. Negative
	// input is treated as the lowest band rather than returning "".
	return RiskBands[len(RiskBands)-1].Label
}

// riskBandIndex finds a band by label, case-insensitively.
func riskBandIndex(label string) (int, bool) {
	for i, b := range RiskBands {
		if strings.EqualFold(b.Label, label) {
			return i, true
		}
	}
	return 0, false
}

// RiskLevelCaseSQL renders the band ladder as a SQL CASE expression over expr
// (e.g. "COALESCE(MAX(ci.risk_score), 0)"), yielding the same label
// GetRiskLevel would return for the same value.
//
// expr is interpolated, so it must be a trusted, code-supplied SQL fragment —
// never user input.
func RiskLevelCaseSQL(expr string) string {
	var sb strings.Builder
	sb.WriteString("CASE")
	for _, b := range RiskBands[:len(RiskBands)-1] {
		fmt.Fprintf(&sb, "\n\t\t\t\t\tWHEN %s >= %d THEN '%s'", expr, b.Min, b.Label)
	}
	fmt.Fprintf(&sb, "\n\t\t\t\t\tELSE '%s'\n\t\t\t\tEND", RiskBands[len(RiskBands)-1].Label)
	return sb.String()
}

// RiskBandSQL renders a predicate matching exactly one band — the half-open
// interval [Min, next-higher Min). The top band is unbounded above. Returns
// false for an unknown label so callers can ignore junk filter values.
func RiskBandSQL(expr, label string) (string, bool) {
	i, ok := riskBandIndex(label)
	if !ok {
		return "", false
	}
	if i == 0 {
		return fmt.Sprintf("%s >= %d", expr, RiskBands[i].Min), true
	}
	return fmt.Sprintf("%s >= %d AND %s < %d", expr, RiskBands[i].Min, expr, RiskBands[i-1].Min), true
}

// RiskAtLeastSQL renders a predicate matching a band and everything above it
// ("high and above" includes Critical). Used by surfaces whose filter
// vocabulary is coarser than the five badge levels.
func RiskAtLeastSQL(expr, label string) (string, bool) {
	i, ok := riskBandIndex(label)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s >= %d", expr, RiskBands[i].Min), true
}

// MustRiskBandSQL is RiskBandSQL for callers passing a compile-time-constant
// label. A miss is a programmer typo, not a runtime condition, so it panics
// rather than silently emitting a predicate that matches nothing.
func MustRiskBandSQL(expr, label string) string {
	cond, ok := RiskBandSQL(expr, label)
	if !ok {
		panic(fmt.Sprintf("unknown risk band %q", label))
	}
	return cond
}

// MustRiskAtLeastSQL is RiskAtLeastSQL with the same fail-fast contract.
func MustRiskAtLeastSQL(expr, label string) string {
	cond, ok := RiskAtLeastSQL(expr, label)
	if !ok {
		panic(fmt.Sprintf("unknown risk band %q", label))
	}
	return cond
}

// RiskBandMin returns a band's inclusive lower bound.
func RiskBandMin(label string) (int, bool) {
	i, ok := riskBandIndex(label)
	if !ok {
		return 0, false
	}
	return RiskBands[i].Min, true
}
