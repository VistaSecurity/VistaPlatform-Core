package models

import "github.com/vistasecurity/vistaplatform/shared/riskbands"

// The risk band ladder now lives in shared/riskbands, and this file forwards to
// it.
//
// It moved because it could not be reached from the OTHER services that band a
// risk score. device-interrogation-service's experimental stats handler wrote
// `risk_score >= 70` by hand for three separate counters — the exact
// hand-copied ladder this table was created to end, one module away where the
// table was an `internal` package it could not import. A rule that only one
// module can use is a rule the other modules will re-invent, and they did.
//
// Everything below is a forwarding declaration. Call sites in this service are
// unchanged, so the move cannot have altered a single query by accident, and
// there is still exactly ONE table.
type RiskBand = riskbands.RiskBand

// RiskBands is the ladder itself. See shared/riskbands for why these numbers
// are the CVSS qualitative ratings ×10.
var RiskBands = riskbands.RiskBands

// GetRiskLevel maps a 0–100 score onto its band label.
func GetRiskLevel(score int) string { return riskbands.GetRiskLevel(score) }

// RiskLevelCaseSQL emits the CASE ladder that labels a score in SQL.
func RiskLevelCaseSQL(expr string) string { return riskbands.RiskLevelCaseSQL(expr) }

// RiskBandSQL emits the predicate selecting exactly one band.
func RiskBandSQL(expr, label string) (string, bool) { return riskbands.RiskBandSQL(expr, label) }

// RiskAtLeastSQL emits the predicate selecting a band and everything above it.
func RiskAtLeastSQL(expr, label string) (string, bool) {
	return riskbands.RiskAtLeastSQL(expr, label)
}

// MustRiskBandSQL is RiskBandSQL for a compile-time-constant label.
func MustRiskBandSQL(expr, label string) string { return riskbands.MustRiskBandSQL(expr, label) }

// MustRiskAtLeastSQL is RiskAtLeastSQL for a compile-time-constant label.
func MustRiskAtLeastSQL(expr, label string) string {
	return riskbands.MustRiskAtLeastSQL(expr, label)
}

// RiskBandMin returns a band's inclusive lower bound.
func RiskBandMin(label string) (int, bool) { return riskbands.RiskBandMin(label) }
