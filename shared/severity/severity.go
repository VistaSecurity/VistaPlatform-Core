// Package severity owns the finding/alert vocabulary. Workflow priorities,
// log levels and external CVSS words are separate concepts.
package severity

import (
	"fmt"
	"strings"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type Definition struct {
	Value         Severity
	Label         string
	Rank          int
	ControlWeight int
}

// Definitions returns a copy in descending severity order. Rank is ordinal;
// ControlWeight is the separate four-value compliance weighting policy.
func Definitions() []Definition {
	return []Definition{
		{Critical, "Critical", 5, 4}, {High, "High", 4, 3},
		{Medium, "Medium", 3, 2}, {Low, "Low", 2, 1}, {Info, "Informational", 1, 0},
	}
}

// Parse accepts only canonical wire values. Source/migration normalization
// belongs at the explicitly named boundary, never in this parser.
func Parse(value string) (Severity, error) {
	for _, d := range Definitions() {
		if value == string(d.Value) {
			return d.Value, nil
		}
	}
	return "", fmt.Errorf("invalid finding severity %q", value)
}
func definition(value Severity) (Definition, error) {
	for _, d := range Definitions() {
		if value == d.Value {
			return d, nil
		}
	}
	return Definition{}, fmt.Errorf("invalid finding severity %q", value)
}
func Rank(value Severity) (int, error)     { d, err := definition(value); return d.Rank, err }
func Label(value Severity) (string, error) { d, err := definition(value); return d.Label, err }
func ControlWeight(value Severity) (int, error) {
	d, err := definition(value)
	if err != nil {
		return 0, err
	}
	if d.ControlWeight == 0 {
		return 0, fmt.Errorf("severity %q is not a compliance control severity", value)
	}
	return d.ControlWeight, nil
}

// RankSQL accepts a trusted code-owned SQL expression, never user input.
// Invalid/null values produce NULL rather than silently becoming Info/Medium.
func RankSQL(expr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CASE %s", expr)
	for _, d := range Definitions() {
		fmt.Fprintf(&b, " WHEN '%s' THEN %d", d.Value, d.Rank)
	}
	b.WriteString(" ELSE NULL END")
	return b.String()
}
