package riskbands

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestCanonicalRiskBoundaries(t *testing.T) {
	for _, tc := range []struct {
		score       int
		label, wire string
	}{{0, "Informational", "info"}, {1, "Low", "low"}, {39, "Low", "low"}, {40, "Medium", "medium"}, {69, "Medium", "medium"}, {70, "High", "high"}, {89, "High", "high"}, {90, "Critical", "critical"}, {100, "Critical", "critical"}} {
		if GetRiskLevel(tc.score) != tc.label || string(Severity(tc.score)) != tc.wire {
			t.Fatal(tc)
		}
	}
}
func TestIntegration_RiskSQLMatchesGo(t *testing.T) {
	db := testdb.Connect(t)
	for score := 0; score <= 100; score++ {
		var label string
		if err := db.QueryRow("SELECT "+RiskLevelCaseSQL("$1::int"), score).Scan(&label); err != nil {
			t.Fatal(err)
		}
		if label != GetRiskLevel(score) {
			t.Fatal(score, label)
		}
		for _, band := range RiskBands {
			var matched bool
			if err := db.QueryRow("SELECT "+MustRiskBandSQL("$1::int", band.Label), score).Scan(&matched); err != nil {
				t.Fatal(err)
			}
			if matched != (label == band.Label) {
				t.Fatal(score, band.Label)
			}
		}
	}
}
