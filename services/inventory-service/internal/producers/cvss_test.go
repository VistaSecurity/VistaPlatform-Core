package producers

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

func f(v float64) *float64 { return &v }

// The mapping is the published CVSS v3.1 / v4.0 qualitative rating, times ten.
// Written out longhand rather than derived, so a change to either side shows up
// as a disagreement between two independent statements of the same table.
func TestCVSSSeverity_MatchesTheQualitativeRatings(t *testing.T) {
	cases := []struct {
		cvss     float64
		severity string
		score    int
	}{
		{10.0, producer.SeverityCritical, 100},
		{9.8, producer.SeverityCritical, 98},
		{9.0, producer.SeverityCritical, 90},
		{8.9, producer.SeverityHigh, 89},
		{7.5, producer.SeverityHigh, 75},
		{7.0, producer.SeverityHigh, 70},
		{6.9, producer.SeverityMedium, 69},
		{5.3, producer.SeverityMedium, 53},
		{4.0, producer.SeverityMedium, 40},
		{3.9, producer.SeverityLow, 39},
		{0.1, producer.SeverityLow, 1},
		{0.0, producer.SeverityInfo, 0},
	}
	for _, tc := range cases {
		sev, score, scored := cvssSeverity(f(tc.cvss))
		if !scored {
			t.Errorf("CVSS %.1f reported as unscored", tc.cvss)
		}
		if sev != tc.severity || score != tc.score {
			t.Errorf("CVSS %.1f = %s/%d, want %s/%d", tc.cvss, sev, score, tc.severity, tc.score)
		}
	}
}

// The x10 convention is only worth anything if the bands the product already
// uses land on the same words. This drives models.RiskBands with the score this
// file produces and asserts the two agree.
//
// NB `models` here is inventory-service's, which is models.RiskBands — the
// CVSS-anchored asset ladder. `shared/models` has a GetRiskLevel of its own for
// the RBAC risk score, a different 0-100 metric with its own boundaries
// (>=80/60/40/20). Importing that one by accident compares this producer
// against a ladder it has nothing to do with, and the two names are one letter
// of import path apart.
func TestCVSSSeverity_AgreesWithRiskBands(t *testing.T) {
	for tenths := 0; tenths <= 100; tenths++ {
		cvss := float64(tenths) / 10
		sev, score, _ := cvssSeverity(&cvss)
		band := models.GetRiskLevel(score)
		want := map[string]string{
			producer.SeverityCritical: "Critical",
			producer.SeverityHigh:     "High",
			producer.SeverityMedium:   "Medium",
			producer.SeverityLow:      "Low",
			producer.SeverityInfo:     "Informational",
		}[sev]
		if band != want {
			t.Fatalf("CVSS %.1f → score %d: this file says %s, models.RiskBands says %q (want %q). The x10 convention has drifted from the band ladder.",
				cvss, score, sev, band, want)
		}
	}
}

func TestCVSSSeverity_UnscoredIsNotHarmless(t *testing.T) {
	// The registry says it in as many words: "A CVE with no CVSS score scores 0
	// and is reported as not scored, never as harmless." The finding is still
	// raised; `scored` is what lets the UI say which of the two zeros it is.
	sev, score, scored := cvssSeverity(nil)
	if scored {
		t.Error("a nil CVSS reported itself as scored")
	}
	if sev != producer.SeverityInfo || score != 0 {
		t.Errorf("a nil CVSS = %s/%d, want info/0", sev, score)
	}

	// CVSS 0.0 is a real grade — somebody looked and said it scores nothing —
	// and must be distinguishable from "nobody graded it".
	_, _, zeroScored := cvssSeverity(f(0))
	if !zeroScored {
		t.Error("CVSS 0.0 reported itself as unscored; 'graded as none' and 'not graded' are different answers")
	}
}

func TestCVSSSeverity_ClampsOutOfRange(t *testing.T) {
	// A feed that published 11.0 or -1 has a bug, but the score column has a
	// 0-100 CHECK and the writer refuses anything outside it — so the producer
	// must clamp rather than hand the database a value it will reject and take
	// the whole run down with it.
	if _, score, _ := cvssSeverity(f(11)); score != 100 {
		t.Errorf("CVSS 11 = %d, want clamped to 100", score)
	}
	if _, score, _ := cvssSeverity(f(-1)); score != 0 {
		t.Errorf("CVSS -1 = %d, want clamped to 0", score)
	}
}

func TestWorseCVSS_WorstWins(t *testing.T) {
	crit, critScore, _ := cvssSeverity(f(9.8))
	low, lowScore, _ := cvssSeverity(f(2.1))

	// An install with a critical and eleven lows is a critical problem.
	sev, score, scored := worseCVSS(low, lowScore, true, crit, critScore, true)
	if sev != producer.SeverityCritical || score != 98 || !scored {
		t.Errorf("worseCVSS(low, critical) = %s/%d/%v, want critical/98/true", sev, score, scored)
	}
	sev, score, _ = worseCVSS(crit, critScore, true, low, lowScore, true)
	if sev != producer.SeverityCritical || score != 98 {
		t.Errorf("worseCVSS(critical, low) = %s/%d, want critical/98 — order must not matter", sev, score)
	}

	// A scored advisory beats an unscored one, so an ungraded CVE alongside a
	// real 9.8 cannot lower the finding.
	unsev, unscore, unscored := cvssSeverity(nil)
	sev, score, scored = worseCVSS(unsev, unscore, unscored, crit, critScore, true)
	if sev != producer.SeverityCritical || score != 98 || !scored {
		t.Errorf("worseCVSS(unscored, critical) = %s/%d/%v, want critical/98/true", sev, score, scored)
	}
	// And an install carrying ONLY ungraded CVEs stays visibly ungraded rather
	// than looking like a genuine CVSS 0.0.
	sev, score, scored = worseCVSS(unsev, unscore, unscored, unsev, unscore, unscored)
	if scored {
		t.Error("two unscored advisories produced a 'scored' result")
	}
	if sev != producer.SeverityInfo || score != 0 {
		t.Errorf("two unscored advisories = %s/%d, want info/0", sev, score)
	}
}
