package jobs

// The three findings-driven alert ladders.
//
// Three things are pinned here and they guard different mistakes:
//
//  1. that the boundaries in Go still describe the ladder the registry
//     documents — the registry owns the severity and the threshold wording,
//     this package owns the numbers, and nothing but a test keeps the two
//     halves of one decision together;
//  2. the boundary arithmetic itself, tested on BOTH sides of every rung,
//     because an off-by-one is the difference between "supported" and "past
//     end of life", and between a Medium and a High page;
//  3. that a subject with several findings is graded by the WORST of them and
//     appears exactly once.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/alertcatalog"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

// --- registry join ----------------------------------------------------------

// TestFindingsAlertLaddersMatchRegistry is the join between the two halves of
// each ladder. Edit standards/alert-registry.yaml — add a rung, re-order them,
// reword a threshold — and this fails, so the person who did it decides what
// the boundaries should be rather than discovering later that alerts stopped
// escalating.
func TestFindingsAlertLaddersMatchRegistry(t *testing.T) {
	cases := []struct {
		alertType string
		rungs     []alertcatalog.LadderRung
		// numbers each threshold's wording must still quote, so a boundary
		// changed in Go and not in the YAML (or the reverse) is caught.
		quotes []string
	}{
		{
			alertType: "known_vulnerability",
			rungs: []alertcatalog.LadderRung{
				{Threshold: "CVSS 4.0 or higher (Medium)", Severity: "medium"},
				{Threshold: "CVSS 7.0 or higher (High)", Severity: "high"},
				{Threshold: "CVSS 9.0 or higher (Critical)", Severity: "critical"},
			},
			quotes: []string{"4.0", "7.0", "9.0"},
		},
		{
			alertType: "end_of_life",
			rungs: []alertcatalog.LadderRung{
				{Threshold: "180 days to end of life", Severity: "low"},
				{Threshold: "90 days to end of life", Severity: "medium"},
				{Threshold: "past end of life", Severity: "high"},
				{Threshold: "past end of life by more than a year", Severity: "critical"},
			},
			quotes: []string{"180", "90", "end of life", "year"},
		},
		{
			alertType: "drift_detected",
			rungs: []alertcatalog.LadderRung{
				{Threshold: "a change the drift producer graded low", Severity: "low"},
				{Threshold: "a change the drift producer graded medium", Severity: "medium"},
				{Threshold: "a change the drift producer graded high", Severity: "high"},
				{Threshold: "a change the drift producer graded critical", Severity: "critical"},
			},
			quotes: []string{"low", "medium", "high", "critical"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.alertType, func(t *testing.T) {
			entry, ok := alertcatalog.Get(tc.alertType)
			if !ok {
				t.Fatalf("%s is not in standards/alert-registry.yaml", tc.alertType)
			}
			if entry.SeverityModel != "ladder" {
				t.Fatalf("severity_model=%q, want ladder — this detector picks rungs", entry.SeverityModel)
			}
			if entry.Status != "live" {
				t.Fatalf("status=%q, want live — a detector runs for this type", entry.Status)
			}
			if len(entry.Rungs) != len(tc.rungs) {
				t.Fatalf("the registry has %d rungs and this package maps %d; the rung constants index them positionally",
					len(entry.Rungs), len(tc.rungs))
			}
			for i, want := range tc.rungs {
				if entry.Rungs[i] != want {
					t.Errorf("rung %d = %+v, want %+v — the boundary in this package no longer describes what the registry says",
						i, entry.Rungs[i], want)
				}
			}
			for i := 1; i < len(entry.Rungs); i++ {
				if alertcatalog.SeverityRank(entry.Rungs[i].Severity) <= alertcatalog.SeverityRank(entry.Rungs[i-1].Severity) {
					t.Errorf("rung %d (%s) is not worse than rung %d (%s) — rungs are ordered worst-last",
						i, entry.Rungs[i].Severity, i-1, entry.Rungs[i-1].Severity)
				}
			}
			joined := strings.Join(tc.quotes, "|")
			for _, q := range tc.quotes {
				found := false
				for _, r := range entry.Rungs {
					if strings.Contains(r.Threshold, q) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no rung threshold quotes %q (wanted all of %s) — the wording no longer names the boundary the code uses", q, joined)
				}
			}
		})
	}
}

// TestRungConstantsAreInRange catches a registry ladder trimmed under a
// detector: FixedRung errors rather than clamping to the worst rung it still
// has, and every index this package names must resolve.
func TestRungConstantsAreInRange(t *testing.T) {
	for _, tc := range []struct {
		alertType string
		indices   []int
	}{
		{"known_vulnerability", []int{vulnRungMedium, vulnRungHigh, vulnRungCritical}},
		{"end_of_life", []int{eolRungApproaching, eolRungNear, eolRungPast, eolRungLongPast}},
	} {
		for _, i := range tc.indices {
			if _, err := alertcatalog.FixedRung(tc.alertType, i); err != nil {
				t.Errorf("%s rung %d: %v", tc.alertType, i, err)
			}
		}
		if _, err := alertcatalog.FixedRung(tc.alertType, len(tc.indices)); err == nil {
			t.Errorf("%s: FixedRung accepted an index past the end of the ladder", tc.alertType)
		}
	}
}

func TestFixedRung_RejectsATunableLadderAndAnUnknownType(t *testing.T) {
	// certificate_expiring declares a baseline_rung, not a fixed ladder.
	if _, err := alertcatalog.FixedRung("certificate_expiring", 0); err == nil {
		t.Error("FixedRung returned a rung for a type with no fixed ladder")
	}
	if _, err := alertcatalog.FixedRung("no_such_alert_type", 0); err == nil {
		t.Error("FixedRung returned a rung for a type not in the registry")
	}
}

// --- known_vulnerability ladder ---------------------------------------------

func vulnFinding(score int) openFinding {
	return openFinding{
		id: uuid.New(), kind: sharedfindings.KindKnownVulnerability,
		subjectType: sharedfindings.SubjectSoftwareInstall, subjectID: uuid.New(),
		severity: "medium", score: score,
	}
}

func TestVulnerabilityRungFor_Boundaries(t *testing.T) {
	// Both sides of every rung. The CVSS band boundaries are 4.0 / 7.0 / 9.0,
	// and findings.score is the base score times ten.
	cases := []struct {
		score   int
		wantIdx int
		wantOK  bool
	}{
		{0, 0, false},  // unscored, or a genuine CVSS 0.0 — no alert
		{1, 0, false},  // CVSS 0.1: a Low finding, below the alert floor
		{39, 0, false}, // CVSS 3.9: still Low
		{40, vulnRungMedium, true},
		{41, vulnRungMedium, true},
		{69, vulnRungMedium, true}, // CVSS 6.9
		{70, vulnRungHigh, true},
		{89, vulnRungHigh, true}, // CVSS 8.9
		{90, vulnRungCritical, true},
		{100, vulnRungCritical, true}, // CVSS 10.0
	}
	for _, c := range cases {
		idx, ok := vulnerabilityRungFor(vulnFinding(c.score))
		if ok != c.wantOK {
			t.Errorf("score %d: crossed=%v, want %v", c.score, ok, c.wantOK)
			continue
		}
		if ok && idx != c.wantIdx {
			t.Errorf("score %d: rung %d, want %d", c.score, idx, c.wantIdx)
		}
	}
}

// TestVulnerabilityRungFor_UnscoredIsNotHarmless pins the three-valued rule at
// the place it is easiest to lose: an advisory the feed never scored produces a
// finding at score 0, and score 0 opens no alert. The finding still exists —
// that is what makes this a notification threshold rather than a claim the
// install is clean.
func TestVulnerabilityRungFor_UnscoredIsNotHarmless(t *testing.T) {
	f := vulnFinding(0)
	f.severity = "info"
	f.evidence = map[string]any{"worst_cvss_scored": false, "cve_count": float64(3)}
	if _, ok := vulnerabilityRungFor(f); ok {
		t.Fatal("an unscored advisory crossed an alert rung — the alert would claim a severity nobody assigned")
	}
}

func TestSummarizeVulnerability(t *testing.T) {
	f := vulnFinding(93)
	f.subjectLabel = "openssl 1.1.1k"
	f.evidence = map[string]any{
		"cve_count": float64(4),
		"cves": []interface{}{
			map[string]interface{}{"cve_id": "CVE-2026-1111", "cvss_score": 9.3},
			map[string]interface{}{"cve_id": "CVE-2026-2222", "cvss_score": 5.0},
		},
	}
	g := subjectGroup{
		subjectType: sharedfindings.SubjectSoftwareInstall, subjectID: f.subjectID,
		subjectLabel: f.subjectLabel, findings: []openFinding{f}, worst: f, crosses: true,
		rungIndex: vulnRungCritical,
	}
	rung, err := alertcatalog.FixedRung("known_vulnerability", vulnRungCritical)
	if err != nil {
		t.Fatalf("FixedRung: %v", err)
	}
	title, message, meta := summarizeVulnerability(g, rung)
	if !strings.Contains(title, "openssl 1.1.1k") {
		t.Errorf("title %q does not name the install", title)
	}
	for _, want := range []string{"4 published advisories", "CVE-2026-1111", "9.3"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q is missing %q", message, want)
		}
	}
	if meta["worst_cve"] != "CVE-2026-1111" {
		t.Errorf("worst_cve = %v, want CVE-2026-1111", meta["worst_cve"])
	}
	if meta["worst_cvss_score"] != 9.3 {
		t.Errorf("worst_cvss_score = %v, want 9.3", meta["worst_cvss_score"])
	}
}

// --- end_of_life ladder -----------------------------------------------------

func eolFinding(kind string, days int) openFinding {
	return openFinding{
		id: uuid.New(), kind: kind,
		subjectType: sharedfindings.SubjectAsset, subjectID: uuid.New(),
		severity: "low", score: 20,
		evidence: map[string]any{"days_remaining": float64(days)},
	}
}

func TestEndOfLifeRungFor_Boundaries(t *testing.T) {
	// Both sides of every rung. Day 0 is still SUPPORTED — a product goes out
	// of support at the end of its end-of-life date, not at the start of it —
	// which is the producer's own convention and must not diverge here.
	cases := []struct {
		days    int
		wantIdx int
		wantOK  bool
	}{
		{400, 0, false}, // further out than any rung
		{181, 0, false}, // one day outside the widest rung
		{180, eolRungApproaching, true},
		{91, eolRungApproaching, true},
		{90, eolRungNear, true},
		{1, eolRungNear, true},
		{0, eolRungNear, true},  // the date is today, still supported
		{-1, eolRungPast, true}, // one day past
		{-365, eolRungPast, true},
		{-366, eolRungLongPast, true},
		{-4000, eolRungLongPast, true},
	}
	for _, c := range cases {
		idx, ok := endOfLifeRungFor(eolFinding(sharedfindings.KindOSEndOfLife, c.days))
		if ok != c.wantOK {
			t.Errorf("days %d: crossed=%v, want %v", c.days, ok, c.wantOK)
			continue
		}
		if ok && idx != c.wantIdx {
			t.Errorf("days %d: rung %d, want %d", c.days, idx, c.wantIdx)
		}
	}
}

// TestEndOfLifeRungFor_FallsBackToTheFindingSeverity covers a finding whose
// evidence carries no day count. The producer graded the same condition, so the
// alert is graded at the finding's own severity rather than dropped.
func TestEndOfLifeRungFor_FallsBackToTheFindingSeverity(t *testing.T) {
	for severity, wantIdx := range map[string]int{
		"low":      eolRungApproaching,
		"medium":   eolRungNear,
		"high":     eolRungPast,
		"critical": eolRungLongPast,
	} {
		f := eolFinding(sharedfindings.KindSoftwareEndOfLife, 0)
		f.evidence = map[string]any{} // no days_remaining
		f.severity = severity
		idx, ok := endOfLifeRungFor(f)
		if !ok {
			t.Errorf("severity %q: no rung crossed, want rung %d", severity, wantIdx)
			continue
		}
		if idx != wantIdx {
			t.Errorf("severity %q: rung %d, want %d", severity, idx, wantIdx)
		}
	}

	// A severity no rung carries opens nothing rather than guessing.
	f := eolFinding(sharedfindings.KindOSEndOfLife, 0)
	f.evidence = nil
	f.severity = "info"
	if _, ok := endOfLifeRungFor(f); ok {
		t.Error("an `info` end-of-life finding with no day count crossed a rung")
	}
}

// TestEvidenceInt_AbsentIsNotZero pins the distinction the whole eol ladder
// turns on: "the date is today" (0) and "we have no day count" (absent) are
// different answers, and collapsing them would make a missing measurement look
// like a deadline that just arrived.
func TestEvidenceInt_AbsentIsNotZero(t *testing.T) {
	if _, ok := evidenceInt(map[string]any{}, "days_remaining"); ok {
		t.Error("an absent key reported a value")
	}
	if _, ok := evidenceInt(nil, "days_remaining"); ok {
		t.Error("a nil evidence document reported a value")
	}
	if v, ok := evidenceInt(map[string]any{"days_remaining": float64(0)}, "days_remaining"); !ok || v != 0 {
		t.Errorf("an explicit 0 read as (%d, %v), want (0, true)", v, ok)
	}
	if v, ok := evidenceInt(map[string]any{"days_remaining": float64(-12)}, "days_remaining"); !ok || v != -12 {
		t.Errorf("a negative day count read as (%d, %v), want (-12, true)", v, ok)
	}
	if _, ok := evidenceInt(map[string]any{"days_remaining": "not a number"}, "days_remaining"); ok {
		t.Error("a non-numeric value reported a number")
	}
}

func TestSummarizeEndOfLife(t *testing.T) {
	osF := eolFinding(sharedfindings.KindOSEndOfLife, -500)
	osF.severity = "critical"
	osF.subjectLabel = "db-prod-01"
	osF.evidence["eol_date"] = "2024-04-30"
	hwF := eolFinding(sharedfindings.KindHardwareEndOfSupport, 30)
	hwF.subjectID = osF.subjectID
	hwF.subjectLabel = "db-prod-01"

	g := subjectGroup{
		subjectType: sharedfindings.SubjectAsset, subjectID: osF.subjectID, subjectLabel: "db-prod-01",
		findings: []openFinding{osF, hwF}, worst: osF, crosses: true, rungIndex: eolRungLongPast,
	}
	rung, err := alertcatalog.FixedRung("end_of_life", eolRungLongPast)
	if err != nil {
		t.Fatalf("FixedRung: %v", err)
	}
	title, message, meta := summarizeEndOfLife(g, rung)
	if !strings.Contains(title, "Past end of life") || !strings.Contains(title, "db-prod-01") {
		t.Errorf("title = %q", title)
	}
	for _, want := range []string{"operating system", "500 days ago", "2 end-of-life findings"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q is missing %q", message, want)
		}
	}
	if meta["eol_date"] != "2024-04-30" {
		t.Errorf("eol_date = %v", meta["eol_date"])
	}
	kinds, _ := meta["finding_kinds"].([]string)
	if len(kinds) != 2 {
		t.Errorf("finding_kinds = %v, want both kinds on the subject", kinds)
	}
}

// --- grouping ---------------------------------------------------------------

// TestGroup_WorstFindingSetsTheRung is the "one alert per subject" rule: two
// findings on one asset collapse to one group graded by the worse of them, and
// a finding that crosses no rung neither creates a group that alerts nor hides
// one that does.
func TestGroup_WorstFindingSetsTheRung(t *testing.T) {
	j := NewEndOfLifeAlertScanJob(nil, nil, nil, nil, 0)
	asset := uuid.New()

	mild := eolFinding(sharedfindings.KindHardwareEndOfSupport, 150) // approaching
	mild.subjectID = asset
	severe := eolFinding(sharedfindings.KindOSEndOfLife, -900) // long past
	severe.subjectID = asset
	quiet := eolFinding(sharedfindings.KindSoftwareEndOfLife, 900) // no rung
	quiet.subjectID = uuid.New()

	groups := j.group([]openFinding{mild, severe, quiet})
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (one per subject)", len(groups))
	}
	byID := map[uuid.UUID]subjectGroup{}
	for _, g := range groups {
		byID[g.subjectID] = g
	}
	got := byID[asset]
	if !got.crosses || got.rungIndex != eolRungLongPast {
		t.Errorf("asset group crosses=%v rung=%d, want true/%d — the worst finding sets the rung",
			got.crosses, got.rungIndex, eolRungLongPast)
	}
	if got.worst.id != severe.id {
		t.Error("the worst finding recorded on the group is not the worst one")
	}
	if len(got.findings) != 2 {
		t.Errorf("group carries %d findings, want 2", len(got.findings))
	}
	if byID[quiet.subjectID].crosses {
		t.Error("a finding outside every rung opened an alert")
	}
}

func TestSeverityWorse(t *testing.T) {
	if !severityWorse("critical", "high") {
		t.Error("critical should outrank high")
	}
	if severityWorse("high", "high") {
		t.Error("an unchanged severity is not an escalation — re-raising it would be write amplification")
	}
	if severityWorse("medium", "high") {
		t.Error("a lower severity is not an escalation — the engine never de-escalates")
	}
}
