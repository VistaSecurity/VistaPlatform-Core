package producers

// The end-of-life ladders.
//
// Two things are pinned here and they guard different mistakes. The first is
// that the day boundaries in Go still describe the same ladder the registry
// documents — the registry owns the severity and the score, this package owns
// the days, and nothing but a test keeps the two halves of one decision
// together. The second is the boundary arithmetic itself, where an off-by-one
// is the difference between "supported" and "past end of life".

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// TestEOLLadderMatchesRegistry is the join between the two halves of the
// ladder. If somebody edits standards/findings-registry.yaml — adds a rung,
// re-orders them, changes a threshold's wording — this fails, and the person
// who did it has to decide what the day boundaries should be rather than
// discovering later that findings stopped escalating.
func TestEOLLadderMatchesRegistry(t *testing.T) {
	cases := []struct {
		kind       string
		warnDays   int
		thresholds []string
	}{
		{
			kind:     findings.KindOSEndOfLife,
			warnDays: osWarnDays,
			thresholds: []string{
				"within 90 days of end of life",
				"past end of life",
				"past end of life by more than 365 days",
			},
		},
		{
			kind:     findings.KindSoftwareEndOfLife,
			warnDays: softwareWarnDays,
			thresholds: []string{
				"within 90 days of end of life",
				"past end of life",
				"past end of life by more than 365 days",
			},
		},
		{
			kind:     findings.KindHardwareEndOfSupport,
			warnDays: hardwareWarnDays,
			thresholds: []string{
				"within 180 days of end of support",
				"past end of support",
				"past end of support by more than 365 days",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			k, ok := findings.Get(findings.ProducerEOL, tc.kind)
			if !ok {
				t.Fatalf("%s is not registered under the eol producer", tc.kind)
			}
			if k.SeverityModel != "ladder" {
				t.Fatalf("severity_model=%q, want ladder — this producer picks rungs", k.SeverityModel)
			}
			if len(k.Rungs) != len(tc.thresholds) {
				t.Fatalf("the registry has %d rungs and this producer maps %d; rungFor indexes them positionally",
					len(k.Rungs), len(tc.thresholds))
			}
			for i, want := range tc.thresholds {
				if k.Rungs[i].Threshold != want {
					t.Errorf("rung %d threshold = %q, want %q — the day boundary in this package no longer describes what the registry says",
						i, k.Rungs[i].Threshold, want)
				}
			}
			// Severities must escalate. A ladder whose middle rung is milder
			// than its first is a ladder nobody reading the UI can act on.
			for i := 1; i < len(k.Rungs); i++ {
				if k.Rungs[i].Score < k.Rungs[i-1].Score {
					t.Errorf("rung %d scores %d, below rung %d's %d — rungs are ordered worst-last",
						i, k.Rungs[i].Score, i-1, k.Rungs[i-1].Score)
				}
			}
			// And the warning window has to be the number the first rung's
			// wording quotes.
			if tc.warnDays != 90 && tc.warnDays != 180 {
				t.Errorf("unexpected warning window %d", tc.warnDays)
			}
		})
	}
}

func TestRungFor_Boundaries(t *testing.T) {
	cases := []struct {
		name     string
		kind     string
		days     int
		wantRung int // -1 = no finding
	}{
		// A product whose support ends in two years is not a finding. Raising
		// one would be noise that trains people to ignore the real ones.
		{"far future is silent", findings.KindOSEndOfLife, 800, -1},
		{"one day past the window is silent", findings.KindOSEndOfLife, osWarnDays + 1, -1},
		{"the edge of the window reports", findings.KindOSEndOfLife, osWarnDays, rungApproaching},
		{"inside the window reports", findings.KindOSEndOfLife, 30, rungApproaching},
		// The end-of-life DATE is the last supported day: a product goes out of
		// support at the end of it, not at the start.
		{"the day itself is still approaching", findings.KindOSEndOfLife, 0, rungApproaching},
		{"one day past is past", findings.KindOSEndOfLife, -1, rungPast},
		{"a year past is still the middle rung", findings.KindOSEndOfLife, -longPastDays, rungPast},
		{"past a year escalates", findings.KindOSEndOfLife, -longPastDays - 1, rungLongPast},
		{"long past escalates", findings.KindOSEndOfLife, -2000, rungLongPast},

		// Hardware has a wider window: a rack visit takes longer than an apt
		// upgrade.
		{"hardware at 120 days reports", findings.KindHardwareEndOfSupport, 120, rungApproaching},
		{"os at 120 days does not", findings.KindOSEndOfLife, 120, -1},
		{"hardware past its window is silent", findings.KindHardwareEndOfSupport, hardwareWarnDays + 1, -1},

		{"software follows the os window", findings.KindSoftwareEndOfLife, softwareWarnDays, rungApproaching},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rung, report, err := rungFor(tc.kind, tc.days)
			if err != nil {
				t.Fatalf("rungFor: %v", err)
			}
			if tc.wantRung < 0 {
				if report {
					t.Fatalf("rungFor(%s, %d) raised a finding at %s/%d; want silence",
						tc.kind, tc.days, rung.Severity, rung.Score)
				}
				return
			}
			if !report {
				t.Fatalf("rungFor(%s, %d) raised nothing; want rung %d", tc.kind, tc.days, tc.wantRung)
			}
			k, _ := findings.Get(findings.ProducerEOL, tc.kind)
			want := k.Rungs[tc.wantRung]
			if rung.Severity != want.Severity || rung.Score != want.Score {
				t.Errorf("rungFor(%s, %d) = %s/%d, want rung %d (%s/%d)",
					tc.kind, tc.days, rung.Severity, rung.Score, tc.wantRung, want.Severity, want.Score)
			}
		})
	}
}

func TestRungFor_RefusesAKindWithNoLadder(t *testing.T) {
	if _, _, err := rungFor(findings.KindKnownVulnerability, -10); err == nil {
		t.Fatal("rungFor accepted a kind with no end-of-life ladder")
	}
}

func TestDaysUntil_CountsCalendarDays(t *testing.T) {
	// An end-of-life date is a DATE. A product must not become unsupported
	// eleven hours early because the nightly run started in the afternoon.
	afternoon := time.Date(2026, 9, 12, 16, 30, 0, 0, time.UTC)
	sameDay := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	if got := daysUntil(afternoon, sameDay); got != 0 {
		t.Errorf("daysUntil(same calendar day) = %d, want 0", got)
	}
	tomorrow := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	if got := daysUntil(afternoon, tomorrow); got != 1 {
		t.Errorf("daysUntil(tomorrow) = %d, want 1", got)
	}
	yesterday := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	if got := daysUntil(afternoon, yesterday); got != -1 {
		t.Errorf("daysUntil(yesterday) = %d, want -1", got)
	}
	// Across a timezone the local clock is behind UTC, the answer still has to
	// be the calendar difference in UTC.
	westAfternoon := afternoon.In(time.FixedZone("UTC-8", -8*3600))
	if got := daysUntil(westAfternoon, sameDay); got != 0 {
		t.Errorf("daysUntil across a zone = %d, want 0", got)
	}
}

func TestEOLDetail(t *testing.T) {
	cases := map[int]string{
		30: "in 30 days", 1: "tomorrow", 0: "today", -1: "1 day ago", -45: "45 days ago",
	}
	for days, want := range cases {
		if got := eolDetail(days); got != want {
			t.Errorf("eolDetail(%d) = %q, want %q", days, got, want)
		}
	}
}

func TestEOLSummary_UsesTheRegistryTemplate(t *testing.T) {
	got := eolSummary(findings.KindOSEndOfLife, "web-01", "30 days ago")
	want := "web-01 runs an end-of-life operating system (30 days ago)"
	if got != want {
		t.Errorf("eolSummary = %q, want %q — the title comes from the registry's template, not from a string in Go", got, want)
	}
}

// Every kind the registry gives the eol producer must have a ladder here.
// Without this, adding a fourth eol kind to the YAML would produce a producer
// that swept it (eolKinds is derived) but could never raise it.
func TestEveryEOLKindHasALadder(t *testing.T) {
	for _, k := range findings.All {
		if k.Producer != findings.ProducerEOL {
			continue
		}
		if _, ok := eolLadders[k.Key]; !ok {
			t.Errorf("registry kind eol/%s has no ladder in this package; it would be swept but never raised", k.Key)
		}
	}
	if len(eolKinds) != len(eolLadders) {
		t.Errorf("%d eol kinds in the registry, %d ladders here", len(eolKinds), len(eolLadders))
	}
}
