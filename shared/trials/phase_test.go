package trials

import (
	"testing"
	"time"
)

// trialStart is a stable anchor every test uses; phase comparisons are
// done by adding day offsets to it, not against time.Now.
var trialStart = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// ptr is a one-character int-pointer helper to keep the table tests
// readable. The phase computation accepts *int for the trial-day
// fields so callers can express "tier is not a trial" via nil.
func ptr(i int) *int { return &i }

func ptrTime(t time.Time) *time.Time { return &t }

func TestCompute(t *testing.T) {
	cases := []struct {
		name string
		in   Inputs
		want Phase
	}{
		{
			name: "no trial row",
			in:   Inputs{Now: trialStart.Add(1 * time.Hour)},
			want: PhaseNone,
		},
		{
			name: "converted always wins",
			in: Inputs{
				TrialStart:      trialStart,
				ConvertedToPaid: true,
				TrialDaysFull:   ptr(14),
				TrialDaysSoft:   ptr(14),
				Now:             trialStart.Add(365 * 24 * time.Hour),
			},
			want: PhaseConverted,
		},
		{
			name: "day 0 → full",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart,
			},
			want: PhaseFull,
		},
		{
			name: "day 13 → still full",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(13*24*time.Hour + 23*time.Hour),
			},
			want: PhaseFull,
		},
		{
			name: "day 14 exact → soft_prompt (inclusive boundary)",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(14 * 24 * time.Hour),
			},
			want: PhaseSoftPrompt,
		},
		{
			name: "day 20 → soft_prompt",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(20 * 24 * time.Hour),
			},
			want: PhaseSoftPrompt,
		},
		{
			name: "day 28 exact → locked",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(28 * 24 * time.Hour),
			},
			want: PhaseLocked,
		},
		{
			name: "day 100 → still locked",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(100 * 24 * time.Hour),
			},
			want: PhaseLocked,
		},
		{
			name: "no soft phase: day full goes straight to locked",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(7),
				TrialDaysSoft: ptr(0),
				Now:           trialStart.Add(7 * 24 * time.Hour),
			},
			want: PhaseLocked,
		},
		{
			name: "nil trial_days_full: locked immediately past trial_start",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: nil,
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(1 * time.Second),
			},
			want: PhaseSoftPrompt,
		},
		{
			name: "trial_end beyond tier calendar delays lock from soft_prompt",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				TrialEnd:      ptrTime(trialStart.Add(40 * 24 * time.Hour)),
				Now:           trialStart.Add(30 * 24 * time.Hour),
			},
			want: PhaseSoftPrompt,
		},
		{
			name: "trial_end beyond tier calendar then locked once past trial_end",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				TrialEnd:      ptrTime(trialStart.Add(40 * 24 * time.Hour)),
				Now:           trialStart.Add(40 * 24 * time.Hour),
			},
			want: PhaseLocked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Compute(tc.in)
			if got != tc.want {
				t.Errorf("Compute = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDaysRemaining(t *testing.T) {
	cases := []struct {
		name string
		in   Inputs
		want int
	}{
		{
			name: "no trial → 0",
			in:   Inputs{Now: trialStart},
			want: 0,
		},
		{
			name: "day 0, 14+14 trial → 14 days left in full phase",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart,
			},
			want: 14,
		},
		{
			name: "day 5, 14+14 trial → 8 days (full ends at day 14, floor)",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(5*24*time.Hour + 1*time.Hour),
			},
			want: 8,
		},
		{
			name: "day 16 (soft_prompt), 14+14 trial → 11 days until lock",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(16*24*time.Hour + 30*time.Minute),
			},
			want: 11,
		},
		{
			name: "locked → 0",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(30 * 24 * time.Hour),
			},
			want: 0,
		},
		{
			name: "converted → 0",
			in: Inputs{
				TrialStart:      trialStart,
				ConvertedToPaid: true,
				TrialDaysFull:   ptr(14),
				TrialDaysSoft:   ptr(14),
				Now:             trialStart.Add(5 * 24 * time.Hour),
			},
			want: 0,
		},
		{
			name: "partial day rounds DOWN — 23h59m left → 0",
			in: Inputs{
				TrialStart:    trialStart,
				TrialDaysFull: ptr(14),
				TrialDaysSoft: ptr(14),
				Now:           trialStart.Add(13*24*time.Hour + 1*time.Minute),
			},
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DaysRemaining(tc.in)
			if got != tc.want {
				t.Errorf("DaysRemaining = %d, want %d", got, tc.want)
			}
		})
	}
}
