package services

import (
	"errors"
	"testing"
)

// Pins the alert lifecycle state machine (NOTIFICATION_ALERTING_ARCHITECTURE.md
// §9): active → acknowledged → snoozed → resolved. Every legal and
// illegal move is enumerated — a change here changes what users can do to
// evidence-chain state, so nothing is left to inference.
func TestTransitionFor(t *testing.T) {
	legal := []struct {
		from, action, want string
	}{
		{"active", "acknowledge", "acknowledged"},
		{"snoozed", "acknowledge", "acknowledged"},
		{"active", "snooze", "snoozed"},
		{"acknowledged", "snooze", "snoozed"},
		{"snoozed", "unsnooze", "active"},
		{"active", "resolve", "resolved"},
		{"acknowledged", "resolve", "resolved"},
		{"snoozed", "resolve", "resolved"},
	}
	for _, tc := range legal {
		got, err := transitionFor(tc.from, tc.action)
		if err != nil {
			t.Errorf("transitionFor(%s, %s) unexpected error: %v", tc.from, tc.action, err)
			continue
		}
		if got != tc.want {
			t.Errorf("transitionFor(%s, %s) = %s, want %s", tc.from, tc.action, got, tc.want)
		}
	}

	illegal := []struct{ from, action string }{
		{"resolved", "acknowledge"},
		{"resolved", "snooze"},
		{"resolved", "unsnooze"},
		{"resolved", "resolve"},
		{"acknowledged", "acknowledge"},
		{"acknowledged", "unsnooze"},
		{"active", "unsnooze"},
		{"snoozed", "snooze"},
	}
	for _, tc := range illegal {
		if _, err := transitionFor(tc.from, tc.action); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("transitionFor(%s, %s) = %v, want ErrInvalidTransition", tc.from, tc.action, err)
		}
	}
}

// Pins the severity ordering the raise path uses to decide escalate-vs-touch.
// A raise notifies only when it OPENS an alert or INCREASES severity; equal or
// lower severity is a silent touch. Getting this ordering wrong either spams
// (notify on every re-raise) or goes silent (never escalates).
func TestSeverityRank(t *testing.T) {
	order := []string{"info", "low", "medium", "high", "critical"}
	for i := 1; i < len(order); i++ {
		if severityRank(order[i]) <= severityRank(order[i-1]) {
			t.Errorf("severityRank(%s) should outrank %s", order[i], order[i-1])
		}
	}
	if severityRank("bogus") != severityRank("info") {
		t.Errorf("unknown severities must rank as info")
	}
}
