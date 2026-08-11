package services

import "testing"

// Pins the normalized severity enum (critical/high/medium/low/info) and the
// producer-vocabulary mapping applied at the SendNotification bus boundary
// (NOTIFICATION_ALERTING_ARCHITECTURE.md §10.1). Routing-rule severity filters
// compare against these values — a mapping change here silently changes which
// rules fire, so every case is pinned.
func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"high", "high"},
		{"error", "high"},
		{"Error", "high"},
		{"medium", "medium"},
		{"warning", "medium"},
		{"warn", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"", "info"},
		{"  high  ", "high"},
		{"bogus", "info"},
		{"emergency", "info"},
	}
	for _, tc := range cases {
		if got := NormalizeSeverity(tc.in); got != tc.want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
