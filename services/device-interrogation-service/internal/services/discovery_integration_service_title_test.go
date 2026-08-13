package services

import "testing"

// discoveryNotificationTitle composes the notification-bell headline for
// discovery job events. Before this fix, SendDiscoveryNotification set
// Title: alertType directly (e.g. "job_completed"), which — combined with a
// notification-service bug that discarded producer titles anyway — rendered
// as "[medium] job_completed" in the bell (M-8/L-3 QA finding, 2026-08).

func TestDiscoveryNotificationTitle_KnownTypes(t *testing.T) {
	cases := map[string]string{
		"job_completed": "Discovery job completed",
		"job_failed":    "Discovery job failed",
		"new_findings":  "New discovery findings",
	}
	for in, want := range cases {
		if got := discoveryNotificationTitle(in); got != want {
			t.Errorf("discoveryNotificationTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDiscoveryNotificationTitle_UnknownPassesThrough(t *testing.T) {
	// An alert_type this function doesn't recognize should pass through
	// unchanged rather than error — notification-service's own
	// humanizeAlertType fallback (delivery_service.go) is the final backstop
	// for anything that reaches it un-humanized.
	if got := discoveryNotificationTitle("some_future_type"); got != "some_future_type" {
		t.Errorf("discoveryNotificationTitle() = %q, want passthrough", got)
	}
}
