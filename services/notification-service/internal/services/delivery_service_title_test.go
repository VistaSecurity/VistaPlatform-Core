package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

// Pins the in-app bell headline logic (M-8/L-3 QA finding, 2026-08): the bell
// used to show "[medium] job_completed" / "[medium] control_noncompliant"
// because sendInApp unconditionally composed the title from severity+alert_type,
// discarding any Title a producer had already set. resolveInAppTitle now
// prefers a producer-supplied Title and only falls back to a humanized form of
// AlertType — never folding severity into the headline text.

func TestResolveInAppTitle_PrefersProducerTitle(t *testing.T) {
	req := &models.SendNotificationRequest{
		AlertType: "control_noncompliant",
		Severity:  "medium",
		Title:     "Control noncompliant: PCI-3.4",
	}
	if got := resolveInAppTitle(req); got != "Control noncompliant: PCI-3.4" {
		t.Errorf("resolveInAppTitle() = %q, want the producer's own title", got)
	}
}

func TestResolveInAppTitle_FallsBackToHumanizedAlertType(t *testing.T) {
	req := &models.SendNotificationRequest{
		AlertType: "job_completed",
		Severity:  "medium",
		Title:     "",
	}
	got := resolveInAppTitle(req)
	if got != "Discovery job completed" {
		t.Errorf("resolveInAppTitle() = %q, want %q", got, "Discovery job completed")
	}
	// The old behavior baked severity into the title text; make sure it's gone.
	if got == "[medium] job_completed" {
		t.Fatalf("resolveInAppTitle() regressed to the bracketed severity+type format")
	}
}

func TestResolveInAppTitle_TreatsWhitespaceOnlyTitleAsMissing(t *testing.T) {
	req := &models.SendNotificationRequest{AlertType: "new_findings", Title: "   "}
	if got := resolveInAppTitle(req); got != "New discovery findings" {
		t.Errorf("resolveInAppTitle() = %q, want the humanized fallback", got)
	}
}

func TestHumanizeAlertType_KnownTypes(t *testing.T) {
	cases := map[string]string{
		"job_completed": "Discovery job completed",
		"job_failed":    "Discovery job failed",
		"new_findings":  "New discovery findings",
		"test":          "Test notification",
		"digest":        "Notification digest",
	}
	for in, want := range cases {
		if got := humanizeAlertType(in); got != want {
			t.Errorf("humanizeAlertType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanizeAlertType_UnknownFallsBackToTitleCasedWords(t *testing.T) {
	// A future alert_type not yet in the curated table must still read as
	// words, not as a raw identifier.
	if got := humanizeAlertType("cert_expiry_warning"); got != "Cert expiry warning" {
		t.Errorf("humanizeAlertType() = %q, want %q", got, "Cert expiry warning")
	}
}

func TestHumanizeAlertType_Empty(t *testing.T) {
	if got := humanizeAlertType(""); got != "Notification" {
		t.Errorf("humanizeAlertType(\"\") = %q, want a safe default", got)
	}
}
