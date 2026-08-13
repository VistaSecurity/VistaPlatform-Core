package subscribers

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// convertNotificationEventToRequest used to drop the NATS event's Title on
// the floor entirely — SendNotificationRequest had no Title field, so a
// properly-composed title (e.g. compliance-engine's
// "Control noncompliant: PCI-3.4") never reached the bell; delivery_service.go
// silently replaced it with "[severity] alert_type" (M-8/L-3 QA finding).
// This pins that Title now survives the NATS→HTTP-request conversion.

func TestConvertNotificationEventToRequest_PropagatesTitle(t *testing.T) {
	ev := &events.NotificationEvent{
		EventID:     uuid.New(),
		TenantID:    uuid.New(),
		AlertSource: "compliance-engine",
		AlertType:   "control_noncompliant",
		Severity:    "high",
		Title:       "Control noncompliant: PCI-3.4",
		Message:     "Control PCI-3.4 (PCI-DSS) is noncompliant — 3 asset(s) affected.",
	}

	req := convertNotificationEventToRequest(ev)

	if req.Title != "Control noncompliant: PCI-3.4" {
		t.Errorf("req.Title = %q, want the event's composed title", req.Title)
	}
	if req.AlertType != ev.AlertType || req.Severity != ev.Severity || req.Message != ev.Message {
		t.Errorf("conversion dropped or mangled a field: %+v", req)
	}
	if req.TenantID == nil || *req.TenantID != ev.TenantID {
		t.Errorf("req.TenantID = %v, want %v", req.TenantID, ev.TenantID)
	}
}

func TestConvertNotificationEventToRequest_EmptyTitlePassesThroughEmpty(t *testing.T) {
	// A producer that never composed a title (Title == "") should still leave
	// req.Title empty so delivery_service.go's humanized fallback kicks in,
	// rather than resurrecting the old metadata["title"] indirection.
	ev := &events.NotificationEvent{
		AlertSource: "discovery",
		AlertType:   "job_completed",
		Severity:    "medium",
		Title:       "",
		Message:     "Cloud discovery completed: 4 aws resources found",
	}

	req := convertNotificationEventToRequest(ev)

	if req.Title != "" {
		t.Errorf("req.Title = %q, want empty so the delivery fallback applies", req.Title)
	}
}

func TestConvertNotificationEventToRequest_NilTenantIDStaysNil(t *testing.T) {
	ev := &events.NotificationEvent{AlertSource: "system", AlertType: "test", Severity: "info"}
	req := convertNotificationEventToRequest(ev)
	if req.TenantID != nil {
		t.Errorf("req.TenantID = %v, want nil for a platform-scoped event", req.TenantID)
	}
}
