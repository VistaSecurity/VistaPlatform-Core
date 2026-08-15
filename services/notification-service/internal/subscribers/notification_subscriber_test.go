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

// The platform sentinel is the tenant id platform-track alerts are RAISED
// under (alerts.tenant_id is NOT NULL and RLS-partitioned), and the alert
// engine carries it straight through onto notifications.send. Treating it as a
// real tenant sent every service_down / metric_threshold / tenant_health_degraded
// notification down the tenant path — where it matched no rules (the sentinel
// intentionally has no tenants row) and its history INSERT violated
// notification_history_tenant_id_fkey. The platform pack could never be
// consulted. It must arrive as a PLATFORM notification.
func TestConvertNotificationEventToRequest_PlatformSentinelBecomesPlatform(t *testing.T) {
	ev := &events.NotificationEvent{
		TenantID:    events.PlatformAlertTenantID,
		AlertSource: "monitoring",
		AlertType:   "service_down",
		Severity:    "critical",
		Message:     "Service auth-service is failing health checks.",
	}

	req := convertNotificationEventToRequest(ev)

	if req.TenantID != nil {
		t.Errorf("req.TenantID = %v, want nil — the platform sentinel is not a tenant, and routing it "+
			"as one bypasses the platform notification rules entirely", req.TenantID)
	}
}

// The other polarity: a real tenant id must NOT be swallowed by the sentinel
// check, or every tenant notification would route to platform channels.
func TestConvertNotificationEventToRequest_RealTenantIsNotTreatedAsPlatform(t *testing.T) {
	tid := uuid.New()
	ev := &events.NotificationEvent{TenantID: tid, AlertSource: "inventory-service", AlertType: "certificate_expiring"}

	req := convertNotificationEventToRequest(ev)

	if req.TenantID == nil || *req.TenantID != tid {
		t.Errorf("req.TenantID = %v, want the real tenant %v", req.TenantID, tid)
	}
}
