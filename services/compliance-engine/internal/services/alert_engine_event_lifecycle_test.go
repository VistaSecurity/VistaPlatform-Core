package services

// An EVENT-lifecycle alert type (alert-registry `lifecycle: event`; today only
// object_changed) is routed once per raise and leaves no alerts row. These
// tests drive the real Raise with no database at all: if the event branch were
// removed, Raise would reach the stateful path and use the nil pool.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/alertcatalog"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

func TestRaise_EventLifecycleNotifiesEveryRaiseWithoutAnAlertRow(t *testing.T) {
	const secret = "internal-auth-test-secret"
	t.Setenv("INTERNAL_AUTH_SECRET", secret)
	t.Setenv("USE_MTLS", "false")
	stub := newNotifyStub(t, secret)
	t.Setenv("NOTIFICATION_SERVICE_URL", stub.server.URL)

	s := NewAlertEngineService(nil, nil, nil, nil) // no DB: an alerts-row write would panic
	tenant, object := uuid.New(), uuid.New()
	raise := func(eventID uuid.UUID, action string) RaiseOutcome {
		t.Helper()
		out, err := s.Raise(context.Background(), events.AlertRaiseEvent{
			EventID: eventID, TenantID: tenant, AlertType: "object_changed", Source: "inventory-service",
			SubjectType: "cable", SubjectID: &object, SubjectLabel: "CBL-1", Severity: "info",
			Title: "Cable updated: CBL-1", Message: "status changed",
			Metadata: map[string]interface{}{"object_kind": "cable", "action": action, "changed_fields": []string{"status"}},
		})
		if err != nil {
			t.Fatalf("Raise: %v", err)
		}
		return out
	}

	first := uuid.New()
	if out := raise(first, "update"); out != RaiseNotified {
		t.Fatalf("outcome = %q, want %q", out, RaiseNotified)
	}
	if stub.hits != 1 {
		t.Fatalf("notification-service hits = %d, want 1", stub.hits)
	}
	md, _ := stub.body["metadata"].(map[string]interface{})
	if md["alert_transition"] != "event" {
		t.Errorf("alert_transition = %v, want event", md["alert_transition"])
	}
	if _, has := md["alert_id"]; has {
		t.Errorf("an event has no alerts row, so no alert_id: %#v", md)
	}
	if md["object_kind"] != "cable" || md["action"] != "update" {
		t.Errorf("producer metadata not carried through: %#v", md)
	}

	// The SAME subject again: a stateful type would dedupe this into a silent
	// touch. An event is delivered again.
	if out := raise(uuid.New(), "delete"); out != RaiseNotified {
		t.Fatalf("second outcome = %q, want %q", out, RaiseNotified)
	}
	if stub.hits != 2 {
		t.Fatalf("second change to the same object reached notification-service %d time(s) in total, want 2", stub.hits)
	}
}

func TestEventNotificationEvent_KeepsTheProducersEventID(t *testing.T) {
	id := uuid.New()
	n := eventNotificationEvent(events.AlertRaiseEvent{EventID: id, TenantID: uuid.New(), AlertType: "object_changed"}, "info")
	if n.EventID != id {
		t.Fatalf("event id = %s, want the producer's %s (a redelivery must carry the same X-Vista-Event-Id)", n.EventID, id)
	}
	if n2 := eventNotificationEvent(events.AlertRaiseEvent{TenantID: uuid.New()}, "info"); n2.EventID == uuid.Nil {
		t.Fatal("a raise with no event id still needs one")
	}
}

// Registry parity: object_changed is the event type, inventory-service is its
// source, and every other type stays stateful (a typo in `lifecycle` would
// otherwise silently stop a real alert from ever opening a row).
func TestRegistry_ObjectChangedIsTheOnlyEventType(t *testing.T) {
	e, ok := alertcatalog.Get("object_changed")
	if !ok {
		t.Fatal("object_changed missing from the generated registry")
	}
	if e.Lifecycle != alertcatalog.LifecycleEvent || e.Source != "inventory-service" || e.Track != "tenant" ||
		e.SeverityModel != "fixed" || e.DefaultSeverity != "info" || e.Status != "live" {
		t.Fatalf("object_changed entry = %+v", *e)
	}
	for _, r := range alertcatalog.Registry {
		if r.ID == "object_changed" {
			continue
		}
		if r.Lifecycle != alertcatalog.LifecycleStateful {
			t.Errorf("%s: lifecycle = %q, want %q", r.ID, r.Lifecycle, alertcatalog.LifecycleStateful)
		}
	}
}
