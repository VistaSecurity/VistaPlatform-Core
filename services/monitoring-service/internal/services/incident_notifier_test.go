package services

// Security-incident notifications used to be delivered from
// monitoring_notification_channels, a table nothing ever wrote to, so the hooks
// reached nobody. They now go out on NATS notifications.send. These tests drive
// the real hook (CheckAndCreateIncident) into the real creator and capture what
// it publishes, so deleting either the hook->creator wiring or the publish
// fails here.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

type published struct {
	subject string
	data    interface{}
}

func capturingHook(t *testing.T, publishErr error) (*IncidentResponseHook, *[]published) {
	t.Helper()
	var got []published
	creator := &NotificationIncidentCreator{publish: func(subject string, data interface{}) error {
		got = append(got, published{subject, data})
		return publishErr
	}}
	return NewIncidentResponseHook(nil, creator, true), &got
}

func piiLog(tenant *uuid.UUID) *LogMetadata {
	return &LogMetadata{
		LogID:          "log-123",
		ServiceName:    "inventory-service",
		EventType:      "request",
		Severity:       "info",
		Timestamp:      time.Now(),
		TenantID:       tenant,
		PIIDetected:    true,
		PIITypes:       []string{"email"},
		ComplianceTags: []string{"gdpr"},
	}
}

func TestIncidentHook_PublishesPlatformNotification(t *testing.T) {
	tenant := uuid.New()
	hook, got := capturingHook(t, nil)

	if err := hook.CheckAndCreateIncident(context.Background(), piiLog(&tenant)); err != nil {
		t.Fatalf("CheckAndCreateIncident: %v", err)
	}
	if len(*got) != 1 {
		t.Fatalf("published %d messages, want 1", len(*got))
	}
	msg := (*got)[0]
	if msg.subject != events.SubjectNotificationsSend {
		t.Fatalf("subject = %q, want %q", msg.subject, events.SubjectNotificationsSend)
	}
	ev, ok := msg.data.(events.NotificationEvent)
	if !ok {
		t.Fatalf("payload is %T, want events.NotificationEvent", msg.data)
	}
	if ev.AlertSource != "monitoring" || ev.AlertType != IncidentAlertType {
		t.Errorf("source/type = %q/%q, want monitoring/%s", ev.AlertSource, ev.AlertType, IncidentAlertType)
	}
	if ev.Severity != "high" {
		t.Errorf("severity = %q, want high (PII + gdpr)", ev.Severity)
	}
	if ev.Title != "PII Detected in inventory-service Logs" {
		t.Errorf("title = %q", ev.Title)
	}
	if ev.Message == "" {
		t.Error("message is empty")
	}
	// Platform scope: the tenant the log line belonged to must not become the
	// notification's tenant (that would route platform-internal incidents to a
	// customer's rules). It travels as metadata only.
	if ev.TenantID != uuid.Nil {
		t.Errorf("tenant_id = %s, want the zero UUID (platform notification)", ev.TenantID)
	}
	affected, _ := ev.Metadata["affected_tenants"].([]string)
	if len(affected) != 1 || affected[0] != tenant.String() {
		t.Errorf("metadata.affected_tenants = %v, want [%s]", ev.Metadata["affected_tenants"], tenant)
	}
	if ev.Metadata["log_id"] != "log-123" || ev.Metadata["category"] != "data_breach" {
		t.Errorf("metadata = %v", ev.Metadata)
	}
	if ev.EventID == uuid.Nil {
		t.Error("event id must be set (stable across redelivery)")
	}
}

func TestIncidentHook_CriticalSecurityEventIsCritical(t *testing.T) {
	hook, got := capturingHook(t, nil)
	md := &LogMetadata{
		LogID: "log-9", ServiceName: "auth-service", EventType: "request", Severity: "critical",
		Category: "security", Timestamp: time.Now(), ComplianceTags: []string{"security"},
	}
	if err := hook.CheckAndCreateIncident(context.Background(), md); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 {
		t.Fatalf("published %d, want 1", len(*got))
	}
	if ev := (*got)[0].data.(events.NotificationEvent); ev.Severity != "critical" {
		t.Errorf("severity = %q, want critical", ev.Severity)
	}
}

func TestIncidentHook_NoIncidentNoPublish(t *testing.T) {
	hook, got := capturingHook(t, nil)
	md := &LogMetadata{LogID: "boring", ServiceName: "x", Severity: "info", Timestamp: time.Now()}
	if err := hook.CheckAndCreateIncident(context.Background(), md); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 0 {
		t.Fatalf("published %d messages for a log that raises no incident", len(*got))
	}
}

// A publish failure must reach the caller: log storage records a failed hook in
// the access audit from this error. Swallowing it is how the old path looked
// healthy while telling nobody.
func TestIncidentHook_PublishFailureIsReturned(t *testing.T) {
	hook, _ := capturingHook(t, errors.New("nats down"))
	err := hook.CheckAndCreateIncident(context.Background(), piiLog(nil))
	if err == nil {
		t.Fatal("publish failure was swallowed")
	}
}

// The builder is what main.go calls. Enabled must give a hook that fails
// visibly without NATS; disabled must give none.
func TestBuildIncidentResponseHook(t *testing.T) {
	if BuildIncidentResponseHook(nil, nil, false) != nil {
		t.Fatal("disabled config must not build a hook")
	}
	hook := BuildIncidentResponseHook(nil, nil, true)
	if hook == nil {
		t.Fatal("enabled config must build a hook even before NATS is up")
	}
	if err := hook.CheckAndCreateIncident(context.Background(), piiLog(nil)); err == nil {
		t.Fatal("with no NATS client the incident must fail visibly, not vanish")
	}
}

// The event id is the incident's own id, so a NATS redelivery of the same
// incident is the same X-Vista-Event-Id / PagerDuty dedup key downstream rather
// than a second page.
func TestNotificationIncidentCreator_EventIDIsTheIncidentID(t *testing.T) {
	var got events.NotificationEvent
	c := &NotificationIncidentCreator{publish: func(_ string, data interface{}) error {
		got = data.(events.NotificationEvent)
		return nil
	}}
	id := uuid.New()
	desc := "details"
	if _, err := c.CreateSecurityIncident(context.Background(), SecurityIncident{ID: id, Title: "t", Description: &desc, Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	if got.EventID != id {
		t.Fatalf("event id = %s, want the incident id %s", got.EventID, id)
	}
	if got.Message != "details" {
		t.Errorf("message = %q, want the description", got.Message)
	}
}
