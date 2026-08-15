package subscribers

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// Audit ingestion has two transports — HTTP (the LogActivity handler) and NATS
// (this subscriber) — and detection must not depend on which one carried the
// event. Two things made the NATS transport lossy in exactly the way that
// disables detection silently:
//
//   - the envelope dropped event_type and success, so the consumer rebuilt
//     event_type from the action and re-derived success from StatusCode. A
//     hand-logged failure carries StatusCode 0, which reads as SUCCESS.
//   - the subscriber never evaluated alert rules at all.
//
// Both are invisible from the outside: the row lands, nothing errors, and every
// audit alert rule quietly stops matching.

type recordingEvaluator struct{ seen []map[string]interface{} }

func (r *recordingEvaluator) EvaluateEvent(_ context.Context, event map[string]interface{}) []services.Alert {
	r.seen = append(r.seen, event)
	return nil
}

// failedLoginEnvelope is what shared/middleware/audit publishes for
// auth-service's failed-login entry.
func failedLoginEnvelope(tenantID, userID uuid.UUID) *events.AuditEvent {
	success := false
	return &events.AuditEvent{
		EventID:       uuid.New(),
		TenantID:      tenantID,
		UserID:        userID.String(),
		UserType:      "tenant",
		Action:        "login_failed",
		EventType:     "user.login_failed",
		EventCategory: "authentication",
		Success:       &success,
		Timestamp:     time.Now(),
	}
}

func TestEnvelopePreservesEventTypeAndOutcome(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()
	got := convertAuditEventToActivityLog(failedLoginEnvelope(tenantID, userID))

	if got.EventType != "user.login_failed" {
		t.Fatalf("EventType = %q, want %q — rebuilt from the action instead of carried", got.EventType, "user.login_failed")
	}
	if got.EventCategory != "authentication" {
		t.Fatalf("EventCategory = %q, want %q", got.EventCategory, "authentication")
	}
	if got.Success {
		t.Fatal("an explicitly-failed entry was recorded as a SUCCESS (StatusCode 0 re-derivation)")
	}
}

// TestEnvelopeFallsBackForPublishersWithoutTheFields — the new fields are
// omitempty, so an auto-logged HTTP request (or an older publisher) must still
// decode to the derived values rather than to empty strings.
func TestEnvelopeFallsBackForPublishersWithoutTheFields(t *testing.T) {
	got := convertAuditEventToActivityLog(&events.AuditEvent{
		EventID:    uuid.New(),
		TenantID:   uuid.New(),
		Action:     "asset.updated",
		StatusCode: 200,
		Timestamp:  time.Now(),
	})
	if got.EventType != "asset.updated" {
		t.Fatalf("EventType = %q, want the action %q as the fallback", got.EventType, "asset.updated")
	}
	if got.EventCategory != "api" {
		t.Fatalf("EventCategory = %q, want the %q fallback", got.EventCategory, "api")
	}
	if !got.Success {
		t.Fatal("a 200 with no explicit outcome must still derive as success")
	}
}

func TestNATSIngestionEvaluatesAlertRules(t *testing.T) {
	rec := &recordingEvaluator{}
	sub := &AuditSubscriber{alertService: rec}

	tenantID, userID := uuid.New(), uuid.New()
	entry := convertAuditEventToActivityLog(failedLoginEnvelope(tenantID, userID))
	sub.evaluateAlerts(context.Background(), entry)

	if len(rec.seen) != 1 {
		t.Fatalf("NATS-ingested entry produced %d rule evaluations, want 1", len(rec.seen))
	}
	ev := rec.seen[0]
	// The map must be the same shape the HTTP handler builds, or a rule matches
	// on one transport and misses on the other.
	if ev["event_type"] != "user.login_failed" {
		t.Fatalf("event_type = %v, want %q", ev["event_type"], "user.login_failed")
	}
	if ev["success"] != false {
		t.Fatalf("success = %v, want false", ev["success"])
	}
	tid, ok := ev["tenant_id"].(*uuid.UUID)
	if !ok || tid == nil || *tid != tenantID {
		t.Fatalf("tenant_id = %v, want %s", ev["tenant_id"], tenantID)
	}
}

// TestNilEvaluatorIsSafe — alertService is optional; ingestion must not panic
// when it is absent.
func TestNilEvaluatorIsSafe(t *testing.T) {
	sub := &AuditSubscriber{}
	sub.evaluateAlerts(context.Background(), &models.ActivityLog{ID: uuid.New()})
}
