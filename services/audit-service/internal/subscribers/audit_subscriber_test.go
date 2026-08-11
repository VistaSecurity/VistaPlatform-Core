package subscribers

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// TestConvertAuditEventToActivityLog_UserType pins the fix for: the
// activity_logs valid_user_type CHECK constraint only allows 'tenant' and
// 'platform', so the subscriber must propagate the event's user_type and
// default to 'platform' when it is absent (older publishers, system events).
func TestConvertAuditEventToActivityLog_UserType(t *testing.T) {
	tests := []struct {
		name      string
		userType  string
		wantValue string
	}{
		{name: "tenant passes through", userType: "tenant", wantValue: "tenant"},
		{name: "platform passes through", userType: "platform", wantValue: "platform"},
		{name: "empty falls back to platform", userType: "", wantValue: "platform"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := &events.AuditEvent{
				EventID:   uuid.New(),
				UserType:  tt.userType,
				Action:    "update",
				Timestamp: time.Now(),
			}
			got := convertAuditEventToActivityLog(evt)
			if got.UserType != tt.wantValue {
				t.Errorf("UserType = %q, want %q", got.UserType, tt.wantValue)
			}
		})
	}
}

// TestConvertAuditEventToActivityLog_FieldMapping verifies the rest of the
// event-to-log mapping alongside the user_type fix.
func TestConvertAuditEventToActivityLog_FieldMapping(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	resourceID := uuid.New()
	occurred := time.Now().Add(-time.Minute)

	evt := &events.AuditEvent{
		EventID:    uuid.New(),
		TenantID:   tenantID,
		UserID:     userID.String(),
		UserType:   "tenant",
		Action:     "billing.invoice_paid",
		Resource:   "invoice",
		ResourceID: resourceID.String(),
		IPAddress:  "10.0.0.5",
		UserAgent:  "test-agent",
		StatusCode: 200,
		Timestamp:  occurred,
	}

	got := convertAuditEventToActivityLog(evt)

	if got.ID != evt.EventID {
		t.Errorf("ID = %v, want %v", got.ID, evt.EventID)
	}
	if got.TenantID == nil || *got.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", got.TenantID, tenantID)
	}
	if got.UserID == nil || *got.UserID != userID {
		t.Errorf("UserID = %v, want %v", got.UserID, userID)
	}
	if got.UserType != "tenant" {
		t.Errorf("UserType = %q, want %q", got.UserType, "tenant")
	}
	if got.ResourceType == nil || *got.ResourceType != "invoice" {
		t.Errorf("ResourceType = %v, want %q", got.ResourceType, "invoice")
	}
	if got.ResourceID == nil || *got.ResourceID != resourceID {
		t.Errorf("ResourceID = %v, want %v", got.ResourceID, resourceID)
	}
	if got.EventType != "billing.invoice_paid" {
		t.Errorf("EventType = %q, want %q", got.EventType, "billing.invoice_paid")
	}
	if got.EventCategory != "api" {
		t.Errorf("EventCategory = %q, want %q", got.EventCategory, "api")
	}
	if !got.Success {
		t.Error("Success = false, want true for StatusCode 200")
	}
	if !got.OccurredAt.Equal(occurred) {
		t.Errorf("OccurredAt = %v, want %v", got.OccurredAt, occurred)
	}

	// Non-UUID external ids (e.g. Stripe pi_*/in_* ids) must not panic and
	// must simply leave ResourceID unset.
	evt.ResourceID = "in_1QxYz"
	got = convertAuditEventToActivityLog(evt)
	if got.ResourceID != nil {
		t.Errorf("ResourceID = %v, want nil for non-UUID external id", got.ResourceID)
	}
}
