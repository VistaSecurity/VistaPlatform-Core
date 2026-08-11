package audit

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestToAuditEvent_PropagatesUserType pins the fix for: the NATS audit
// path must carry user_type through to the subscriber, otherwise every
// NATS-delivered audit event fails the activity_logs valid_user_type CHECK.
func TestToAuditEvent_PropagatesUserType(t *testing.T) {
	for _, userType := range []string{"tenant", "platform"} {
		t.Run(userType, func(t *testing.T) {
			entry := &ActivityLogRequest{
				UserType:   userType,
				Action:     "update",
				OccurredAt: time.Now(),
			}
			evt := toAuditEvent(entry)
			if evt.UserType != userType {
				t.Errorf("UserType = %q, want %q", evt.UserType, userType)
			}
		})
	}
}

// TestToAuditEvent_MapsCoreFields verifies the rest of the conversion still
// behaves as before the toAuditEvent extraction.
func TestToAuditEvent_MapsCoreFields(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	ip := "10.0.0.5"
	ua := "test-agent"
	occurred := time.Now().Add(-time.Minute)

	entry := &ActivityLogRequest{
		TenantID:      &tenantID,
		UserID:        &userID,
		UserType:      "tenant",
		EventType:     "asset.updated",
		EventCategory: "inventory",
		Action:        "update",
		IPAddress:     &ip,
		UserAgent:     &ua,
		OccurredAt:    occurred,
		Metadata: map[string]interface{}{
			"status_code": 201,
			"duration_ms": int64(42),
		},
	}

	evt := toAuditEvent(entry)

	if evt.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", evt.TenantID, tenantID)
	}
	if evt.UserID != userID.String() {
		t.Errorf("UserID = %q, want %q", evt.UserID, userID.String())
	}
	if evt.Action != "update" {
		t.Errorf("Action = %q, want %q", evt.Action, "update")
	}
	if evt.Resource != "inventory" {
		t.Errorf("Resource = %q, want %q", evt.Resource, "inventory")
	}
	if evt.IPAddress != ip {
		t.Errorf("IPAddress = %q, want %q", evt.IPAddress, ip)
	}
	if evt.UserAgent != ua {
		t.Errorf("UserAgent = %q, want %q", evt.UserAgent, ua)
	}
	if !evt.Timestamp.Equal(occurred) {
		t.Errorf("Timestamp = %v, want %v", evt.Timestamp, occurred)
	}
	if evt.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want 201", evt.StatusCode)
	}
	if evt.Duration != 42 {
		t.Errorf("Duration = %d, want 42", evt.Duration)
	}
}
