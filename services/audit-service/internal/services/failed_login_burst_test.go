package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// The tests in alert_service_test.go prove the RAIL: given an Alert, the raise
// reaches alerts.raise correctly. They cannot prove the DETECTOR, because they
// build the Alert themselves (via createAlert/executeActions) and hand-write the
// event as `event_type: "user.login.failed"` — the shape the rule expects rather
// than the shape auth-service emits. Under that shape the rail was green while
// failed_login_burst could not fire at all: the emitter writes
// "user.login_failed", and the rule's substring test cannot bridge `.` and `_`.
//
// These tests drive the detector end to end through EvaluateEvent, using the
// event shape the ingestion paths actually build.

// emittedFailedLogin mirrors, field for field, the map both audit ingestion
// paths build from auth-service's failed-login ActivityLogRequest.
func emittedFailedLogin(tenantID, userID *uuid.UUID) map[string]interface{} {
	return map[string]interface{}{
		"id":             uuid.New(),
		"event_type":     "user.login_failed",
		"event_category": "authentication",
		"action":         "login_failed",
		"success":        false,
		"user_id":        userID,
		"tenant_id":      tenantID,
	}
}

func TestFailedLoginRule_MatchesTheEventTypeAuthServiceEmits(t *testing.T) {
	svc, _, _ := newTestAlertService()
	var rule AlertRule
	for _, r := range svc.getDefaultRules() {
		if r.ID == failedLoginRuleID {
			rule = r
		}
	}
	if rule.ID == uuid.Nil {
		t.Fatal("failed-login rule missing from the built-in rules")
	}

	tenantID, userID := uuid.New(), uuid.New()
	if !svc.matchesConditions(emittedFailedLogin(&tenantID, &userID), rule.Conditions) {
		t.Fatal(`rule does not match event_type "user.login_failed", which is what auth-service emits`)
	}

	// Negative control: a successful login of the same shape must not match.
	ok := emittedFailedLogin(&tenantID, &userID)
	ok["event_type"] = "user.login"
	ok["success"] = true
	if svc.matchesConditions(ok, rule.Conditions) {
		t.Fatal("rule matched a successful login")
	}
}

func TestFailedLoginBurst_RequiresTheDeclaredThreshold(t *testing.T) {
	s, raises, _ := newTestAlertService()
	if err := s.LoadRules(context.Background()); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	tenantID, userID := uuid.New(), uuid.New()

	// The rule declares 5 failures in 5 minutes. Four must stay silent — the
	// defect this pins is the opposite: ThresholdCount was declared but never
	// read, so the FIRST failure would have raised a "burst".
	for i := 1; i < 5; i++ {
		s.EvaluateEvent(context.Background(), emittedFailedLogin(&tenantID, &userID))
		if len(*raises) != 0 {
			t.Fatalf("alert raised after %d failure(s); the rule declares a threshold of 5", i)
		}
	}

	s.EvaluateEvent(context.Background(), emittedFailedLogin(&tenantID, &userID))
	if len(*raises) != 1 {
		t.Fatalf("a burst of 5 failures produced %d alerts, want 1", len(*raises))
	}

	ev := (*raises)[0]
	if ev.AlertType != alertTypeFailedLoginBurst {
		t.Fatalf("alert_type = %q, want the registry id %q", ev.AlertType, alertTypeFailedLoginBurst)
	}
	if ev.TenantID != tenantID {
		t.Fatalf("alert tenant = %s, want %s", ev.TenantID, tenantID)
	}
	if ev.SubjectID == nil || *ev.SubjectID != userID {
		t.Fatalf("alert subject = %v, want the failing user %s", ev.SubjectID, userID)
	}
	if ev.Metadata["event_count"] != 5 {
		t.Fatalf("event_count = %v, want 5", ev.Metadata["event_count"])
	}
}

func TestFailedLoginBurst_WindowIsScopedPerAccount(t *testing.T) {
	s, raises, _ := newTestAlertService()
	if err := s.LoadRules(context.Background()); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	tenantID := uuid.New()

	// Five failures spread across five accounts is not a burst against any one
	// of them, and must not aggregate into a phantom alert.
	for i := 0; i < 5; i++ {
		userID := uuid.New()
		s.EvaluateEvent(context.Background(), emittedFailedLogin(&tenantID, &userID))
	}
	if len(*raises) != 0 {
		t.Fatalf("failures spread across distinct accounts raised %d alerts, want 0", len(*raises))
	}
}

// TestUnthresholdedRules_StillFireImmediately — only the failed-login rule
// declares a burst threshold. Introducing the window must not make the other
// built-ins wait for a repeat that may never come.
func TestUnthresholdedRules_StillFireImmediately(t *testing.T) {
	s, _, notified := newTestAlertService()
	if err := s.LoadRules(context.Background()); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	tenantID := uuid.New()

	s.EvaluateEvent(context.Background(), map[string]interface{}{
		"event_type":     "security.alert",
		"event_category": "security",
		"action":         "detect",
		"success":        false,
		"tenant_id":      &tenantID,
	})
	if *notified == 0 {
		t.Fatal("a rule with no declared threshold did not fire on its first matching event")
	}
}
