package services

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// newTestAlertService builds an AlertService with both sinks captured and no
// network: `raises` records what reached the stateful alert rail, `notified`
// counts the direct notification path.
func newTestAlertService() (*AlertService, *[]events.AlertRaiseEvent, *int) {
	raises := []events.AlertRaiseEvent{}
	notified := 0
	s := &AlertService{
		rules:        []AlertRule{},
		alertHistory: make(map[uuid.UUID]time.Time),
		logger:       log.New(log.Writer(), "[AlertServiceTest] ", 0),
	}
	s.publishRaise = func(ev events.AlertRaiseEvent) error {
		raises = append(raises, ev)
		return nil
	}
	s.notify = func(context.Context, Alert) error {
		notified++
		return nil
	}
	return s, &raises, &notified
}

func failedLoginEvent(tenantID, userID *uuid.UUID) map[string]interface{} {
	return map[string]interface{}{
		"event_type":     "user.login.failed",
		"event_category": "user",
		"action":         "login",
		"success":        false,
		"user_id":        userID,
		"tenant_id":      tenantID,
	}
}

func failedLoginAlert(s *AlertService, tenantID, userID *uuid.UUID) Alert {
	rule := s.getDefaultRules()[0] // Multiple Failed Login Attempts
	return s.createAlert(rule, failedLoginEvent(tenantID, userID))
}

// TestFailedLoginBurst_ReachesTheAlertRail is the regression test for the
// orphaned-type defect: failed_login_burst was `status: live` in the registry
// while audit-service only ever published a notification, so the burst never
// became a row in `alerts` and never appeared at Remediation → Alerts.
func TestFailedLoginBurst_ReachesTheAlertRail(t *testing.T) {
	s, raises, _ := newTestAlertService()
	tenantID, userID := uuid.New(), uuid.New()
	alert := failedLoginAlert(s, &tenantID, &userID)

	s.executeActions(context.Background(), alert, nil)

	if len(*raises) != 1 {
		t.Fatalf("published %d alert raises, want 1", len(*raises))
	}
	ev := (*raises)[0]
	if ev.AlertType != "failed_login_burst" {
		t.Errorf("AlertType = %q, want %q", ev.AlertType, "failed_login_burst")
	}
	if ev.AlertType == alert.RuleName {
		t.Errorf("AlertType is the free-text rule name %q, want the registry id", alert.RuleName)
	}
	if ev.TenantID != tenantID {
		t.Errorf("TenantID = %s, want %s", ev.TenantID, tenantID)
	}
	if ev.Source != "audit" {
		t.Errorf("Source = %q, want %q", ev.Source, "audit")
	}
	if ev.SubjectType != "user" {
		t.Errorf("SubjectType = %q, want %q (registry subject_type)", ev.SubjectType, "user")
	}
	if ev.SubjectID == nil || *ev.SubjectID != userID {
		t.Errorf("SubjectID = %v, want the user id %s", ev.SubjectID, userID)
	}
	if ev.Severity != "high" {
		t.Errorf("Severity = %q, want %q", ev.Severity, "high")
	}
}

// TestFailedLoginBurst_DoesNotDoubleNotify — the alert engine fans a
// notification out itself on open and on escalation, so a producer that
// publishes the raise must NOT also publish the direct notification.
func TestFailedLoginBurst_DoesNotDoubleNotify(t *testing.T) {
	s, raises, notified := newTestAlertService()
	tenantID, userID := uuid.New(), uuid.New()

	s.executeActions(context.Background(), failedLoginAlert(s, &tenantID, &userID), nil)

	if len(*raises) != 1 || *notified != 0 {
		t.Fatalf("raises=%d notifications=%d, want 1/0 (the engine notifies on open)", len(*raises), *notified)
	}
}

// TestFailedLoginBurst_SubjectIsStableAcrossDetections — the engine dedupes on
// (tenant, alert_type, subject_id). A per-detection random id would open a fresh
// alert every burst, which is the failure mode this subject choice avoids.
func TestFailedLoginBurst_SubjectIsStableAcrossDetections(t *testing.T) {
	s, raises, _ := newTestAlertService()
	tenantID, userID := uuid.New(), uuid.New()

	for i := 0; i < 3; i++ {
		if !s.raiseRailAlert(failedLoginAlert(s, &tenantID, &userID)) {
			t.Fatalf("detection %d: raise not taken by the rail", i)
		}
	}
	if len(*raises) != 3 {
		t.Fatalf("published %d raises, want 3", len(*raises))
	}
	for i, ev := range *raises {
		if ev.SubjectID == nil || *ev.SubjectID != userID {
			t.Fatalf("raise %d: SubjectID = %v, want the stable user id %s", i, ev.SubjectID, userID)
		}
	}
}

// TestRailUnavailable_FallsBackToNotification — NATS being down must degrade to
// a notification, never to silence.
func TestRailUnavailable_FallsBackToNotification(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()

	t.Run("publish fails", func(t *testing.T) {
		s, raises, notified := newTestAlertService()
		s.publishRaise = func(events.AlertRaiseEvent) error { return context.DeadlineExceeded }
		s.executeActions(context.Background(), failedLoginAlert(s, &tenantID, &userID), nil)
		if len(*raises) != 0 || *notified != 1 {
			t.Fatalf("raises=%d notifications=%d, want 0/1", len(*raises), *notified)
		}
	})

	t.Run("no NATS client wired", func(t *testing.T) {
		s, raises, notified := newTestAlertService()
		s.publishRaise = nil
		s.executeActions(context.Background(), failedLoginAlert(s, &tenantID, &userID), nil)
		if len(*raises) != 0 || *notified != 1 {
			t.Fatalf("raises=%d notifications=%d, want 0/1", len(*raises), *notified)
		}
	})
}

// TestUnmappedRules_AreNotRaisedUnderSomeoneElsesType — only the failed-login
// rule maps onto a registry alert type. Blanket-raising every audit rule would
// file bulk-export and privileged-action alerts as "failed_login_burst".
func TestUnmappedRules_AreNotRaisedUnderSomeoneElsesType(t *testing.T) {
	s, raises, notified := newTestAlertService()
	tenantID := uuid.New()

	for _, rule := range s.getDefaultRules()[1:] {
		alert := s.createAlert(rule, map[string]interface{}{"tenant_id": &tenantID})
		s.executeActions(context.Background(), alert, nil)
	}

	if len(*raises) != 0 {
		t.Fatalf("published %d raises for unmapped rules, want 0 (got %q)", len(*raises), (*raises)[0].AlertType)
	}
	if *notified != len(s.getDefaultRules())-1 {
		t.Fatalf("notified %d times, want %d — unmapped rules must keep notifying", *notified, len(s.getDefaultRules())-1)
	}
}

// TestTenantlessAlert_IsNotRaised — `alerts` is tenant-scoped and NOT NULL, so a
// platform-level audit event with no tenant cannot become a stateful alert. It
// must still notify.
func TestTenantlessAlert_IsNotRaised(t *testing.T) {
	s, raises, notified := newTestAlertService()
	userID := uuid.New()

	s.executeActions(context.Background(), failedLoginAlert(s, nil, &userID), nil)

	if len(*raises) != 0 || *notified != 1 {
		t.Fatalf("raises=%d notifications=%d, want 0/1", len(*raises), *notified)
	}
}

// TestFailedLoginBurst_UnknownUserGetsNilSubject — a burst against an
// unrecognised account has no user id. A nil subject dedupes as the tenant's one
// "unknown user" burst; inventing a random id would open one alert per attempt.
func TestFailedLoginBurst_UnknownUserGetsNilSubject(t *testing.T) {
	s, raises, _ := newTestAlertService()
	tenantID := uuid.New()

	if !s.raiseRailAlert(failedLoginAlert(s, &tenantID, nil)) {
		t.Fatal("raise not taken by the rail")
	}
	if (*raises)[0].SubjectID != nil {
		t.Fatalf("SubjectID = %v, want nil for an unresolved user", (*raises)[0].SubjectID)
	}
}
