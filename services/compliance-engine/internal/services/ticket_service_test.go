package services

// Pure-logic test for the SEC-4 fix: the overdue/due-soon dedupe key must be
// recorded only when the notification actually published, not before. These
// run without a database or NATS connection.

import (
	"errors"
	"testing"
	"time"
)

func TestRecordDueDateNotification_StoresKeyOnlyOnSuccess(t *testing.T) {
	s := &TicketService{}
	now := time.Now()
	key := "ticket-1|overdue"

	// SEC-4 mutation check: a failed publish must NOT record the dedupe key.
	// Before the fix, the key was stored unconditionally before the publish
	// attempt — this assertion is exactly what that bug would fail.
	s.recordDueDateNotification(key, now, errors.New("nats: publish failed"))
	if _, ok := s.dueNotifSent.Load(key); ok {
		t.Fatal("dedupe key was recorded despite a failed publish — SEC-4 regression")
	}

	// A successful publish DOES record the key, so the 24h dedupe window works.
	s.recordDueDateNotification(key, now, nil)
	got, ok := s.dueNotifSent.Load(key)
	if !ok {
		t.Fatal("dedupe key was not recorded after a successful publish")
	}
	if gt, ok2 := got.(time.Time); !ok2 || !gt.Equal(now) {
		t.Fatalf("stored dedupe timestamp = %v, want %v", got, now)
	}
}

func TestRecordDueDateNotification_RetriesAfterFailure(t *testing.T) {
	// Simulates two consecutive sweeps for the same ticket/bucket: first sweep's
	// publish fails, second sweep's publish succeeds. The key must reflect the
	// second (successful) attempt's timestamp, proving a failed publish doesn't
	// block the very next retry.
	s := &TicketService{}
	key := "ticket-2|due_soon_3d"

	firstAttempt := time.Now().Add(-time.Hour)
	s.recordDueDateNotification(key, firstAttempt, errors.New("connection refused"))
	if _, ok := s.dueNotifSent.Load(key); ok {
		t.Fatal("dedupe key recorded after failed first attempt")
	}

	secondAttempt := time.Now()
	s.recordDueDateNotification(key, secondAttempt, nil)
	got, ok := s.dueNotifSent.Load(key)
	if !ok {
		t.Fatal("dedupe key not recorded after successful second attempt")
	}
	if gt := got.(time.Time); !gt.Equal(secondAttempt) {
		t.Fatalf("stored dedupe timestamp = %v, want the successful attempt's time %v", gt, secondAttempt)
	}
}
