package services

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// The doorbell publishes on the shared subject the export-feed consumer
// subscribes to — a typo'd subject is a doorbell nobody hears, which would
// pass every other test (the consumer's poll still delivers, just late).
func TestNATSDoorbell_RingsTheSharedSubject(t *testing.T) {
	var subjects []string
	d := &NATSDoorbell{publish: func(subject string, data []byte) error {
		subjects = append(subjects, subject)
		if len(data) == 0 {
			t.Error("empty doorbell payload")
		}
		return nil
	}}
	RingStored(d, &models.ActivityLog{})
	if len(subjects) != 1 || subjects[0] != events.SubjectDoorbellAuditStored {
		t.Fatalf("published to %v; want exactly [%s]", subjects, events.SubjectDoorbellAuditStored)
	}
}

// Ring is fire-and-forget: a failed publish is swallowed, and an unattached
// doorbell (NATS not reachable yet) rings nothing without panicking.
func TestNATSDoorbell_IsFireAndForget(t *testing.T) {
	d := &NATSDoorbell{publish: func(string, []byte) error { return errors.New("nats down") }}
	d.Ring()
	NewNATSDoorbell().Ring()
	var nilBell *NATSDoorbell
	nilBell.Ring()
	RingStored(nil, &models.ActivityLog{})
	RingStored(d, nil)
}
