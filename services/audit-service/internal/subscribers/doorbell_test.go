package subscribers

// The NATS ingestion path — which is also how batched audit entries arrive
// (AuditBatchEvent) — rings the stored-events doorbell once per STORED entry
// through the same services.RingStored seam as the HTTP handler, and never for
// an entry it failed to store.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

type countingDoorbell struct{ rings int }

func (d *countingDoorbell) Ring() { d.rings++ }

// failingWriter stores every entry except the ones whose action is "fail".
type failingWriter struct{ stored []uuid.UUID }

func (w *failingWriter) LogActivity(_ context.Context, e *models.ActivityLog) error {
	if e.Action == "fail" {
		return errors.New("insert refused")
	}
	w.stored = append(w.stored, e.ID)
	return nil
}

func TestNATSBatchIngestion_RingsOncePerStoredEntry(t *testing.T) {
	batch := events.AuditBatchEvent{
		EventID: uuid.New(), Source: "auth-service", Count: 3,
		Entries: []events.AuditEvent{
			{EventID: uuid.New(), Action: "login", EventType: "user.login", EventCategory: "authentication", StatusCode: 200, Timestamp: time.Now()},
			{EventID: uuid.New(), Action: "fail", StatusCode: 200, Timestamp: time.Now()},
			{EventID: uuid.New(), Action: "logout", EventType: "user.logout", EventCategory: "authentication", StatusCode: 200, Timestamp: time.Now()},
		},
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	d := &countingDoorbell{}
	w := &failingWriter{}
	sub := &AuditSubscriber{activityLogService: w, doorbell: d}
	_ = sub.handleAuditBatch(context.Background(), &nats.Msg{Data: data})

	if len(w.stored) != 2 {
		t.Fatalf("stored %d entries; the fixture expects 2", len(w.stored))
	}
	if d.rings != 2 {
		t.Fatalf("rang %d times; want once per stored entry (2) and never for the refused one", d.rings)
	}
}

func TestNATSBatchIngestion_NilDoorbellStillStores(t *testing.T) {
	data, _ := json.Marshal(events.AuditBatchEvent{Entries: []events.AuditEvent{{EventID: uuid.New(), Action: "x", Timestamp: time.Now()}}})
	w := &failingWriter{}
	sub := &AuditSubscriber{activityLogService: w}
	if err := sub.handleAuditBatch(context.Background(), &nats.Msg{Data: data}); err != nil {
		t.Fatal(err)
	}
	if len(w.stored) != 1 {
		t.Fatal("the entry was not stored")
	}
}
