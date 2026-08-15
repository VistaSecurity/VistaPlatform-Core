package processor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// recordingSink captures consumer audit events instead of shipping them.
type recordingSink struct {
	mu     sync.Mutex
	events []auditmiddleware.ConsumerEvent
}

func (r *recordingSink) LogConsumerEvent(_ context.Context, ev auditmiddleware.ConsumerEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *recordingSink) all() []auditmiddleware.ConsumerEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]auditmiddleware.ConsumerEvent, len(r.events))
	copy(out, r.events)
	return out
}

// newTestBatchProcessor points the batch processor at a closed port, so the
// first RLS-scoped read fails and ProcessBatch returns on its earliest error
// path. That path is the one worth pinning: a batch that never materialized
// anything is exactly the event an operator needs and the one an
// emit-at-the-bottom implementation would drop.
func newTestBatchProcessor(t *testing.T, sink AuditSink) *BatchProcessor {
	t.Helper()
	db, err := sqlx.Open("postgres", "postgres://u:p@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open stub db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewBatchProcessor(db, nil, nil, nil, sink)
}

// TestProcessBatch_AuditsFailedBatch pins the consumer-path audit record.
// discovery-processor-service materializes tenant assets with no tenant HTTP
// surface, so without this event its work is recorded nowhere.
func TestProcessBatch_AuditsFailedBatch(t *testing.T) {
	sink := &recordingSink{}
	p := newTestBatchProcessor(t, sink)

	tenantID := uuid.New()
	if err := p.ProcessBatch("batch-123", tenantID); err == nil {
		t.Fatal("expected ProcessBatch to fail against an unreachable database")
	}

	evts := sink.all()
	if len(evts) != 1 {
		t.Fatalf("recorded %d audit events, want 1", len(evts))
	}
	ev := evts[0]
	if ev.TenantID == nil || *ev.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", ev.TenantID, tenantID)
	}
	if ev.ResourceRef != "batch-123" {
		t.Errorf("ResourceRef = %q, want the batch id", ev.ResourceRef)
	}
	if ev.EventCategory != "discovery" {
		t.Errorf("EventCategory = %q, want discovery", ev.EventCategory)
	}
	if ev.Success {
		t.Error("Success = true for a batch that failed")
	}
	if ev.ErrorKind == "" {
		t.Error("failed batch recorded no error classification")
	}
}

// A batch processor built without an audit sink must still process batches.
func TestProcessBatch_NilAuditSinkIsSafe(t *testing.T) {
	p := newTestBatchProcessor(t, nil)
	if err := p.ProcessBatch("batch-123", uuid.New()); err == nil {
		t.Fatal("expected ProcessBatch to fail against an unreachable database")
	}
}

// The audit trail records a classification, never err.Error() — wrapped batch
// errors routinely quote the finding that failed to import.
func TestClassifyBatchError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"no valid findings", fmt.Errorf("%w for batch x", ErrNoValidFindings), "no_valid_findings"},
		{"inventory 4xx", &client.HTTPStatusError{StatusCode: http.StatusBadRequest}, "inventory_http_400"},
		{"anything else", errors.New("cert CN=secret.internal failed to parse"), "batch_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyBatchError(tc.err)
			if got != tc.want {
				t.Fatalf("classifyBatchError = %q, want %q", got, tc.want)
			}
			if tc.err != nil && got != "" && got == tc.err.Error() {
				t.Fatal("classification leaked the raw error text")
			}
		})
	}
}

// Counts describe volume, not content.
func TestLogBatchAudit_CountsOnly(t *testing.T) {
	sink := &recordingSink{}
	p := newTestBatchProcessor(t, sink)

	ba := &batchAudit{counts: map[string]int{"discoveries_read": 4, "internal_findings": 3}}
	ba.imported = 2
	p.logBatchAudit(context.Background(), uuid.New(), "batch-9", ba, nil)

	ev := sink.all()[0]
	if ev.Counts["assets_imported"] != 2 {
		t.Errorf("assets_imported = %d, want 2", ev.Counts["assets_imported"])
	}
	if ev.Counts["discoveries_read"] != 4 {
		t.Errorf("discoveries_read = %d, want 4", ev.Counts["discoveries_read"])
	}
	if !ev.Success {
		t.Error("Success = false for a batch that returned no error")
	}
}
