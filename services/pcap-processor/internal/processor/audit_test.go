package processor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/nats-io/nats.go"

	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
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

// newTestProcessor builds a Processor whose every persistence path fails
// harmlessly: the DB points at a closed port and sensor-manager at an
// unroutable address. HandlePcapJob treats all of those as warnings, which is
// exactly what makes the audit assertion here meaningful — the audit record is
// the ONLY durable trace of the job, so it must be emitted on both outcomes.
func newTestProcessor(t *testing.T, sink AuditSink) *Processor {
	t.Helper()
	db, err := sqlx.Open("postgres", "postgres://u:p@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open stub db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := &config.Config{
		MaxConcurrentJobs: 1,
		SensorManagerURL:  "http://127.0.0.1:1",
	}
	return New(db, cfg, nil, sink)
}

func jobMsg(t *testing.T, job *events.PcapJobEvent) *nats.Msg {
	t.Helper()
	data, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("marshal job: %v", err)
	}
	return &nats.Msg{Subject: events.SubjectPcapJobsProcess, Data: data}
}

// writeEmptyPcap writes a valid libpcap file with a global header and zero
// packets, which processPcapFile opens successfully and walks in no time.
func writeEmptyPcap(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "empty.pcap")
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // magic
	binary.LittleEndian.PutUint16(hdr[4:], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4)          // version minor
	binary.LittleEndian.PutUint32(hdr[16:], 65535)     // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], 1)         // linktype EN10MB
	if err := os.WriteFile(path, hdr, 0o600); err != nil {
		t.Fatalf("write pcap: %v", err)
	}
	return path
}

// TestHandlePcapJob_AuditsSuccessfulJob pins the consumer-path audit record.
// pcap-processor ingests tenant-uploaded captures into the discovery pipeline
// and serves no tenant HTTP surface, so without this event the mutation is
// recorded nowhere.
func TestHandlePcapJob_AuditsSuccessfulJob(t *testing.T) {
	sink := &recordingSink{}
	p := newTestProcessor(t, sink)

	tenantID := uuid.New()
	jobID := uuid.New()
	job := events.NewPcapJobEvent(tenantID, jobID, writeEmptyPcap(t), "capture.pcap", 24)

	if err := p.HandlePcapJob(context.Background(), jobMsg(t, job)); err != nil {
		t.Fatalf("HandlePcapJob returned error: %v", err)
	}

	evts := sink.all()
	if len(evts) != 1 {
		t.Fatalf("recorded %d audit events, want 1", len(evts))
	}
	ev := evts[0]
	if ev.TenantID == nil || *ev.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", ev.TenantID, tenantID)
	}
	if ev.ResourceID == nil || *ev.ResourceID != jobID {
		t.Errorf("ResourceID = %v, want job id %v", ev.ResourceID, jobID)
	}
	if ev.Source != events.SubjectPcapJobsProcess {
		t.Errorf("Source = %q, want the NATS subject", ev.Source)
	}
	if !ev.Success {
		t.Errorf("Success = false for a job that completed")
	}
	if _, ok := ev.Counts["discoveries"]; !ok {
		t.Errorf("Counts missing discoveries: %#v", ev.Counts)
	}
	if _, ok := ev.Counts["packets_processed"]; !ok {
		t.Errorf("Counts missing packets_processed: %#v", ev.Counts)
	}
}

// TestHandlePcapJob_AuditsFailedJob — a capture that cannot be parsed is still
// a tenant-initiated processing attempt and must leave a record.
func TestHandlePcapJob_AuditsFailedJob(t *testing.T) {
	sink := &recordingSink{}
	p := newTestProcessor(t, sink)

	tenantID := uuid.New()
	jobID := uuid.New()
	job := events.NewPcapJobEvent(tenantID, jobID, filepath.Join(t.TempDir(), "missing.pcap"), "missing.pcap", 0)

	if err := p.HandlePcapJob(context.Background(), jobMsg(t, job)); err == nil {
		t.Fatal("expected HandlePcapJob to fail on a missing capture")
	}

	evts := sink.all()
	if len(evts) != 1 {
		t.Fatalf("recorded %d audit events, want 1", len(evts))
	}
	if evts[0].Success {
		t.Error("Success = true for a failed job")
	}
	if evts[0].ErrorKind == "" {
		t.Error("failed job recorded no error classification")
	}
}

// The audit trail says what was processed, never what was in it. The uploaded
// filename and the capture's contents must not appear.
func TestHandlePcapJob_AuditCarriesNoCaptureContent(t *testing.T) {
	sink := &recordingSink{}
	p := newTestProcessor(t, sink)

	job := events.NewPcapJobEvent(uuid.New(), uuid.New(), writeEmptyPcap(t), "secrets-in-the-name.pcap", 24)
	if err := p.HandlePcapJob(context.Background(), jobMsg(t, job)); err != nil {
		t.Fatalf("HandlePcapJob returned error: %v", err)
	}

	ev := sink.all()[0]
	if ev.ResourceRef == job.OriginalFilename || ev.Source == job.OriginalFilename {
		t.Error("uploaded filename leaked into the audit event")
	}
}

// A processor built without an audit sink must still process jobs.
func TestHandlePcapJob_NilAuditSinkIsSafe(t *testing.T) {
	p := newTestProcessor(t, nil)
	job := events.NewPcapJobEvent(uuid.New(), uuid.New(), writeEmptyPcap(t), "capture.pcap", 24)
	if err := p.HandlePcapJob(context.Background(), jobMsg(t, job)); err != nil {
		t.Fatalf("HandlePcapJob returned error with no audit sink: %v", err)
	}
}
