package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type queueRecorder struct {
	subjects []string
	payloads [][]byte
	ids      []string
	err      error
}

func (r *queueRecorder) Publish(subject string, data []byte, msgID string) error {
	r.subjects = append(r.subjects, subject)
	r.payloads = append(r.payloads, data)
	r.ids = append(r.ids, msgID)
	return r.err
}

// captureLog redirects the standard logger for the duration of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return &buf
}

func TestPublishDiscoveryQueueReady_PublishesOneEventWithTenantAndBatch(t *testing.T) {
	rec := &queueRecorder{}
	tenant := uuid.New()
	if err := PublishDiscoveryQueueReady(context.Background(), rec, tenant, "batch-1", "test.writer"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(rec.subjects) != 1 || rec.subjects[0] != SubjectDiscoveryQueueReady {
		t.Fatalf("published %v, want exactly one %s", rec.subjects, SubjectDiscoveryQueueReady)
	}
	var ev DiscoveryQueueReadyEvent
	if err := json.Unmarshal(rec.payloads[0], &ev); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if ev.TenantID != tenant || ev.BatchID != "batch-1" || ev.Source != "test.writer" {
		t.Fatalf("event = %+v, want tenant %s batch batch-1 source test.writer", ev, tenant)
	}
	// The message id must be unique per publish, never derived from the
	// batch: JetStream de-duplicates on it, and one batch id legitimately
	// receives rows more than once (every unit of a scan job).
	if rec.ids[0] == "" || strings.Contains(rec.ids[0], "batch-1") {
		t.Fatalf("msgID %q must be a fresh id, not derived from the batch", rec.ids[0])
	}
	_ = PublishDiscoveryQueueReady(context.Background(), rec, tenant, "batch-1", "test.writer")
	if rec.ids[0] == rec.ids[1] {
		t.Fatalf("two publishes for one batch shared msgID %q; JetStream would drop the second wake", rec.ids[0])
	}
}

// The nil-client path: no panic, a WARNING naming the subject, and only once
// per process however many writes go through it. Both nil shapes — a nil
// interface and a typed nil *NATSClient, which is what a service passes when
// its optional NATS connect failed.
func TestPublishDiscoveryQueueReady_NilClientWarnsOnceAndDoesNotPanic(t *testing.T) {
	missingQueuePublisher = sync.Once{}
	t.Cleanup(func() { missingQueuePublisher = sync.Once{} })
	buf := captureLog(t)

	var typedNil *NATSClient
	for i, client := range []MessagePublisher{nil, typedNil, typedNil} {
		if err := PublishDiscoveryQueueReady(context.Background(), client, uuid.New(), "b", "test.nil"); err != nil {
			t.Fatalf("call %d: nil client returned %v; a missing client must never fail the caller's write", i, err)
		}
	}
	out := buf.String()
	if n := strings.Count(out, "WARNING"); n != 1 {
		t.Fatalf("logged %d warnings, want exactly 1 (once per process):\n%s", n, out)
	}
	if !strings.Contains(out, SubjectDiscoveryQueueReady) || !strings.Contains(out, "test.nil") {
		t.Fatalf("warning does not name the subject and the writer:\n%s", out)
	}
}

// A publish failure is reported, never swallowed — and the rows are already
// committed, so it is logged as a delay, not a loss.
func TestPublishDiscoveryQueueReady_PublishErrorIsReturnedAndLogged(t *testing.T) {
	buf := captureLog(t)
	rec := &queueRecorder{err: errors.New("nats down")}
	err := PublishDiscoveryQueueReady(context.Background(), rec, uuid.New(), "b", "test.err")
	if err == nil || !strings.Contains(err.Error(), "nats down") {
		t.Fatalf("err = %v, want the publish error", err)
	}
	if !strings.Contains(buf.String(), "fallback poll") {
		t.Fatalf("publish failure was not logged:\n%s", buf.String())
	}
}

// The wake-up subject lives in its own stream, and the scan-job subject stays
// where it was: sharing a stream (or a subject) is F10.
func TestDiscoveryQueueSubjectStreamMembership(t *testing.T) {
	owner := func(subject string) []string {
		var names []string
		for _, sc := range DefaultStreams {
			for _, f := range sc.Subjects {
				if subjectMatches(f, subject) {
					names = append(names, sc.Name)
				}
			}
		}
		return names
	}
	if got := owner(SubjectDiscoveryQueueReady); len(got) != 1 || got[0] != "DISCOVERY_QUEUE" {
		t.Fatalf("%s is captured by %v, want exactly [DISCOVERY_QUEUE]", SubjectDiscoveryQueueReady, got)
	}
	if got := owner(SubjectDiscoveryJobsSubmit); len(got) != 1 || got[0] != "DISCOVERY_JOBS" {
		t.Fatalf("%s is captured by %v, want exactly [DISCOVERY_JOBS]", SubjectDiscoveryJobsSubmit, got)
	}
	if SubjectDiscoveryQueueReady == SubjectDiscoveryJobsSubmit {
		t.Fatal("the processor wake-up and cluster-sensor's scan-job subject must differ (F10)")
	}
}
