package services

// The discovery.queue.ready WIRING of the Platform Sensor's unit commit
// ( WP1): a scan-plan unit run through the real processor commits its
// findings into sensor_discoveries (jobunits.Commit) and must then wake
// discovery-processor — once per committed unit, after the commit, with the
// tenant and the job id the mirror rows carry as their batch.
//
// Delete the publish in commitUnit and this goes red.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/events/eventstest"
)

func TestIntegration_CommitUnit_PublishesQueueReady(t *testing.T) {
	f, fake := newUnitFixture(t)
	fake.Host("10.183.8.10", map[uint16]string{25: ServeBanner(t, "220 mx.example.test ESMTP\r\n")}, nil)
	rec := &eventstest.Recorder{}
	f.jp.queuePublisher = rec
	jobID := f.createPlanJob(t, "25", "10.183.8.10")

	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("processing: %v", err)
	}
	var queued int
	if err := f.raw.QueryRow(`SELECT COUNT(*) FROM sensor_discoveries WHERE batch_id = $1`, jobID).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued == 0 {
		t.Fatal("the unit queued nothing into sensor_discoveries; this fixture no longer exercises the mirror, so the test proves nothing")
	}
	got := rec.QueueReady()
	if len(got) != 1 {
		t.Fatalf("one committed unit published %d discovery.queue.ready event(s), want exactly 1", len(got))
	}
	if got[0].TenantID != f.tenant || got[0].BatchID != jobID {
		t.Fatalf("event = tenant %s batch %s, want tenant %s batch %s", got[0].TenantID, got[0].BatchID, f.tenant, jobID)
	}
}

// NewJobProcessor — what main builds — must hand its NATS client to the
// queue publisher, or production publishes into a nil client.
func TestNewJobProcessor_WiresQueuePublisherToTheNATSClient(t *testing.T) {
	jp := NewJobProcessor(nil, nil, nil, nil, nil, nil)
	if jp.queuePublisher == nil {
		t.Fatal("NewJobProcessor left queuePublisher as a nil interface; it must carry the (possibly nil) NATS client so a missing client is reported, and a present one is used")
	}
}
