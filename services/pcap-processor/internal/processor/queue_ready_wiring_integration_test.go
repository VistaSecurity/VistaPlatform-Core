package processor

// The discovery.queue.ready WIRING of pcap-processor's sensor_discoveries
// writer ( WP1). It used to publish discovery.jobs.submit, which is
// cluster-sensor's scan-job subject (F10); now it publishes the processor's
// own wake-up, once per job, after the insert transaction commits.
//
// Delete the publish and this goes red; restore the old subject and the
// "nothing on discovery.jobs.submit" assertion does.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/events/eventstest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_InsertDiscoveriesIntoPipeline_PublishesQueueReady(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	if _, err := raw.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status)
		VALUES ($1, $2, 'Platform Discovery Sensor', 'platform', '1.0.0', 'discovery', 'active')`, uuid.New(), tenant); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}
	rec := &eventstest.Recorder{}
	p := &Processor{db: sqlx.NewDb(raw, "postgres"), queuePublisher: rec}

	jobID := uuid.New()
	err := p.insertDiscoveriesIntoPipeline(context.Background(), jobID, tenant, []CryptoDiscovery{
		{SourceIP: "192.0.2.5", DestIP: "203.0.113.40", DestPort: 443, Protocol: "TLS", SNI: "a.example.test", DiscoveryMethod: "pcap_upload", Timestamp: time.Now()},
		{SourceIP: "192.0.2.5", DestIP: "203.0.113.41", DestPort: 443, Protocol: "TLS", SNI: "b.example.test", DiscoveryMethod: "pcap_upload", Timestamp: time.Now()},
	})
	if err != nil {
		t.Fatalf("insertDiscoveriesIntoPipeline: %v", err)
	}
	var n int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM sensor_discoveries WHERE tenant_id = $1 AND batch_id = $2`, tenant, jobID.String()).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows inserted = %d (%v), want 2", n, err)
	}
	got := rec.QueueReady()
	if len(got) != 1 {
		t.Fatalf("one pcap job published %d discovery.queue.ready event(s), want exactly 1", len(got))
	}
	if got[0].TenantID != tenant || got[0].BatchID != jobID.String() {
		t.Fatalf("event = tenant %s batch %s, want tenant %s batch %s", got[0].TenantID, got[0].BatchID, tenant, jobID)
	}
	for _, m := range rec.Messages() {
		if m.Subject == events.SubjectDiscoveryJobsSubmit {
			t.Fatalf("pcap-processor published %s — cluster-sensor's scan-job subject, which it must no longer use as the processor's wake-up (F10)", m.Subject)
		}
	}
}

// New — what cmd/main.go builds — must hand its NATS client to the queue
// publisher, or production publishes into a nil client.
func TestNew_WiresQueuePublisherToTheNATSClient(t *testing.T) {
	p := New(nil, &config.Config{MaxConcurrentJobs: 1}, nil, nil)
	if p.queuePublisher == nil {
		t.Fatal("New left queuePublisher as a nil interface; it must carry the (possibly nil) NATS client")
	}
}
