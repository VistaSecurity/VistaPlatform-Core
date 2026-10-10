package services

// The discovery.queue.ready WIRING of device-interrogation's sensor_discoveries
// writers ( WP1): agent/interrogation results (writeSensorDiscovery, via
// the real ProcessJobResults), host-inventory connections (via the real
// MaterialiseAndRecord) and cloud at-rest resources (WriteSensorDiscoveries).
//
// Each drives the real path with a recording NATS stand-in installed as the
// process's queue publisher, and asserts one wake-up per committed write,
// carrying the tenant and the batch the rows were written under. Delete the
// publish in any writer and its test goes red.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/events/eventstest"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// installQueueRecorder makes rec the process's discovery-queue publisher for
// the test. Events are filtered by tenant, so a test elsewhere in the package
// publishing at the same moment cannot satisfy (or spoil) an assertion here.
func installQueueRecorder(t *testing.T) *eventstest.Recorder {
	t.Helper()
	rec := &eventstest.Recorder{}
	SetDiscoveryQueuePublisher(rec)
	t.Cleanup(func() { SetDiscoveryQueuePublisher(nil) })
	return rec
}

func queueReadyFor(rec *eventstest.Recorder, tenant uuid.UUID) []events.DiscoveryQueueReadyEvent {
	var out []events.DiscoveryQueueReadyEvent
	for _, ev := range rec.QueueReady() {
		if ev.TenantID == tenant {
			out = append(out, ev)
		}
	}
	return out
}

func distinctBatches(t *testing.T, owner *sql.DB, tenant uuid.UUID) []string {
	t.Helper()
	rows, err := owner.Query(`SELECT DISTINCT batch_id FROM sensor_discoveries WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func TestIntegration_ProcessJobResults_PublishesQueueReady(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()
	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	rec := installQueueRecorder(t)

	job, err := NewJobQueueService(appDB, owner, nil).CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantID, JobType: models.JobTypeDeviceInterrogation, AgentID: &agentID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := NewResultProcessor(appDB, owner).ProcessJobResults(ctx, job.ID, &models.JobResult{
		JobID: job.ID, Success: true,
		Assets: []models.DiscoveredAsset{{
			Hostname: "lb.example.net", IPAddress: "198.51.100.20", Port: 443, Protocol: "TLS",
			ProtocolVersion: "TLS 1.2", CipherSuite: "ECDHE-RSA-AES128-GCM-SHA256",
		}},
	}); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	batches := distinctBatches(t, owner, tenantID)
	if len(batches) != 1 {
		t.Fatalf("sensor_discoveries batches = %v, want exactly one — the fixture no longer writes the row this test is about", batches)
	}
	got := queueReadyFor(rec, tenantID)
	if len(got) != 1 {
		t.Fatalf("one written asset published %d discovery.queue.ready event(s), want exactly 1", len(got))
	}
	if got[0].BatchID != batches[0] {
		t.Fatalf("event batch = %s, want the rows' batch %s", got[0].BatchID, batches[0])
	}
}

func TestIntegration_HostInventoryConnections_PublishQueueReady(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)
	if _, err := owner.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,tags)
		VALUES($1,$2,'IT system interrogation','linux','test','device_interrogation','active',ARRAY['system'])`, uuid.New(), tenantID); err != nil {
		t.Fatalf("seed system sensor: %v", err)
	}
	rec := installQueueRecorder(t)

	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "QUEUE-WAKE-HOST", defaultPackages())
	rep.Sections[hostinventory.SectionConnections] = hostinventory.SectionOK
	rep.Connections = []hostinventory.Connection{
		{Proto: "tcp", LocalAddress: "198.51.100.20", LocalPort: 50111, RemoteAddress: "8.8.8.8", RemotePort: 443, Process: "browser", PID: 77},
		{Proto: "tcp", LocalAddress: "198.51.100.20", LocalPort: 50112, RemoteAddress: "10.40.0.15", RemotePort: 8443, Process: "agent", PID: 78},
	}
	obs := observationsFor(t, rep)
	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(t.Context(), tenantID, agentID, jobID, obs)
	if err != nil || counts.ConnectionsQueued != 2 {
		t.Fatalf("MaterialiseAndRecord = %+v %v, want 2 connections queued", counts, err)
	}
	want := "host-inventory-connections:" + jobID.String()
	var wakes []events.DiscoveryQueueReadyEvent
	for _, ev := range queueReadyFor(rec, tenantID) {
		if ev.BatchID == want {
			wakes = append(wakes, ev)
		}
	}
	if len(wakes) != 1 {
		t.Fatalf("queued connections published %d discovery.queue.ready event(s) for %s, want exactly 1 (all: %+v)", len(wakes), want, queueReadyFor(rec, tenantID))
	}

	// The replay queues nothing new (ON CONFLICT DO NOTHING), so it wakes
	// nobody.
	before := len(queueReadyFor(rec, tenantID))
	if replay, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(t.Context(), tenantID, agentID, jobID, obs); err != nil || replay.ConnectionsQueued != 0 {
		t.Fatalf("replay = %+v %v", replay, err)
	}
	for _, ev := range queueReadyFor(rec, tenantID)[before:] {
		if ev.BatchID == want {
			t.Fatal("a replay that queued no connection published a wake-up for them")
		}
	}
}

func TestIntegration_CloudWriteSensorDiscoveries_PublishesQueueReady(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	integration := seedCloudIntegration(t, owner, tenant)
	rec := installQueueRecorder(t)

	batch := uuid.New().String()
	n, err := NewCloudDiscoveryService(appDB, owner, testMasterKey).WriteSensorDiscoveries(
		context.Background(), tenant, batch, integration, "aws", []models.Device{s3Bucket("queue-wake-bucket")})
	if err != nil || n != 1 {
		t.Fatalf("WriteSensorDiscoveries = %d %v, want 1 row", n, err)
	}
	got := queueReadyFor(rec, tenant)
	if len(got) != 1 || got[0].BatchID != batch {
		t.Fatalf("cloud write published %+v, want exactly one discovery.queue.ready for batch %s", got, batch)
	}
}
