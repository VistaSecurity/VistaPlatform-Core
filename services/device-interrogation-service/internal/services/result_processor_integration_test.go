package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// These tests exist because the unit suite could not see the bug that mattered.
//
// CreateDiscoveryFinding omitted tenant_id from its INSERT while
// discovery_findings.tenant_id is NOT NULL, so every insert failed at the
// database. Nothing in the Go code type-checked wrongly and no mock could
// notice — only a real Postgres rejects the statement. Callers logged the error
// and carried on, so device interrogation produced targets and zero findings for
// every job while the UI kept reporting the run as a success.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

// insertDiscoveryJobAndTarget seeds the parent rows a finding needs, using the
// owner connection (which bypasses RLS, like the production bypass role).
func insertDiscoveryJobAndTarget(t *testing.T, db *sql.DB, tenantID uuid.UUID) (jobID, targetID uuid.UUID) {
	t.Helper()
	jobID, targetID = uuid.New(), uuid.New()
	if _, err := db.Exec(
		`INSERT INTO discovery_jobs (id, tenant_id, execution_mode, status)
		 VALUES ($1, $2, 'sensors', 'queued')`, jobID, tenantID); err != nil {
		t.Fatalf("seed discovery_job: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO discovery_targets (id, job_id, tenant_id, input, protocols, ports, status)
		 VALUES ($1, $2, $3, '198.51.100.1', ARRAY['TLS'], ARRAY[443], 'pending')`,
		targetID, jobID, tenantID); err != nil {
		t.Fatalf("seed discovery_target: %v", err)
	}
	return jobID, targetID
}

// TestIntegration_CreateDiscoveryFinding_PersistsWithTenant is the direct
// regression guard: the row must actually land, and land under the right tenant.
func TestIntegration_CreateDiscoveryFinding_PersistsWithTenant(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	jobID, targetID := insertDiscoveryJobAndTarget(t, owner, tenantID)

	// Exercise through the RLS-scoped app role, not the owner connection —
	// an owner bypasses RLS and would pass even if the tenant scoping were
	// wrong, which is exactly how this class of bug survives a green suite.
	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewDiscoveryIntegrationService(appDB, owner)

	host := "controller.example.net"
	ip := "198.51.100.1"
	findingID, err := svc.CreateDiscoveryFinding(
		ctx, tenantID, jobID, targetID, "device_interrogation",
		"TLS", 443, &host, &ip,
		map[string]interface{}{"cipher_suite": "TLS_AES_256_GCM_SHA384"}, 0.95,
	)
	if err != nil {
		t.Fatalf("CreateDiscoveryFinding: %v", err)
	}
	if findingID == uuid.Nil {
		t.Fatal("CreateDiscoveryFinding returned a nil id")
	}

	var gotTenant uuid.UUID
	var gotHost string
	if err := owner.QueryRow(
		`SELECT tenant_id, hostname FROM discovery_findings WHERE id = $1`, findingID,
	).Scan(&gotTenant, &gotHost); err != nil {
		t.Fatalf("finding row not found — the insert silently failed: %v", err)
	}
	if gotTenant != tenantID {
		t.Errorf("finding landed under tenant %s, want %s", gotTenant, tenantID)
	}
	if gotHost != host {
		t.Errorf("hostname = %q, want %q", gotHost, host)
	}
}

// TestIntegration_CreateDiscoveryFinding_RejectsMissingTenant proves the guard
// fails loudly rather than writing a row the RLS policy can never select back.
func TestIntegration_CreateDiscoveryFinding_RejectsMissingTenant(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	jobID, targetID := insertDiscoveryJobAndTarget(t, owner, tenantID)
	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewDiscoveryIntegrationService(appDB, owner)

	host := "controller.example.net"
	if _, err := svc.CreateDiscoveryFinding(
		ctx, uuid.Nil, jobID, targetID, "device_interrogation",
		"TLS", 443, &host, nil, nil, 0.95,
	); err == nil {
		t.Fatal("expected an error for a nil tenant id, got nil")
	}
}

// TestIntegration_ProcessJobResults_MaterializesAndLogs is the end-to-end claim
// the job detail modal makes: assets arrive, findings land, and the processing
// verdict is persisted so the UI can show "discovered vs materialized" honestly.
func TestIntegration_ProcessJobResults_MaterializesAndLogs(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	agentID := insertDeviceAgent(t, owner, tenantID)
	jobID := uuid.New()
	if _, err := owner.Exec(
		`INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, status)
		 VALUES ($1, $2, 'device_interrogation', $3, 'in_progress')`,
		jobID, tenantID, agentID); err != nil {
		t.Fatalf("seed device_job: %v", err)
	}

	appDB := testdb.ConnectAsAppRole(t, owner)
	processor := NewResultProcessor(appDB, owner)

	result := &models.JobResult{
		JobID:   jobID,
		Success: true,
		Assets: []models.DiscoveredAsset{
			{Hostname: "ap-one.example.net", IPAddress: "198.51.100.10", Port: 8443, Protocol: "TLS"},
			{Hostname: "", IPAddress: "198.51.100.1", Port: 443, Protocol: "TLS", CipherSuite: "TLS_AES_256_GCM_SHA384"},
		},
	}
	if err := processor.ProcessJobResults(ctx, jobID, result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	var findings int
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_findings WHERE tenant_id = $1`, tenantID,
	).Scan(&findings); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if findings != len(result.Assets) {
		t.Errorf("materialized %d findings, want %d", findings, len(result.Assets))
	}

	// The processing verdict must be readable back off the job — this is what
	// GET /jobs/{id}/results serves to the modal.
	var resultsJSON string
	if err := owner.QueryRow(
		`SELECT results::text FROM device_jobs WHERE id = $1`, jobID,
	).Scan(&resultsJSON); err != nil {
		t.Fatalf("read back results: %v", err)
	}
	var stored struct {
		Processing struct {
			AssetsReceived    int  `json:"assets_received"`
			FindingsCreated   int  `json:"findings_created"`
			FindingsFailed    int  `json:"findings_failed"`
			FullyMaterialized bool `json:"fully_materialized"`
		} `json:"processing"`
	}
	if err := json.Unmarshal([]byte(resultsJSON), &stored); err != nil {
		t.Fatalf("processing summary not valid JSON: %v", err)
	}
	if stored.Processing.AssetsReceived != len(result.Assets) {
		t.Errorf("assets_received = %d, want %d", stored.Processing.AssetsReceived, len(result.Assets))
	}
	if stored.Processing.FindingsCreated != len(result.Assets) || stored.Processing.FindingsFailed != 0 {
		t.Errorf("processing log disagrees with the database: %+v", stored.Processing)
	}
	if !stored.Processing.FullyMaterialized {
		t.Error("fully_materialized = false on a clean run")
	}
}

// TestIntegration_ProcessJobResults_ReusesStampedDiscoveryJob is the regression
// guard for the double-process found live on.
//
// The in-cluster executor interrogates the device itself, creating a discovery
// job and writing every target and finding into it, then hands the result
// processor a payload with no assets. The processor used to read that as "no
// discovery job yet" and create a SECOND one, which no executor ever picks up —
// it sits `queued` forever, owning nothing — and then pointed the job's
// processing log at that empty job. One UniFi run that found 12 devices reported
// 0 assets / 0 findings / fully_materialized: true against an empty job.
//
// The stamped id must be reused, and the log must describe the job that actually
// holds the findings.
func TestIntegration_ProcessJobResults_ReusesStampedDiscoveryJob(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	// The discovery job the interrogation already materialized into. It reaches
	// this processor already completed — InterrogateDevice runs it start to
	// finish — so any job still `queued` afterwards is one this processor
	// created and abandoned.
	discoveryJobID, targetID := insertDiscoveryJobAndTarget(t, owner, tenantID)
	if _, err := owner.Exec(
		`UPDATE discovery_jobs SET status = 'completed', completed_at = now() WHERE id = $1`,
		discoveryJobID); err != nil {
		t.Fatalf("complete seeded discovery job: %v", err)
	}
	const preexisting = 12
	for i := 0; i < preexisting; i++ {
		if _, err := owner.Exec(
			`INSERT INTO discovery_findings (id, job_id, target_id, tenant_id, executed_via, protocol, port, confidence_score)
			 VALUES ($1, $2, $3, $4, 'device_interrogation', 'TLS', 443, 0.95)`,
			uuid.New(), discoveryJobID, targetID, tenantID); err != nil {
			t.Fatalf("seed pre-existing finding: %v", err)
		}
	}

	// An in-cluster (agent_id NULL) interrogation names its device — the shape
	// valid_job_assignment requires, and the shape that produced this bug live.
	deviceID := seedDevice(t, owner, tenantID)
	deviceJobID := uuid.New()
	if _, err := owner.Exec(
		`INSERT INTO device_jobs (id, tenant_id, job_type, device_id, status)
		 VALUES ($1, $2, 'device_interrogation', $3, 'in_progress')`,
		deviceJobID, tenantID, deviceID); err != nil {
		t.Fatalf("seed device_job: %v", err)
	}

	appDB := testdb.ConnectAsAppRole(t, owner)

	// Exactly what the worker does after InterrogateDevice returns.
	queue := NewJobQueueService(appDB, owner, nil)
	if err := queue.RecordDiscoveryJob(ctx, deviceJobID, discoveryJobID); err != nil {
		t.Fatalf("RecordDiscoveryJob: %v", err)
	}

	var jobCountBefore int
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1`, tenantID,
	).Scan(&jobCountBefore); err != nil {
		t.Fatalf("count discovery_jobs: %v", err)
	}

	processor := NewResultProcessor(appDB, owner)
	emptyPayload := &models.JobResult{JobID: deviceJobID, Success: true, Assets: []models.DiscoveredAsset{}}
	if err := processor.ProcessJobResults(ctx, deviceJobID, emptyPayload); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	// 1. No second discovery job.
	var jobCountAfter int
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1`, tenantID,
	).Scan(&jobCountAfter); err != nil {
		t.Fatalf("count discovery_jobs: %v", err)
	}
	if jobCountAfter != jobCountBefore {
		t.Errorf("discovery_jobs went %d → %d: a second job was created for one interrogation", jobCountBefore, jobCountAfter)
	}
	var orphanQueued int
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_jobs WHERE tenant_id = $1 AND status = 'queued'`, tenantID,
	).Scan(&orphanQueued); err != nil {
		t.Fatalf("count queued discovery_jobs: %v", err)
	}
	if orphanQueued != 0 {
		t.Errorf("%d discovery job(s) left `queued` — these show as permanently queued on Discovery → Discovery Jobs", orphanQueued)
	}

	// 2. The processing log references the job that owns the findings, and its
	//    counts describe reality rather than the empty payload.
	var resultsJSON string
	if err := owner.QueryRow(
		`SELECT results::text FROM device_jobs WHERE id = $1`, deviceJobID,
	).Scan(&resultsJSON); err != nil {
		t.Fatalf("read back results: %v", err)
	}
	var stored struct {
		Processing struct {
			DiscoveryJobID    string `json:"discovery_job_id"`
			AssetsReceived    int    `json:"assets_received"`
			ExistingFindings  int    `json:"existing_findings"`
			Materialized      int    `json:"materialized"`
			FullyMaterialized bool   `json:"fully_materialized"`
		} `json:"processing"`
	}
	if err := json.Unmarshal([]byte(resultsJSON), &stored); err != nil {
		t.Fatalf("processing summary not valid JSON: %v", err)
	}
	if stored.Processing.DiscoveryJobID != discoveryJobID.String() {
		t.Errorf("processing log points at discovery job %s, want %s (the one holding the findings)",
			stored.Processing.DiscoveryJobID, discoveryJobID)
	}
	if stored.Processing.ExistingFindings != preexisting || stored.Processing.Materialized != preexisting {
		t.Errorf("processing log reports existing=%d materialized=%d, want %d for both",
			stored.Processing.ExistingFindings, stored.Processing.Materialized, preexisting)
	}

	// 3. A zero-asset payload against a job that holds findings is not a clean
	//    success — the run happened, the report of it does not describe it.
	if stored.Processing.FullyMaterialized {
		t.Error("fully_materialized = true on a zero-asset payload against a discovery job holding findings")
	}
}

// TestIntegration_ProcessJobResults_UnusableStampIsNotAForeignKey covers the
// other polarity of the reuse branch: a stamped value that is not a usable uuid
// must fall back to creating a discovery job, not write uuid.Nil onto every
// target and finding.
func TestIntegration_ProcessJobResults_UnusableStampIsNotAForeignKey(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	deviceID := seedDevice(t, owner, tenantID)
	deviceJobID := uuid.New()
	if _, err := owner.Exec(
		`INSERT INTO device_jobs (id, tenant_id, job_type, device_id, status, parameters)
		 VALUES ($1, $2, 'device_interrogation', $3, 'in_progress', '{"discovery_job_id": "not-a-uuid"}'::jsonb)`,
		deviceJobID, tenantID, deviceID); err != nil {
		t.Fatalf("seed device_job: %v", err)
	}

	appDB := testdb.ConnectAsAppRole(t, owner)
	processor := NewResultProcessor(appDB, owner)

	result := &models.JobResult{
		JobID:   deviceJobID,
		Success: true,
		Assets: []models.DiscoveredAsset{
			{Hostname: "ap-one.example.net", IPAddress: "198.51.100.10", Port: 8443, Protocol: "TLS"},
		},
	}
	if err := processor.ProcessJobResults(ctx, deviceJobID, result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	var findings, nilJobFindings int
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_findings WHERE tenant_id = $1`, tenantID,
	).Scan(&findings); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if findings != 1 {
		t.Errorf("materialized %d findings, want 1", findings)
	}
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_findings WHERE tenant_id = $1 AND job_id = $2`,
		tenantID, uuid.Nil).Scan(&nilJobFindings); err != nil {
		t.Fatalf("count nil-job findings: %v", err)
	}
	if nilJobFindings != 0 {
		t.Errorf("%d finding(s) written against a nil discovery job id", nilJobFindings)
	}
}
