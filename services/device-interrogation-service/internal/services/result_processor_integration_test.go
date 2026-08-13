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
