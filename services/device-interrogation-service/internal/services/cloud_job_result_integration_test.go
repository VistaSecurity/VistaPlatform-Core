package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// B-03, second half: GetJobByID omitted integration_id, so every consumer read
// nil for it — and ProcessJobResults gated its sensor_discoveries write on
// exactly that nil.
//
// The two defects cancelled out. Adding integration_id to the SELECT without
// also changing the gate would have flipped scheduled cloud discovery onto the
// "skip, it was written upstream" branch and silently stopped its assets
// reaching Inventory: the accidental nil was the only reason they arrived. These
// tests pin both halves so neither can be "fixed" alone again.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

// seedCloudIntegration creates the platform_integrations row device_jobs.integration_id
// references, on the owner connection.
func seedCloudIntegration(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO platform_integrations (id, tenant_id, integration_name, integration_type, provider, status)
		 VALUES ($1, $2, 'test-aws', 'aws', 'cloud', 'connected')`,
		id, tenantID); err != nil {
		t.Fatalf("seed platform_integration: %v", err)
	}
	return id
}

// TestIntegration_GetJobByID_CarriesIntegrationID is the narrow guard: the
// projection must include integration_id.
//
// Mutation check: drop integration_id from GetJobByID's SELECT and this fails,
// while nothing else in the package notices — which is how it stayed missing.
func TestIntegration_GetJobByID_CarriesIntegrationID(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)

	jobQueue := NewJobQueueService(appDB, owner, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:      tenantID,
		JobType:       models.JobTypeCloudDiscovery,
		IntegrationID: &integrationID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	got, err := jobQueue.GetJobByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJobByID: %v", err)
	}
	if got.IntegrationID == nil {
		t.Fatal("GetJobByID returned IntegrationID = nil for a cloud discovery job")
	}
	if *got.IntegrationID != integrationID {
		t.Errorf("IntegrationID = %v, want %v", *got.IntegrationID, integrationID)
	}
}

// TestIntegration_ProcessJobResults_CloudAssetsStillReachInventory is the
// non-regression guard for the scheduled cloud discovery path.
//
// The scheduled path (PlatformAgentWorker.executeCloudDiscovery) builds
// DiscoveredAssets and hands them here; unlike the interactive handler it writes
// no sensor_discoveries row of its own. If this processor skips the write for a
// job that carries an integration_id, a nightly cloud discovery silently stops
// producing inventory.
//
// Mutation check: restore the `if deviceJob.IntegrationID == nil` gate around
// the lookupSystemSensor call and this fails on the sensor_discoveries count.
func TestIntegration_ProcessJobResults_CloudAssetsStillReachInventory(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)

	jobQueue := NewJobQueueService(appDB, owner, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:      tenantID,
		JobType:       models.JobTypeCloudDiscovery,
		IntegrationID: &integrationID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	processor := NewResultProcessor(appDB, owner)
	result := &models.JobResult{
		JobID:   job.ID,
		Success: true,
		Assets: []models.DiscoveredAsset{{
			Hostname:        "lb.example.test",
			IPAddress:       "198.51.100.20",
			Port:            443,
			Protocol:        "TLS",
			ProtocolVersion: "TLS 1.2",
			CipherSuite:     "ECDHE-RSA-AES128-GCM-SHA256",
		}},
	}
	if err := processor.ProcessJobResults(ctx, job.ID, result); err != nil {
		t.Fatalf("ProcessJobResults: %v", err)
	}

	var sensorRows int
	var gotSensor uuid.UUID
	if err := owner.QueryRow(
		`SELECT count(*) OVER (), sensor_id FROM sensor_discoveries WHERE tenant_id = $1 LIMIT 1`, tenantID,
	).Scan(&sensorRows, &gotSensor); err != nil {
		t.Fatalf("cloud assets no longer reach Inventory — no sensor_discoveries row: %v", err)
	}
	if sensorRows != 1 {
		t.Fatalf("sensor_discoveries rows = %d, want 1", sensorRows)
	}

	// Attributed to the tenant's real platform sensor, not to a zero UUID.
	// sensor_discoveries.sensor_id carries no foreign key, so a row written with
	// an unresolved sensor id lands happily and then belongs to nobody.
	var wantSensor uuid.UUID
	if err := owner.QueryRow(
		`SELECT id FROM sensors
		  WHERE tenant_id = $1 AND profile = 'device_interrogation' AND 'system' = ANY(tags)
		    AND deleted_at IS NULL`, tenantID,
	).Scan(&wantSensor); err != nil {
		t.Fatalf("read platform sensor: %v", err)
	}
	if gotSensor != wantSensor {
		t.Errorf("sensor_id = %v, want the tenant's platform sensor %v", gotSensor, wantSensor)
	}

	// And the run is now labelled as what it was. With integration_id invisible,
	// a scheduled cloud discovery was recorded as
	// executed_via=device_interrogation on a discovery job whose execution_mode
	// read 'sensors'.
	var executedVia, executionMode string
	if err := owner.QueryRow(
		`SELECT f.executed_via, j.execution_mode
		   FROM discovery_findings f JOIN discovery_jobs j ON j.id = f.job_id
		  WHERE f.tenant_id = $1`, tenantID,
	).Scan(&executedVia, &executionMode); err != nil {
		t.Fatalf("read finding provenance: %v", err)
	}
	if executedVia != "cloud_discovery" {
		t.Errorf("discovery_findings.executed_via = %q, want cloud_discovery", executedVia)
	}
	if executionMode != "cloud" {
		t.Errorf("discovery_jobs.execution_mode = %q, want cloud", executionMode)
	}
}
