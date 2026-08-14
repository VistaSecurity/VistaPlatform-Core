package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// RC3: a missing platform device-interrogation sensor is a broken
// invariant, not a missing optional prerequisite, and it used to degrade to
// "write discovery_findings and stop" — which never reaches inventory. On a
// scheduled scan that is a silent no-op on a timer.
//
// These pin the three parts of the fix against a real Postgres, because all
// three are statements about rows: what the provisioning trigger creates, what
// the lookup's predicate selects, and what the job records when it fails.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

// TestIntegration_LookupSystemSensor_IgnoresSoftDeleted is F6b.
//
// `sensors` soft-deletes. Without `deleted_at IS NULL` the lookup kept returning
// the deleted row's id, so every interrogated asset was attributed to a sensor
// the user had removed — wrong rather than absent, which is also why the nil
// branch was almost never observed in the field.
func TestIntegration_LookupSystemSensor_IgnoresSoftDeleted(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	processor := NewResultProcessor(appDB, owner)

	// The trigger provisions the row; the lookup must find it.
	id, err := processor.lookupSystemSensor(ctx, tenantID)
	if err != nil {
		t.Fatalf("lookupSystemSensor on a fresh tenant: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("lookupSystemSensor returned uuid.Nil for a tenant the trigger provisioned")
	}

	// Soft-delete it, exactly as sensor-manager's repository does.
	if _, err := owner.Exec(`UPDATE sensors SET deleted_at = NOW() WHERE id = $1`, id); err != nil {
		t.Fatalf("soft-delete platform sensor: %v", err)
	}

	got, err := processor.lookupSystemSensor(ctx, tenantID)
	if !errors.Is(err, ErrNoPlatformSensor) {
		t.Fatalf("after soft delete: err = %v, want ErrNoPlatformSensor", err)
	}
	if got == id {
		t.Error("lookupSystemSensor returned the SOFT-DELETED sensor's id")
	}
	if got != uuid.Nil {
		t.Errorf("want uuid.Nil alongside the error, got %s", got)
	}
}

// TestIntegration_ProcessJobResults_FailsLoudlyWithoutPlatformSensor is F6.
//
// With no live platform sensor the run cannot reach inventory. It must therefore
// FAIL — visibly, on the job, with a reason — rather than complete having
// written findings nothing reads.
func TestIntegration_ProcessJobResults_FailsLoudlyWithoutPlatformSensor(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	// Break the invariant the way a tenant could before the delete guard existed.
	if _, err := owner.Exec(
		`UPDATE sensors SET deleted_at = NOW() WHERE tenant_id = $1`, tenantID); err != nil {
		t.Fatalf("soft-delete platform sensors: %v", err)
	}

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
		},
	}

	err := processor.ProcessJobResults(ctx, jobID, result)
	if !errors.Is(err, ErrNoPlatformSensor) {
		t.Fatalf("ProcessJobResults = %v, want an error wrapping ErrNoPlatformSensor", err)
	}

	// 1. The job itself must read as failed, with the reason — this is what the
	//    Discovery → Jobs list shows.
	var status string
	var errorMessage *string
	if err := owner.QueryRow(
		`SELECT status, error_message FROM device_jobs WHERE id = $1`, jobID,
	).Scan(&status, &errorMessage); err != nil {
		t.Fatalf("read back job: %v", err)
	}
	if status != string(models.JobStatusFailed) {
		t.Errorf("job status = %q, want %q", status, models.JobStatusFailed)
	}
	if errorMessage == nil || *errorMessage == "" {
		t.Error("job failed with no error_message — the user has nothing to act on")
	}

	// 2. The processing log must carry the fatal reason and must NOT claim a
	//    clean materialization.
	var resultsJSON string
	if err := owner.QueryRow(
		`SELECT results::text FROM device_jobs WHERE id = $1`, jobID,
	).Scan(&resultsJSON); err != nil {
		t.Fatalf("read back results: %v", err)
	}
	var stored struct {
		Processing struct {
			Fatal             string `json:"fatal"`
			FullyMaterialized bool   `json:"fully_materialized"`
		} `json:"processing"`
		// The agent's own payload must survive being marked failed — it is the
		// evidence of what the run found.
		Assets []map[string]interface{} `json:"assets"`
	}
	if err := json.Unmarshal([]byte(resultsJSON), &stored); err != nil {
		t.Fatalf("results not valid JSON: %v", err)
	}
	if stored.Processing.Fatal == "" {
		t.Error("processing.fatal is empty — the failure is invisible in the job detail")
	}
	if stored.Processing.FullyMaterialized {
		t.Error("fully_materialized = true on a run that reached nothing")
	}
	if len(stored.Assets) != len(result.Assets) {
		t.Errorf("agent payload was clobbered: %d assets stored, want %d", len(stored.Assets), len(result.Assets))
	}

	// 3. Nothing was written to the dead-end sink either: the run aborts before
	//    it can leave a trail of findings nothing will ever import.
	var findings int
	if err := owner.QueryRow(
		`SELECT count(*) FROM discovery_findings WHERE tenant_id = $1`, tenantID,
	).Scan(&findings); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if findings != 0 {
		t.Errorf("%d finding(s) written on an aborted run", findings)
	}
}

// TestIntegration_ProcessJobResults_SucceedsWithPlatformSensor is the opposite
// polarity: the guard must not fail a healthy tenant. A check that fires on the
// normal path is the same bug pointed the other way.
func TestIntegration_ProcessJobResults_SucceedsWithPlatformSensor(t *testing.T) {
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
		},
	}
	if err := processor.ProcessJobResults(ctx, jobID, result); err != nil {
		t.Fatalf("ProcessJobResults on a healthy tenant: %v", err)
	}

	var discoveries int
	if err := owner.QueryRow(
		`SELECT count(*) FROM sensor_discoveries WHERE tenant_id = $1`, tenantID,
	).Scan(&discoveries); err != nil {
		t.Fatalf("count sensor_discoveries: %v", err)
	}
	if discoveries != len(result.Assets) {
		t.Errorf("wrote %d sensor_discoveries, want %d — the unified pipeline is the path to inventory",
			discoveries, len(result.Assets))
	}
}
