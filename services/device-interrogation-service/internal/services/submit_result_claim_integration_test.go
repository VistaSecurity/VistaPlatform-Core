package services

// An agent may file a result only against the job it claimed and is running
// (review of). The result processor stamps the job's asset as the owner
// of every finding, so an agent that could choose the job could choose the
// asset its findings land on.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SubmitJobResult_OnlyTheClaimedRunningJob(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewAgentService(db, db, nil)

	agent := insertDeviceAgent(t, db, tenant)
	other := insertDeviceAgent(t, db, tenant)
	asset := subjectAsset(t, db, tenant, "fw-"+uuid.NewString()[:8])

	job := func(t *testing.T, jobType string, agentID *uuid.UUID, status string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := db.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
			VALUES ($1, $2, $3::device_job_type, $4, $5, $6::device_job_status)`, id, tenant, jobType, agentID, asset, status); err != nil {
			t.Fatalf("seed %s job: %v", jobType, err)
		}
		return id
	}

	for _, c := range []struct {
		name  string
		jobID uuid.UUID
		ok    bool
	}{
		{"claimed by this agent, running", job(t, "device_interrogation", &agent, "in_progress"), true},
		{"unclaimed (no agent)", job(t, "device_interrogation", nil, "pending"), false},
		// The platform worker's own in-cluster run: in progress, no agent.
		// Only the agent check stands between an agent and this job.
		{"running, but the platform worker's (no agent)", job(t, "device_interrogation", nil, "in_progress"), false},
		{"claimed by another agent", job(t, "device_interrogation", &other, "in_progress"), false},
		{"this agent's, not yet started", job(t, "device_interrogation", &agent, "assigned"), false},
		{"this agent's, already completed", job(t, "device_interrogation", &agent, "completed"), false},
		{"this agent's, failed", job(t, "device_interrogation", &agent, "failed"), false},
		{"this agent's host inventory, running", job(t, "host_inventory", &agent, "in_progress"), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := svc.SubmitJobResult(ctx, agent, &models.JobResult{JobID: c.jobID, Success: true})
			switch {
			case c.ok && err != nil:
				t.Fatalf("SubmitJobResult = %v, want accepted", err)
			case !c.ok && !errors.Is(err, ErrJobTenantMismatch):
				t.Fatalf("SubmitJobResult = %v, want ErrJobTenantMismatch", err)
			}
		})
	}
}
