package services

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// insertDeviceAgent seeds a registered device agent for a tenant using the owner
// connection (which bypasses RLS, like the production bypass role), returning its
// id. registration_key/platform/version are NOT NULL in the schema.
func insertDeviceAgent(t *testing.T, db *sql.DB, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(
		`INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, profile, status)
		 VALUES ($1, $2, $3, 'linux', '1.0', 'device_interrogation', 'active')`,
		id, tenantID, "regkey-"+id.String(),
	)
	if err != nil {
		t.Fatalf("insertDeviceAgent(tenant %s): %v", tenantID, err)
	}
	return id
}

// connectJobClaimRedis returns a client for REDIS_URL (default localhost:6379),
// skipping the test when Redis is unreachable. REDIS_URL is a redis:// URL in
// the nightly job, which is not a valid Options.Addr: passed straight through,
// the dial failed and both job-claim tests skipped, green, on every nightly run.
// Accept the URL form and fall back to a bare host:port for local runs.
func connectJobClaimRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("REDIS_URL")
	if addr == "" {
		addr = "localhost:6379"
	}
	opts, err := redis.ParseURL(addr)
	if err != nil {
		opts = &redis.Options{Addr: addr}
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis unreachable at %s (%v) — skipping job-claim integration test", addr, err)
	}
	return rdb
}

// TestIntegration_SubmitJobResult_CrossTenantWriteBlocked proves the fix for
// the most severe path: an agent cannot submit results for a job owned by another
// tenant (which would forge discovery findings into that tenant's inventory) or for
// a job explicitly assigned to a different agent. SubmitJobResult authenticates the
// caller only by agent id and takes the job id from the (attacker-controllable)
// request body, so the tenant-ownership guard is enforced in the service layer on
// the BYPASSRLS connection — exactly what this real-DB test exercises.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).
func TestIntegration_SubmitJobResult_CrossTenantWriteBlocked(t *testing.T) {
	db := testdb.Connect(t)
	tenantA := testdb.NewTenant(t, db)
	tenantB := testdb.NewTenant(t, db)
	ctx := context.Background()

	agentA := insertDeviceAgent(t, db, tenantA)
	agentB := insertDeviceAgent(t, db, tenantB)

	// SubmitJobResult never touches Redis, so a nil client is fine here.
	svc := NewAgentService(db, db, nil)
	jobQueue := NewJobQueueService(db, db, nil)

	// Use an UNASSIGNED job owned by tenant A (agent_id NULL). This isolates the
	// tenant-ownership guard as the ONLY thing standing between agent B and the
	// write — a job assigned to a specific agent would also be caught by the
	// secondary agent-ownership check, masking a tenant-guard regression. An
	// unassigned device_interrogation job requires a device_id per the CHECK
	// constraint, so seed a tenant-A device first.
	deviceSvc := NewDeviceService(db)
	hostname := "target-a.example.test"
	dev, err := deviceSvc.CreateDevice(ctx, tenantA, models.CreateDeviceRequest{
		DeviceType: "cisco_ios",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice(tenantA) = %v, want nil", err)
	}
	jobA, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantA,
		JobType:  models.JobTypeDeviceInterrogation,
		AssetID:  &dev.ID, // agent_id stays NULL → unassigned, tenant-A owned
	})
	if err != nil {
		t.Fatalf("CreateJob(tenantA) = %v, want nil", err)
	}

	// Agent B (tenant B) tries to complete tenant A's job → must be rejected by
	// the tenant guard and leave the job untouched.
	err = svc.SubmitJobResult(ctx, agentB, &models.JobResult{JobID: jobA.ID, Success: true})
	if !errors.Is(err, ErrJobTenantMismatch) {
		t.Fatalf("SubmitJobResult(agentB, jobA) = %v, want ErrJobTenantMismatch", err)
	}
	after, err := jobQueue.GetJobByID(ctx, jobA.ID)
	if err != nil {
		t.Fatalf("GetJobByID(jobA) = %v, want nil", err)
	}
	if after.Status == models.JobStatusCompleted {
		t.Fatal("cross-tenant SubmitJobResult marked tenantA's job completed (write leaked)")
	}

	// Submitting a result for a non-existent job id is reported the same way (no
	// existence probe).
	if err := svc.SubmitJobResult(ctx, agentA, &models.JobResult{JobID: uuid.New(), Success: true}); !errors.Is(err, ErrJobTenantMismatch) {
		t.Fatalf("SubmitJobResult(agentA, unknown job) = %v, want ErrJobTenantMismatch", err)
	}

	// An agent in the OWNING tenant cannot complete a job it never claimed
	// either: filing a result against an unclaimed job would let it choose the
	// asset its findings are attributed to (review of).
	if err := svc.SubmitJobResult(ctx, agentA, &models.JobResult{JobID: jobA.ID, Success: true}); !errors.Is(err, ErrJobTenantMismatch) {
		t.Fatalf("SubmitJobResult(agentA, unclaimed jobA) = %v, want ErrJobTenantMismatch", err)
	}

	// Once agent A has claimed it and is running it — what GetNextJob does —
	// the result is accepted.
	if _, err := db.ExecContext(ctx, `UPDATE device_jobs SET agent_id=$1, status='in_progress' WHERE id=$2`, agentA, jobA.ID); err != nil {
		t.Fatalf("claim jobA for agentA: %v", err)
	}
	if err := svc.SubmitJobResult(ctx, agentA, &models.JobResult{JobID: jobA.ID, Success: true}); err != nil {
		t.Fatalf("SubmitJobResult(agentA, claimed jobA) = %v, want nil", err)
	}
	done, err := jobQueue.GetJobByID(ctx, jobA.ID)
	if err != nil {
		t.Fatalf("GetJobByID(jobA) after owner submit = %v, want nil", err)
	}
	if done.Status != models.JobStatusCompleted {
		t.Fatalf("owner SubmitJobResult left status %q, want completed", done.Status)
	}
}

// TestIntegration_GetNextJobForAgent_CrossTenantClaimBlocked proves the fix
// for the unassigned-job dispatch path: an unassigned device_interrogation job is
// claimable only by an agent in the SAME tenant. Before the fix the `agent_id IS
// NULL` branch had no tenant filter, so the first agent to poll — from any tenant —
// received another tenant's unassigned job and its credentials.
//
// Needs Redis (GetNextJobForAgent takes a per-agent assignment lock); skips if
// TEST_DATABASE_URL is unset or Redis (REDIS_URL, default localhost:6379) is
// unreachable.
func TestIntegration_GetNextJobForAgent_CrossTenantClaimBlocked(t *testing.T) {
	db := testdb.Connect(t)

	rdb := connectJobClaimRedis(t)

	tenantA := testdb.NewTenant(t, db)
	tenantB := testdb.NewTenant(t, db)
	ctx := context.Background()

	agentA := insertDeviceAgent(t, db, tenantA)
	agentB := insertDeviceAgent(t, db, tenantB)

	// An unassigned device_interrogation job requires a device_id per the
	// device_jobs CHECK constraint; create a real device under tenant A.
	deviceSvc := NewDeviceService(db)
	hostname := "target-a.example.test"
	dev, err := deviceSvc.CreateDevice(ctx, tenantA, models.CreateDeviceRequest{
		DeviceType: "cisco_ios",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice(tenantA) = %v, want nil", err)
	}

	jobQueue := NewJobQueueService(db, db, rdb)
	unassigned, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantA,
		JobType:  models.JobTypeDeviceInterrogation,
		AssetID:  &dev.ID, // agent_id stays NULL → unassigned, tenant-A owned
	})
	if err != nil {
		t.Fatalf("CreateJob(tenantA unassigned) = %v, want nil", err)
	}

	// Agent B (tenant B) must NOT be handed tenant A's unassigned job.
	gotB, err := jobQueue.GetNextJobForAgent(ctx, agentB)
	if err != nil {
		t.Fatalf("GetNextJobForAgent(agentB) = %v, want nil", err)
	}
	if gotB != nil {
		t.Fatalf("GetNextJobForAgent(agentB) claimed job %s (tenant %s) across tenants", gotB.ID, gotB.TenantID)
	}

	// Agent A (same tenant) still claims it.
	gotA, err := jobQueue.GetNextJobForAgent(ctx, agentA)
	if err != nil {
		t.Fatalf("GetNextJobForAgent(agentA) = %v, want nil", err)
	}
	if gotA == nil || gotA.ID != unassigned.ID {
		t.Fatalf("GetNextJobForAgent(agentA) = %v, want the tenant-A unassigned job %s", gotA, unassigned.ID)
	}
}

// TestIntegration_GetNextJob_UnassignedJobClaimedOnce exercises the race between
// the in-cluster platform worker and a tenant agent. They use different Redis
// locks, so the database claim itself must be atomic or both can receive the
// same unassigned device_interrogation job.
//
// A free-running goroutine race almost never lands both claimers between the
// re-select and the UPDATE (removing FOR UPDATE SKIP LOCKED failed 0/200), so
// the afterClaimSelect seam forces that interleaving: a claimer that has
// re-selected the job is held until the other claimer has either re-selected it
// too or returned. With the row lock, the second claimer skips the locked row
// and returns empty-handed; without it, both are parked holding the job and both
// UPDATEs succeed, because the UPDATE carries no status='pending' predicate.
func TestIntegration_GetNextJob_UnassignedJobClaimedOnce(t *testing.T) {
	db := testdb.Connect(t)

	rdb := connectJobClaimRedis(t)
	ctx := context.Background()

	tenantID := testdb.NewTenant(t, db)
	agentID := insertDeviceAgent(t, db, tenantID)
	_, _ = rdb.Del(ctx, "device_job:lock:agent:"+agentID.String(), "device_job:lock:platform").Result()

	deviceSvc := NewDeviceService(db)
	hostname := "race-target-" + uuid.New().String()[:8] + ".example.test"
	dev, err := deviceSvc.CreateDevice(ctx, tenantID, models.CreateDeviceRequest{
		DeviceType: "cisco_ios",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice = %v, want nil", err)
	}

	jobQueue := NewJobQueueService(db, db, rdb)
	unassigned, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenantID,
		JobType:  models.JobTypeDeviceInterrogation,
		AssetID:  &dev.ID,
	})
	if err != nil {
		t.Fatalf("CreateJob(unassigned) = %v, want nil", err)
	}

	// Hold every claimer that re-selected the job until each claimer has either
	// reached this point or returned. Each goroutine contributes exactly one of
	// those events: a parked claimer cannot return before the release.
	var (
		mu       sync.Mutex
		arrived  int
		finished int
		once     sync.Once
	)
	release := make(chan struct{})
	settle := func() { // mu held
		if arrived+finished == 2 {
			once.Do(func() { close(release) })
		}
	}
	jobQueue.afterClaimSelect = func(ctx context.Context, jobID uuid.UUID) {
		if jobID != unassigned.ID {
			return
		}
		mu.Lock()
		arrived++
		settle()
		mu.Unlock()
		select {
		case <-release:
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
			t.Errorf("claimer parked after re-select was never released")
		}
	}

	type claimResult struct {
		who string
		job *models.DeviceJob
		err error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	var wg sync.WaitGroup
	claim := func(who string, next func() (*models.DeviceJob, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, e := next()
			mu.Lock()
			finished++
			settle()
			mu.Unlock()
			results <- claimResult{who: who, job: got, err: e}
		}()
	}
	claim("agent", func() (*models.DeviceJob, error) { return jobQueue.GetNextJobForAgent(ctx, agentID) })
	claim("platform", func() (*models.DeviceJob, error) { return jobQueue.GetNextJobForPlatform(ctx) })
	close(start)
	wg.Wait()
	close(results)

	// The seam must have fired, or the claim path no longer passes through it
	// and this test has silently fallen back to an unforced race.
	if arrived == 0 {
		t.Fatalf("afterClaimSelect never saw job %s; the forced interleaving did not happen", unassigned.ID)
	}

	claims := 0
	for res := range results {
		if res.err != nil {
			t.Fatalf("%s claim returned error: %v", res.who, res.err)
		}
		if res.job == nil {
			continue
		}
		if res.job.ID != unassigned.ID {
			t.Fatalf("%s claimed unrelated job %s, want %s", res.who, res.job.ID, unassigned.ID)
		}
		claims++
	}
	if claims != 1 {
		t.Fatalf("unassigned job was claimed %d times, want exactly once", claims)
	}
}
