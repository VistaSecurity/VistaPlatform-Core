package services

// C.7: interrogation jobs on the platform executor failed with
// "failed to interrogate device: failed to mark job completed:".
//
// The platform worker runs a job under one deadline. A device that spends it
// answering used to leave nothing for the writes that follow, so the LAST step
// failed on the spent context and the whole job was reported failed even though
// the device had answered. These drive the real worker sequence
// (executeDeviceInterrogation, then storeJobOutcome — what processNextJob runs)
// with a device that answers exactly when the job's deadline expires.
//
// MUTATION: delete the finalizeContext call after Interrogate in
// interrogateDevice and the run fails on the spent context.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// slowInterrogator answers only once the job's context is done: a device that
// takes the whole budget to collect from.
type slowInterrogator struct{}

func (slowInterrogator) SupportedDeviceTypes() []string { return []string{"fortigate"} }

func (slowInterrogator) Interrogate(ctx context.Context, _ di.DeviceInfo, _ di.Credentials) (*di.InterrogateResult, error) {
	<-ctx.Done()
	return &di.InterrogateResult{Assets: []di.CryptoAsset{*interrogatedAsset()}}, nil
}

func TestIntegration_InterrogationCompletesWhenTheDeviceSpendsTheJobsDeadline(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	base, cancelBase := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelBase()

	hostname := "fw-" + uuid.NewString()[:8] + ".corp.example.test"
	mgmt := "https://" + hostname
	user, pass := "readonly", "readonly-password"
	dev, err := NewDeviceServiceWithKey(owner, testMasterKey).CreateDevice(base, tenant, models.CreateDeviceRequest{
		DeviceType: "fortigate", Hostname: &hostname, ManagementURL: &mgmt, Username: &user, Password: &pass,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobQueue := NewJobQueueService(app, owner, nil)
	created, err := jobQueue.CreateJob(base, models.CreateDeviceJobRequest{
		TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &dev.ID,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	job, err := jobQueue.GetJobByID(base, created.ID)
	if err != nil {
		t.Fatalf("GetJobByID: %v", err)
	}

	interrogation := NewDeviceInterrogationService(app, owner, testMasterKey)
	interrogation.registry.Register(slowInterrogator{})
	worker := &PlatformAgentWorker{
		db: app, bypassDB: owner, jobQueue: jobQueue,
		deviceService:       NewDeviceServiceWithKey(app, testMasterKey),
		deviceInterrogation: interrogation,
		resultProcessor:     NewResultProcessor(app, owner),
	}

	// processNextJob's shape: one deadline over the whole run. The device only
	// answers once it has expired.
	runCtx, cancelRun := context.WithTimeout(base, 500*time.Millisecond)
	defer cancelRun()
	result, execErr := worker.executeDeviceInterrogation(runCtx, job)
	if runCtx.Err() == nil {
		t.Fatal("the job's deadline had not expired; the test did not exercise a spent budget")
	}
	if execErr != nil {
		t.Fatalf("a device that answered as the deadline expired failed the job: %v", execErr)
	}
	worker.storeJobOutcome(context.Background(), job, result, execErr)

	var status string
	var errMsg sql.NullString
	if err := owner.QueryRow(`SELECT status::text, error_message FROM device_jobs WHERE id = $1`, job.ID).Scan(&status, &errMsg); err != nil {
		t.Fatalf("read device job: %v", err)
	}
	if status != "completed" || errMsg.Valid {
		t.Errorf("device job = %q, error %q; want completed with no error", status, errMsg.String)
	}

	discoveryID, err := uuid.Parse(result.Metadata["discovery_job_id"].(string))
	if err != nil {
		t.Fatalf("result carries no discovery job id: %v", err)
	}
	var discoveryStatus string
	if err := owner.QueryRow(`SELECT status FROM discovery_jobs WHERE id = $1`, discoveryID).Scan(&discoveryStatus); err != nil {
		t.Fatalf("read discovery job: %v", err)
	}
	if discoveryStatus != "completed" {
		t.Errorf("discovery job = %q, want completed (it stays 'running' when the final UPDATE is lost)", discoveryStatus)
	}

	// The rows the run wrote must have landed, or "completed" is a lie.
	var landed int
	if err := owner.QueryRow(`SELECT count(*) FROM sensor_discoveries WHERE batch_id = $1`, discoveryID.String()).Scan(&landed); err != nil {
		t.Fatalf("count sensor_discoveries: %v", err)
	}
	if landed != 1 {
		t.Errorf("sensor_discoveries rows = %d, want 1", landed)
	}
	var stamped sql.NullString
	if err := owner.QueryRow(`SELECT results->'processing'->>'discovery_job_id' FROM device_jobs WHERE id = $1`, job.ID).Scan(&stamped); err == nil && stamped.Valid && stamped.String != discoveryID.String() {
		t.Errorf("device job stamped with discovery job %s, want %s", stamped.String, discoveryID)
	}
}

// A failed job's stored message keeps its cause when it is long, and an error
// with no message of its own is still named.
func TestIntegration_StoredJobErrorKeepsItsCause(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx := context.Background()

	jobQueue := NewJobQueueService(app, owner, nil)
	dev := subjectAsset(t, owner, tenant, "fw-"+uuid.NewString()[:8])
	created, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &dev,
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	cause := "pq: canceling statement due to user request (57014)"
	msg := "failed to interrogate device: failed to mark job completed: " + strings.Repeat("x", 6000) + cause
	if err := jobQueue.UpdateJobStatus(ctx, created.ID, models.JobStatusFailed, nil, &msg); err != nil {
		t.Fatalf("UpdateJobStatus: %v", err)
	}
	var stored string
	if err := owner.QueryRow(`SELECT error_message FROM device_jobs WHERE id = $1`, created.ID).Scan(&stored); err != nil {
		t.Fatalf("read error_message: %v", err)
	}
	if !strings.HasSuffix(stored, cause) {
		t.Errorf("the stored message lost its cause: ...%q", stored[max(0, len(stored)-80):])
	}
	if len(stored) > 4*maxJobErrorRunes {
		t.Errorf("stored message is %d bytes; the cap did not apply", len(stored))
	}
}
