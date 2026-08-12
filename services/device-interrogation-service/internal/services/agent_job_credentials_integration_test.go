package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_GetNextJob_CarriesDeviceCredentialsToScheduledJob is the
// end-to-end proof, through real SQL, that a job created the way the scheduler
// creates them — no credentials at all — reaches an agent with usable ones.
//
// SchedulerService.TriggerSchedule (and so SchedulerWorker → ProcessDueSchedules,
// the automatic path) never sets Credentials. That was invisible because the
// in-cluster PlatformAgentWorker re-reads and decrypts credentials off the
// device row and ignores the job payload entirely. An agent has no database:
// it gets this payload and nothing else. Both consumers claim the same
// `agent_id IS NULL` queue, so registering a tenant's first device agent is
// what routes a scheduled interrogation to the one that cannot look anything
// up — the same shape as the missing address in.
func TestIntegration_GetNextJob_CarriesDeviceCredentialsToScheduledJob(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	agentID := uuid.New()
	registrationKey := "regkey-" + agentID.String()
	if _, err := db.Exec(`
		INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, profile, status)
		VALUES ($1, $2, $3, 'linux', '1.0', 'device_interrogation', 'active')`,
		agentID, tenant, registrationKey,
	); err != nil {
		t.Fatalf("insert device agent: %v", err)
	}

	// A device with embedded credentials, encrypted under the test master key.
	deviceSvc := NewDeviceService(db)
	deviceSvc.encryptionKey = testMasterKey
	hostname := "gw-" + uuid.New().String()[:8] + ".example.test"
	username := "admin"
	password := "sch3duled-p@ss"
	dev, err := deviceSvc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
		Username:   &username,
		Password:   &password,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// The scheduler's job shape: parameters forwarded verbatim, Credentials
	// never set.
	jobQueue := NewJobQueueService(db, db, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:   tenant,
		JobType:    models.JobTypeDeviceInterrogation,
		DeviceID:   &dev.ID,
		Parameters: map[string]interface{}{"device_type": "unifi"},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey // NewAgentService reads ENCRYPTION_MASTER_KEY from env

	// GetNextJob takes a Redis lock before reaching these; exercise the two
	// steps it delegates to, in the order it runs them.
	handed := job.ToJob()
	if len(handed.Credentials) != 0 {
		t.Fatalf("stored credentials = %v, want the scheduler's empty map", handed.Credentials)
	}
	if err := svc.resolveJobCredentials(ctx, tenant, handed); err != nil {
		t.Fatalf("resolveJobCredentials = %v, want nil", err)
	}
	sealed, err := svc.sealJobCredentials(ctx, agentID, handed)
	if err != nil {
		t.Fatalf("sealJobCredentials = %v, want nil", err)
	}

	if !agentcreds.IsSealed(sealed) {
		t.Fatalf("credentials handed to the agent = %v, want the canonical envelope", sealed)
	}

	// The agent's view: the real plaintext password, not the stored ciphertext.
	got, err := agentcreds.Open(sealed, handed.ID.String(), registrationKey)
	if err != nil {
		t.Fatalf("agent could not open the envelope: %v", err)
	}
	if got["username"] != username {
		t.Errorf("username = %v, want %q", got["username"], username)
	}
	if got["password"] != password {
		t.Errorf("password = %v, want the plaintext password", got["password"])
	}
}

// TestIntegration_ResolveJobCredentials_RefusesDeviceWithoutCredentials pins
// the failure mode: a device carrying neither embedded credentials nor a
// credential_id must fail the job at dispatch with a clear reason, rather than
// handing an agent a payload it can only authenticate with as nobody.
func TestIntegration_ResolveJobCredentials_RefusesDeviceWithoutCredentials(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "bare-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(db).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobQueue := NewJobQueueService(db, db, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:   tenant,
		JobType:    models.JobTypeDeviceInterrogation,
		DeviceID:   &dev.ID,
		Parameters: map[string]interface{}{"device_type": "unifi"},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey

	err = svc.resolveJobCredentials(ctx, tenant, job.ToJob())
	if !errors.Is(err, ErrJobHasNoCredentials) {
		t.Fatalf("resolveJobCredentials = %v, want ErrJobHasNoCredentials", err)
	}
}

// TestIntegration_ResolveJobCredentials_DoesNotLeakAcrossTenants pins the
// tenant constraint on this bypass-role read: the device lookup is scoped to
// the job's own tenant, so it cannot hand one tenant's device credentials to
// another tenant's agent.
func TestIntegration_ResolveJobCredentials_DoesNotLeakAcrossTenants(t *testing.T) {
	db := testdb.Connect(t)
	owner := testdb.NewTenant(t, db)
	other := testdb.NewTenant(t, db)
	ctx := context.Background()

	deviceSvc := NewDeviceService(db)
	deviceSvc.encryptionKey = testMasterKey
	hostname := "secret-" + uuid.New().String()[:8] + ".example.test"
	username := "admin"
	password := "not-yours"
	dev, err := deviceSvc.CreateDevice(ctx, owner, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
		Username:   &username,
		Password:   &password,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	job := &models.Job{
		ID:       uuid.New(),
		Type:     string(models.JobTypeDeviceInterrogation),
		DeviceID: &dev.ID,
	}

	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey

	if err := svc.resolveJobCredentials(ctx, other, job); err == nil {
		t.Fatal("resolveJobCredentials across tenants = nil, want an error")
	}
	if len(job.Credentials) != 0 {
		t.Errorf("leaked credentials %v across tenants", job.Credentials)
	}
}

// TestIntegration_ResolveJobCredentials_KeepsExplicitJobCredentials — a job
// created WITH credentials (the handler paths, which call buildJobCredentials)
// must be left alone. The job's own payload is the more specific intent, and
// re-reading the device row would quietly override a credential chosen at
// creation time.
func TestIntegration_ResolveJobCredentials_KeepsExplicitJobCredentials(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	deviceSvc := NewDeviceService(db)
	deviceSvc.encryptionKey = testMasterKey
	hostname := "gw-" + uuid.New().String()[:8] + ".example.test"
	deviceUser := "device-row-user"
	devicePass := "device-row-pass"
	dev, err := deviceSvc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
		Username:   &deviceUser,
		Password:   &devicePass,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	job := &models.Job{
		ID:       uuid.New(),
		Type:     string(models.JobTypeDeviceInterrogation),
		DeviceID: &dev.ID,
		Credentials: map[string]interface{}{
			"username":  "job-payload-user",
			"password":  mustEncrypt(t, testMasterKey, "job-payload-pass"),
			"encrypted": true,
		},
	}

	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey

	if err := svc.resolveJobCredentials(ctx, tenant, job); err != nil {
		t.Fatalf("resolveJobCredentials = %v, want nil", err)
	}
	if got, _ := job.Credentials["username"].(string); got != "job-payload-user" {
		t.Errorf("username = %q, want the job's own %q", got, "job-payload-user")
	}
}
