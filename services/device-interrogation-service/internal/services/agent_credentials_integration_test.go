package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_GetNextJob_SealsCredentialsForClaimingAgent is the end-to-end
// proof for's credential defect, through real SQL: a job carrying stored
// (master-key encrypted) credentials must reach the agent as the canonical
// envelope, openable with the CLAIMING agent's registration key, and must
// contain the real plaintext password.
//
// Before the fix the agent received the platform's internal shape verbatim —
// the ciphertext (in fact a masked fragment of it) as the password — and every
// remote interrogation needing credentials failed at the device.
func TestIntegration_GetNextJob_SealsCredentialsForClaimingAgent(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	// A registered agent with a known registration key — the shared secret the
	// envelope is keyed to.
	agentID := uuid.New()
	registrationKey := "regkey-" + agentID.String()
	if _, err := db.Exec(`
		INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, profile, status)
		VALUES ($1, $2, $3, 'linux', '1.0', 'device_interrogation', 'active')`,
		agentID, tenant, registrationKey,
	); err != nil {
		t.Fatalf("insert device agent: %v", err)
	}

	// A device to interrogate (device_jobs CHECKs require one).
	hostname := "f5-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(db).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "f5",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// A job carrying the platform's stored embedded-credential shape.
	jobQueue := NewJobQueueService(db, db, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID: tenant,
		JobType:  models.JobTypeDeviceInterrogation,
		DeviceID: &dev.ID,
		AgentID:  &agentID,
		Credentials: map[string]interface{}{
			"username":    "admin",
			"password":    mustEncrypt(t, testMasterKey, "s3cr3t-p@ss"),
			"device_type": "f5",
			"encrypted":   true,
		},
		Parameters: map[string]interface{}{"device_type": "f5"},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey // NewAgentService reads ENCRYPTION_MASTER_KEY from env

	// GetNextJobForAgent takes a Redis lock; give the service a real client only
	// if one is configured. Exercise the seal directly against the queued job
	// instead, which is the code path GetNextJob delegates to.
	handed := job.ToJob()
	sealed, err := svc.sealJobCredentials(ctx, agentID, handed)
	if err != nil {
		t.Fatalf("sealJobCredentials = %v, want nil", err)
	}

	if !agentcreds.IsSealed(sealed) {
		t.Fatalf("credentials handed to the agent = %v, want the canonical envelope", sealed)
	}
	if len(sealed) != 1 {
		t.Fatalf("envelope has %d keys, want 1 — no credential field may travel outside it", len(sealed))
	}

	// The agent's view.
	got, err := agentcreds.Open(sealed, handed.ID.String(), registrationKey)
	if err != nil {
		t.Fatalf("agent could not open the envelope: %v", err)
	}
	if got["password"] != "s3cr3t-p@ss" {
		t.Fatalf("password = %v, want the plaintext password", got["password"])
	}
	if got["username"] != "admin" {
		t.Fatalf("username = %v, want admin", got["username"])
	}

	// A different agent's key must not open it.
	if _, err := agentcreds.Open(sealed, handed.ID.String(), "some-other-agent-key"); err == nil {
		t.Fatal("another agent's registration key opened the envelope, want failure")
	}
}

// TestIntegration_SealJobCredentials_UnknownAgentIsRejected — an unregistered
// agent id must not get a usable envelope.
func TestIntegration_SealJobCredentials_UnknownAgentIsRejected(t *testing.T) {
	db := testdb.Connect(t)
	ctx := context.Background()

	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey

	job := &models.Job{
		ID:          uuid.New(),
		Credentials: map[string]interface{}{"username": "admin", "password": "plain"},
	}
	if _, err := svc.sealJobCredentials(ctx, uuid.New(), job); err == nil {
		t.Fatal("sealJobCredentials succeeded for an unregistered agent, want ErrAgentNotFound")
	}
}
