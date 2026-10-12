package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/agentsecret"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// An agent that holds a secret (version >= 1) must be sealed under that secret.
// If the stored form cannot be unwrapped the job FAILS; it must not quietly fall
// back to the registration key, which the agent no longer keeps — that would hand
// over an envelope nobody can open and report success.
func TestIntegration_SealJobCredentials_UnusableAgentSecretFailsLoudly(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	agentID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, profile, status, agent_secret_enc, agent_secret_version)
		VALUES ($1, $2, $3, 'linux', '1.0', 'device_interrogation', 'active', 'not-a-wrapped-secret', 1)`,
		agentID, tenant, "regkey-"+agentID.String()); err != nil {
		t.Fatal(err)
	}
	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey

	job := &models.Job{ID: uuid.New(), Credentials: map[string]interface{}{"username": "admin", "password": "plain"}}
	if sealed, err := svc.sealJobCredentials(ctx, agentID, job); err == nil {
		t.Fatalf("sealed %v under a fallback key; want an error for an unusable agent secret", sealed)
	}
}

// The agent's secret, not its registration key, roots the envelope once issued —
// at the service layer, against real SQL.
func TestIntegration_SealJobCredentials_UsesTheAgentSecretWhenIssued(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	cipher, err := credentials.NewCipher("test", testMasterKey, credentials.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	secret, wrapped, err := agentsecret.Issue(cipher)
	if err != nil {
		t.Fatal(err)
	}
	agentID := uuid.New()
	regKey := "regkey-" + agentID.String()
	if _, err := db.Exec(`
		INSERT INTO device_agents (id, tenant_id, registration_key, platform, version, profile, status, agent_secret_enc, agent_secret_version)
		VALUES ($1, $2, $3, 'linux', '1.0', 'device_interrogation', 'active', $4, 3)`,
		agentID, tenant, regKey, wrapped); err != nil {
		t.Fatal(err)
	}
	svc := NewAgentService(db, db, nil)
	svc.encryptionKey = testMasterKey
	job := &models.Job{ID: uuid.New(), Credentials: map[string]interface{}{"username": "admin", "password": "plain"}}
	sealed, err := svc.sealJobCredentials(ctx, agentID, job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentcreds.Open(sealed, job.ID.String(), secret); err != nil {
		t.Fatalf("the agent secret does not open the envelope: %v", err)
	}
	if _, err := agentcreds.Open(sealed, job.ID.String(), regKey); err == nil {
		t.Fatal("the registration key opened an envelope sealed under the agent secret")
	}
}
