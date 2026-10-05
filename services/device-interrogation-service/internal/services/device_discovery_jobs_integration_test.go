package services

// Agent-routed Add device ( slice B) against a real database and Redis:
// the real enqueue, the real claim SQL, the real hand-off sealing and the real
// SubmitJobResult. Only the device write at the end is a stub — it posts a
// sighting to inventory-service, which is not part of this claim path and is
// covered for Add device by device_add_enforce_integration_test.go.
//
// Skips unless TEST_DATABASE_URL is set and Redis is reachable
// (make test-integration-db).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

var discoveryCaps = map[string]bool{di.CapabilityDeviceDiscovery: true}

func TestIntegration_DeviceDiscovery_ClaimedOnlyByTheNamedCapableAgent(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	rdb := connectJobClaimRedis(t)
	ctx := context.Background()
	t.Setenv("ENCRYPTION_MASTER_KEY", discoveryTestMasterKey)

	tenant := testdb.NewTenant(t, owner)
	agentA := insertDeviceAgent(t, owner, tenant)
	agentB := insertDeviceAgent(t, owner, tenant)
	jobs := NewDeviceDiscoveryJobs(app, owner, rdb, discoveryTestMasterKey)
	svc := NewAgentService(app, owner, rdb)
	creator := &stubDiscoveryCreator{deviceID: uuid.New()}
	svc.discoveryCreator = creator
	t.Cleanup(func() { _ = rdb.Del(ctx, agentCapabilityKey(agentA), agentCapabilityKey(agentB)).Err() })

	req := EnqueueDeviceDiscoveryRequest{TenantID: tenant, AgentID: agentA, DeviceType: "fortinet",
		ManagementURL: "https://192.0.2.10", Username: "readonly", Password: "device-password-123", TLSInsecureSkipVerify: true}

	// Before the agent has declared it can discover, nothing is queued.
	var reqErr *DeviceDiscoveryRequestError
	if _, err := jobs.Enqueue(ctx, req); !errors.As(err, &reqErr) || reqErr.Code != CodeAgentUnavailable {
		t.Fatalf("enqueue before the capability was declared = %v, want %s", err, CodeAgentUnavailable)
	}
	// An agent of another tenant is not this tenant's to name.
	otherTenant := testdb.NewTenant(t, owner)
	foreign := insertDeviceAgent(t, owner, otherTenant)
	if _, err := jobs.Enqueue(ctx, EnqueueDeviceDiscoveryRequest{TenantID: tenant, AgentID: foreign, DeviceType: "fortinet",
		ManagementURL: "https://192.0.2.10", Username: "u", Password: "p"}); !errors.As(err, &reqErr) || reqErr.Code != CodeAgentNotFound {
		t.Fatalf("enqueue on another tenant's agent = %v, want %s", err, CodeAgentNotFound)
	}

	// A poll that declares the capability is remembered.
	if j, err := svc.GetNextJobWithCapabilities(ctx, agentA, discoveryCaps); err != nil || j != nil {
		t.Fatalf("empty poll = (%v, %v)", j, err)
	}
	queued, err := jobs.Enqueue(ctx, req)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if queued.Status != DiscoveryQueued {
		t.Fatalf("queued status = %s", queued.Status)
	}

	// The in-cluster worker's own claim predicate does not match the row.
	var platformCandidates int
	if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM device_jobs WHERE id=$1 AND `+platformClaimPredicate, queued.ID).Scan(&platformCandidates); err != nil {
		t.Fatal(err)
	}
	if platformCandidates != 0 {
		t.Fatal("the platform worker's claim predicate matches a device_discovery job")
	}

	// The same agent, polling as an OLD build (no capability), is not offered it.
	if j, err := svc.GetNextJob(ctx, agentA); err != nil || j != nil {
		t.Fatalf("old-agent poll = (%+v, %v), want nothing", j, err)
	}
	// Another capable agent of the same tenant is not offered it either.
	if j, err := svc.GetNextJobWithCapabilities(ctx, agentB, discoveryCaps); err != nil || j != nil {
		t.Fatalf("other agent's poll = (%+v, %v), want nothing", j, err)
	}
	// The named agent, declaring the capability, claims it — with the
	// credentials sealed for it alone.
	claimed, err := svc.GetNextJobWithCapabilities(ctx, agentA, discoveryCaps)
	if err != nil || claimed == nil || claimed.ID != queued.ID {
		t.Fatalf("named agent's poll = (%+v, %v), want job %s", claimed, err, queued.ID)
	}
	if claimed.Type != di.JobTypeDeviceDiscovery || claimed.Parameters["management_url"] != "https://192.0.2.10" {
		t.Fatalf("claimed job = %+v", claimed)
	}
	if !agentcreds.IsSealed(claimed.Credentials) {
		t.Fatalf("credentials left the platform unsealed: %v", claimed.Credentials)
	}
	if blob, _ := json.Marshal(claimed); strings.Contains(string(blob), "device-password-123") {
		t.Fatal("the job payload carries the plaintext password")
	}
	// And nobody claims it twice.
	for _, a := range []uuid.UUID{agentA, agentB} {
		if j, err := svc.GetNextJobWithCapabilities(ctx, a, discoveryCaps); err != nil || j != nil {
			t.Fatalf("second claim by %s = (%+v, %v)", a, j, err)
		}
	}
	list, err := jobs.List(ctx, tenant)
	if err != nil || len(list) != 1 || list[0].Status != DiscoveryRunning {
		t.Fatalf("list while running = (%+v, %v)", list, err)
	}

	// Only the claiming agent can file the result.
	if err := svc.SubmitJobResult(ctx, agentB, &models.JobResult{JobID: queued.ID, Success: true}); !errors.Is(err, ErrJobTenantMismatch) {
		t.Fatalf("other agent's submit = %v", err)
	}
	if err := svc.SubmitJobResult(ctx, agentA, &models.JobResult{JobID: queued.ID, Success: true,
		Identification: &di.IdentificationReport{Vendor: "Fortinet", Model: "FortiGate 60F", SerialNumber: "FGT60F0000000001"},
		Metadata:       map[string]interface{}{"psksecret": "branch-tunnel-psk"},
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if creator.calls != 1 || creator.created.Password == nil || *creator.created.Password != "device-password-123" {
		t.Fatalf("device not created from the queued credentials: calls=%d", creator.calls)
	}
	var credsAfter, resultsAfter string
	if err := owner.QueryRowContext(ctx, `SELECT credentials::text, results::text FROM device_jobs WHERE id=$1`, queued.ID).Scan(&credsAfter, &resultsAfter); err != nil {
		t.Fatal(err)
	}
	if credsAfter != "{}" {
		t.Errorf("a completed discovery kept its credentials: %s", credsAfter)
	}
	for _, leak := range []string{"device-password-123", "enc:v1", "branch-tunnel-psk", "password"} {
		if strings.Contains(resultsAfter, leak) {
			t.Errorf("stored results carry %q: %s", leak, resultsAfter)
		}
	}
	list, _ = jobs.List(ctx, tenant)
	if len(list) != 1 || list[0].Status != DiscoverySucceeded || list[0].AssetID == nil || *list[0].AssetID != creator.deviceID {
		t.Fatalf("list after success = %+v", list)
	}
}

func TestIntegration_DeviceDiscovery_FailureRetryDismissAndUnclaimed(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	rdb := connectJobClaimRedis(t)
	ctx := context.Background()
	t.Setenv("ENCRYPTION_MASTER_KEY", discoveryTestMasterKey)

	tenant := testdb.NewTenant(t, owner)
	agent := insertDeviceAgent(t, owner, tenant)
	jobs := NewDeviceDiscoveryJobs(app, owner, rdb, discoveryTestMasterKey)
	svc := NewAgentService(app, owner, rdb)
	svc.discoveryCreator = &stubDiscoveryCreator{deviceID: uuid.New()}
	t.Cleanup(func() { _ = rdb.Del(ctx, agentCapabilityKey(agent)).Err() })
	if _, err := svc.GetNextJobWithCapabilities(ctx, agent, discoveryCaps); err != nil {
		t.Fatal(err)
	}

	queued, err := jobs.Enqueue(ctx, EnqueueDeviceDiscoveryRequest{TenantID: tenant, AgentID: agent, DeviceType: "f5",
		ManagementURL: "https://192.0.2.20", Username: "admin", Password: "pw-for-retry"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetNextJobWithCapabilities(ctx, agent, discoveryCaps); err != nil {
		t.Fatal(err)
	}
	if err := svc.SubmitJobResult(ctx, agent, &models.JobResult{JobID: queued.ID, FailureCode: "connection_failed",
		Error: "dial tcp 192.0.2.20:443: the device printed hunter2"}); err != nil {
		t.Fatal(err)
	}
	got, err := jobs.Get(ctx, tenant, queued.ID)
	if err != nil || got.Status != DiscoveryFailed || got.ErrorCode == nil || *got.ErrorCode != "connection_failed" {
		t.Fatalf("after failure = (%+v, %v)", got, err)
	}
	if strings.Contains(*got.Message, "hunter2") || !strings.Contains(*got.Message, "agent") {
		t.Fatalf("failure message = %q", *got.Message)
	}

	// Retry re-queues it on the same agent with the same credentials.
	retried, err := jobs.Retry(ctx, tenant, queued.ID)
	if err != nil || retried.Status != DiscoveryQueued {
		t.Fatalf("retry = (%+v, %v)", retried, err)
	}
	if _, err := jobs.Retry(ctx, tenant, queued.ID); !errors.Is(err, ErrDeviceDiscoveryNotRetryable) {
		t.Fatalf("retrying a queued discovery = %v", err)
	}
	again, err := svc.GetNextJobWithCapabilities(ctx, agent, discoveryCaps)
	if err != nil || again == nil || again.ID != queued.ID || !agentcreds.IsSealed(again.Credentials) {
		t.Fatalf("re-claim after retry = (%+v, %v)", again, err)
	}

	// Dismiss drops it and its credentials; the agent's late result is refused.
	if err := jobs.Dismiss(ctx, tenant, queued.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.SubmitJobResult(ctx, agent, &models.JobResult{JobID: queued.ID, Success: true,
		Identification: &di.IdentificationReport{Model: "BIG-IP"}}); !errors.Is(err, ErrJobTenantMismatch) {
		t.Fatalf("result for a dismissed discovery = %v", err)
	}
	var creds string
	if err := owner.QueryRowContext(ctx, `SELECT credentials::text FROM device_jobs WHERE id=$1`, queued.ID).Scan(&creds); err != nil || creds != "{}" {
		t.Fatalf("dismissed discovery kept credentials: %q (%v)", creds, err)
	}
	if list, _ := jobs.List(ctx, tenant); len(list) != 0 {
		t.Fatalf("dismissed discovery still listed: %+v", list)
	}

	// One no agent ever claimed reads "not picked up", not as a device failure.
	unclaimed, err := jobs.Enqueue(ctx, EnqueueDeviceDiscoveryRequest{TenantID: tenant, AgentID: agent, DeviceType: "fortinet",
		ManagementURL: "https://192.0.2.21", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE device_jobs SET expires_at=now()-interval '1 minute' WHERE id=$1`, unclaimed.ID); err != nil {
		t.Fatal(err)
	}
	if j, err := svc.GetNextJobWithCapabilities(ctx, agent, discoveryCaps); err != nil || j != nil {
		t.Fatalf("an expired discovery was claimed: (%+v, %v)", j, err)
	}
	got, err = jobs.Get(ctx, tenant, unclaimed.ID)
	if err != nil || got.Status != DiscoveryNotPickedUp {
		t.Fatalf("expired discovery = (%+v, %v)", got, err)
	}
	if _, err := jobs.Retry(ctx, tenant, unclaimed.ID); err != nil {
		t.Fatalf("retrying an unclaimed discovery: %v", err)
	}

	// Another tenant cannot see, retry or dismiss it.
	other := testdb.NewTenant(t, owner)
	if _, err := jobs.Get(ctx, other, unclaimed.ID); !errors.Is(err, ErrDeviceDiscoveryNotFound) {
		t.Fatalf("cross-tenant get = %v", err)
	}
	if err := jobs.Dismiss(ctx, other, unclaimed.ID); !errors.Is(err, ErrDeviceDiscoveryNotFound) {
		t.Fatalf("cross-tenant dismiss = %v", err)
	}
}

// valid_job_assignment is what makes the executor rule structural: there is
// no unassigned device_discovery row for the platform worker and the agents
// to race over.
func TestIntegration_DeviceDiscovery_CheckRefusesAnUnassignedJob(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	agent := insertDeviceAgent(t, db, tenant)
	insert := func(agentID *uuid.UUID) error {
		_, err := db.Exec(`INSERT INTO device_jobs (tenant_id, job_type, agent_id, status, expires_at)
			VALUES ($1, 'device_discovery', $2, 'pending', $3)`, tenant, agentID, time.Now().Add(time.Hour))
		return err
	}
	if err := insert(nil); err == nil || !strings.Contains(err.Error(), "valid_job_assignment") {
		t.Fatalf("unassigned device_discovery insert = %v, want the CHECK to refuse it", err)
	}
	if err := insert(&agent); err != nil {
		t.Fatalf("agent-assigned device_discovery insert: %v", err)
	}
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM device_jobs WHERE tenant_id=$1 AND job_type='device_discovery'`, tenant).Scan(&n)
	if n != 1 {
		t.Fatalf("rows = %d", n)
	}
}
