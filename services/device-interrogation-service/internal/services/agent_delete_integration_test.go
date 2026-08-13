package services

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Delete-path proofs for, through real SQL.
//
// These run on ConnectAsAppRole (the non-owner crypto_app role), NOT the owner
// connection. device_agents, device_jobs and agent_certificates are all RLS
// tables; an owner connection bypasses RLS, so an owner-connection test would
// pass against a DeleteAgent that RLS silently blocks in production — the exact
// class of bug the plain-pool sweep found. Running as the app role means the
// statements here are subject to the same policies the deployed service is.

// newRLSAgentService wires the service the way production does: the tenant-scoped
// handle is the non-owner app role (so RLS applies to ListAgents/DeleteAgent),
// while the bypass handle is the owner connection — the faithful stand-in for the
// BYPASSRLS crypto_bypass role the agent-outbound paths use, where the tenant is
// the OUTPUT of an agent-id lookup and so cannot be set before the query.
//
// Passing the app role as BOTH would not be a stricter test, it would be a wrong
// one: the outbound lookups would find nothing for want of app.tenant_id and
// every assertion about them would pass vacuously.
func newRLSAgentService(app, owner *sql.DB) *AgentService {
	return NewAgentService(app, owner, nil)
}

// seedDevice inserts a minimal device so a job can name a target. The devices
// table's device_identifier CHECK requires one of hostname / ip_address /
// management_url, hence the RFC 5737 documentation address.
func seedDevice(t *testing.T, owner *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO devices (id, tenant_id, device_type, ip_address)
		VALUES ($1, $2, 'unifi', '192.0.2.10')`, id, tenant); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

// enrollAgent inserts a device agent directly, the way the bootstrap path does,
// and returns its id. Insert runs on the owner connection: enrollment in
// production is a bypass-role write (the tenant is the OUTPUT of the
// registration-key lookup), so this is the faithful setup, not a shortcut.
func enrollAgent(t *testing.T, owner *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := owner.Exec(`
		INSERT INTO device_agents (id, tenant_id, registration_key, name, description,
		                           platform, profile, version, status)
		VALUES ($1, $2, $3, 'deviceagent-test', 'a test agent', 'windows', 'device_interrogation', '0.5.6', 'active')`,
		id, tenant, "regkey-"+uuid.New().String())
	if err != nil {
		t.Fatalf("enroll agent: %v", err)
	}
	return id
}

// TestIntegration_DeleteAgent_SoftDeletesAndSettlesJobs is the whole contract in
// one pass: the agent disappears from the roster, its queued work is released
// rather than stranded, its running work is failed rather than left hanging, and
// its certificate is revoked.
func TestIntegration_DeleteAgent_SoftDeletesAndSettlesJobs(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := context.Background()

	agentID := enrollAgent(t, owner, tenant)

	// Three jobs pinned to this agent, covering all three fates:
	//   pendingJob    — queued and names a device → released to the pool
	//   orphanJob     — queued and names NO device → cannot be released
	//                   (valid_job_assignment forbids it, and nothing could
	//                   resolve its target), so it must be failed
	//   runningJob    — already in flight → failed, never re-queued
	deviceID := seedDevice(t, owner, tenant)
	pendingJob, orphanJob, runningJob := uuid.New(), uuid.New(), uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, device_id, status)
		VALUES ($1, $2, 'device_interrogation', $3, $4, 'pending')`,
		pendingJob, tenant, agentID, deviceID); err != nil {
		t.Fatalf("seed pending job: %v", err)
	}
	for id, status := range map[uuid.UUID]string{orphanJob: "pending", runningJob: "in_progress"} {
		if _, err := owner.Exec(`
			INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, status)
			VALUES ($1, $2, 'device_interrogation', $3, $4)`,
			id, tenant, agentID, status); err != nil {
			t.Fatalf("seed %s job: %v", status, err)
		}
	}

	if _, err := owner.Exec(`
		INSERT INTO agent_certificates (agent_id, tenant_id, certificate_pem, serial_number, expires_at)
		VALUES ($1, $2, 'test-pem', '1234', NOW() + interval '90 days')`,
		agentID, tenant); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	svc := newRLSAgentService(app, owner)
	if err := svc.DeleteAgent(ctx, tenant, agentID); err != nil {
		t.Fatalf("DeleteAgent = %v, want nil", err)
	}

	// 1. Gone from the roster the UI reads.
	agents, err := svc.ListAgents(ctx, tenant)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	for _, a := range agents {
		if a.ID == agentID {
			t.Errorf("deleted agent %s is still listed", agentID)
		}
	}

	// 2. Pending job released to the pool, so the in-cluster worker or another
	//    agent can still run it. This is the one that silently stranded before:
	//    device_jobs' ON DELETE SET NULL never fires for a soft delete.
	var releasedAgent sql.NullString
	var releasedStatus string
	if err := owner.QueryRow(`SELECT agent_id, status FROM device_jobs WHERE id = $1`, pendingJob).
		Scan(&releasedAgent, &releasedStatus); err != nil {
		t.Fatalf("read pending job: %v", err)
	}
	if releasedAgent.Valid {
		t.Errorf("pending job still pinned to agent %q, want unassigned", releasedAgent.String)
	}
	if releasedStatus != "pending" {
		t.Errorf("pending job status = %q, want it left pending for re-dispatch", releasedStatus)
	}

	// 3. In-progress job failed with a reason naming the cause — it is NOT
	//    re-queued, because the work may already have run against a live device.
	assertFailedWith(t, owner, runningJob, agentDeletedJobError)

	// 4. The queued job that names no device could not be released (the
	//    valid_job_assignment CHECK forbids an unassigned device_interrogation
	//    job without a device_id, and nothing could resolve its target anyway),
	//    so it is failed — with its own message, not the in-flight one.
	assertFailedWith(t, owner, orphanJob, agentDeletedUnrunnableJobError)

	// 5. Certificate revoked, so the identity is not merely unlisted.
	var revoked sql.NullTime
	var reason sql.NullString
	if err := owner.QueryRow(`SELECT revoked_at, revocation_reason FROM agent_certificates WHERE agent_id = $1`, agentID).
		Scan(&revoked, &reason); err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	if !revoked.Valid {
		t.Error("certificate was not revoked")
	}
	if reason.String != "agent_deleted" {
		t.Errorf("revocation_reason = %q, want agent_deleted", reason.String)
	}
}

// TestIntegration_DeleteAgent_RefusesCrossTenant is the isolation proof: tenant B
// cannot delete tenant A's agent, and gets the same ErrAgentNotFound a bogus id
// would produce — so the API cannot be used to probe which agent ids exist.
func TestIntegration_DeleteAgent_RefusesCrossTenant(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)
	ctx := context.Background()

	agentID := enrollAgent(t, owner, tenantA)
	svc := newRLSAgentService(app, owner)

	if err := svc.DeleteAgent(ctx, tenantB, agentID); !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("cross-tenant DeleteAgent = %v, want ErrAgentNotFound", err)
	}

	// The agent must be untouched — not merely un-listed for B.
	var deletedAt sql.NullTime
	if err := owner.QueryRow(`SELECT deleted_at FROM device_agents WHERE id = $1`, agentID).Scan(&deletedAt); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if deletedAt.Valid {
		t.Error("tenant B's delete soft-deleted tenant A's agent")
	}

	// And A can still delete its own — proving the refusal above was tenant
	// scoping, not a blanket failure. Without this the test would still pass if
	// DeleteAgent were broken for everyone.
	if err := svc.DeleteAgent(ctx, tenantA, agentID); err != nil {
		t.Fatalf("owning tenant DeleteAgent = %v, want nil", err)
	}
}

// TestIntegration_DeleteAgent_UnknownAndRepeated pins that delete is idempotent
// in the safe direction: a second delete reports not-found rather than silently
// re-revoking and re-failing jobs.
func TestIntegration_DeleteAgent_UnknownAndRepeated(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := context.Background()

	svc := newRLSAgentService(app, owner)

	if err := svc.DeleteAgent(ctx, tenant, uuid.New()); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("DeleteAgent(unknown id) = %v, want ErrAgentNotFound", err)
	}

	agentID := enrollAgent(t, owner, tenant)
	if err := svc.DeleteAgent(ctx, tenant, agentID); err != nil {
		t.Fatalf("first DeleteAgent = %v, want nil", err)
	}
	if err := svc.DeleteAgent(ctx, tenant, agentID); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("second DeleteAgent = %v, want ErrAgentNotFound", err)
	}
}

// TestIntegration_DeletedAgentGetsNoWork is the fail-closed proof for the case
// the UI warns about: the binary keeps running on the operator's host and keeps
// polling with a certificate that is still on disk.
//
// The guard predates this feature — every agent-outbound path resolves the agent
// with `deleted_at IS NULL` — but nothing pinned it, so a later "simplification"
// of one of those queries could have opened it silently. Deleting an agent is
// only a safe operator action while this holds.
func TestIntegration_DeletedAgentGetsNoWork(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := context.Background()

	agentID := enrollAgent(t, owner, tenant)
	svc := newRLSAgentService(app, owner)

	// Before deletion the agent resolves — otherwise "no work after delete"
	// would be indistinguishable from a setup that never worked.
	if _, err := svc.jobQueue.resolveAgentTenant(ctx, agentID); err != nil {
		t.Fatalf("resolveAgentTenant before delete = %v, want nil", err)
	}

	if err := svc.DeleteAgent(ctx, tenant, agentID); err != nil {
		t.Fatalf("DeleteAgent: %v", err)
	}

	if _, err := svc.jobQueue.resolveAgentTenant(ctx, agentID); !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("resolveAgentTenant after delete = %v, want ErrAgentNotFound", err)
	}

	// Credential sealing must refuse too — a deleted agent must never be handed
	// decryptable job credentials.
	_, err := svc.sealJobCredentials(ctx, agentID, &models.Job{
		ID:          uuid.New(),
		Credentials: map[string]interface{}{"username": "svc"},
	})
	if !errors.Is(err, ErrAgentNotFound) {
		t.Errorf("sealJobCredentials after delete = %v, want ErrAgentNotFound", err)
	}
}

// TestIntegration_ListAgents_ReturnsAgentShapedDetail proves the fields the new
// Discovery agents table renders actually arrive — description, the multi-homed
// address inventory, and the job summary. Every one of these existed in the
// database and was dropped on the floor by the old SELECT, which is why an agent
// row rendered mostly blank.
func TestIntegration_ListAgents_ReturnsAgentShapedDetail(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := context.Background()

	agentID := enrollAgent(t, owner, tenant)

	// Two addresses on one host, the way a multi-homed agent reports.
	// RFC 5737 documentation addresses.
	for _, a := range []struct {
		iface     string
		addr      string
		isPrimary bool
	}{
		{"Ethernet", "192.0.2.173", true},
		{"Ethernet 2", "198.51.100.20", false},
	} {
		if _, err := owner.Exec(`
			INSERT INTO agent_addresses (device_agent_id, interface_name, address, prefix_length, is_primary)
			VALUES ($1, $2, $3::inet, 24, $4)`,
			agentID, a.iface, a.addr, a.isPrimary); err != nil {
			t.Fatalf("seed address %s: %v", a.addr, err)
		}
	}

	for i := 0; i < 3; i++ {
		if _, err := owner.Exec(`
			INSERT INTO device_jobs (tenant_id, job_type, agent_id, status, completed_at)
			VALUES ($1, 'device_interrogation', $2, 'completed', NOW())`,
			tenant, agentID); err != nil {
			t.Fatalf("seed job %d: %v", i, err)
		}
	}

	agents, err := newRLSAgentService(app, owner).ListAgents(ctx, tenant)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}

	var got *models.Agent
	for _, a := range agents {
		if a.ID == agentID {
			got = a
		}
	}
	if got == nil {
		t.Fatalf("agent %s not returned by ListAgents", agentID)
	}

	if got.Description == nil || *got.Description != "a test agent" {
		t.Errorf("Description = %v, want %q", got.Description, "a test agent")
	}
	if len(got.Addresses) != 2 {
		t.Fatalf("len(Addresses) = %d, want 2", len(got.Addresses))
	}
	// Primary first, and rendered bare — host(), not ::text, which would append
	// "/24" and never match a bare-IP comparison downstream.
	if !got.Addresses[0].IsPrimary || got.Addresses[0].Address != "192.0.2.173" {
		t.Errorf("Addresses[0] = %+v, want the bare primary 192.0.2.173", got.Addresses[0])
	}
	if got.Addresses[0].PrefixLength == nil || *got.Addresses[0].PrefixLength != 24 {
		t.Errorf("Addresses[0].PrefixLength = %v, want 24", got.Addresses[0].PrefixLength)
	}
	if got.JobCount != 3 {
		t.Errorf("JobCount = %d, want 3", got.JobCount)
	}
	if got.LastJobAt == nil {
		t.Error("LastJobAt = nil, want the most recent job's timestamp")
	}
}

// TestIntegration_ListAgents_NeverRunAgentIsDistinguishable pins the empty case
// the Jobs column depends on: an enrolled-but-unused agent must report zero and
// nil, not a zero-value timestamp that renders as a bogus date.
func TestIntegration_ListAgents_NeverRunAgentIsDistinguishable(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	agentID := enrollAgent(t, owner, tenant)

	agents, err := newRLSAgentService(app, owner).ListAgents(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	for _, a := range agents {
		if a.ID != agentID {
			continue
		}
		if a.JobCount != 0 {
			t.Errorf("JobCount = %d, want 0", a.JobCount)
		}
		if a.LastJobAt != nil {
			t.Errorf("LastJobAt = %v, want nil", a.LastJobAt)
		}
		// Non-nil empty, so the UI can iterate without a null check.
		if a.Addresses == nil {
			t.Error("Addresses = nil, want an empty slice")
		}
		return
	}
	t.Fatalf("agent %s not returned by ListAgents", agentID)
}

// assertFailedWith checks a job ended up failed with exactly the given reason.
func assertFailedWith(t *testing.T, owner *sql.DB, jobID uuid.UUID, wantErr string) {
	t.Helper()
	var status string
	var msg sql.NullString
	if err := owner.QueryRow(`SELECT status, error_message FROM device_jobs WHERE id = $1`, jobID).
		Scan(&status, &msg); err != nil {
		t.Fatalf("read job %s: %v", jobID, err)
	}
	if status != "failed" {
		t.Errorf("job %s status = %q, want failed", jobID, status)
	}
	if msg.String != wantErr {
		t.Errorf("job %s error_message = %q, want %q", jobID, msg.String, wantErr)
	}
}
