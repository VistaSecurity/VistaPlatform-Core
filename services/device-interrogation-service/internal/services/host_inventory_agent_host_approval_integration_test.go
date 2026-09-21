package services

// The agent-host approval GATE, against a real Postgres, with the approver
// itself replaced by a recorder. inventory-service's side is pinned in its own
// integration test; what is pinned here is WHEN this service asks — and, as
// much, when it does not:
//
//   - a LOCAL report through the self-report door, on a fresh host: asked
//   - the same report through the REMOTE door (a job result): not asked
//   - the self-report door with a payload whose mode says remote: not asked
//   - a host that is already monitoring: not asked, no call spent
//   - the approver failing: recorded, and the collection still complete
//
// Mutation check: drop the `selfReport` condition in approveAgentHost and the
// remote-door case goes red; drop the mode check and the mismatch case does.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type recordingApprover struct {
	mu     sync.Mutex
	calls  []struct{ tenant, asset, agent uuid.UUID }
	answer bool
	err    error
}

func (r *recordingApprover) ApproveAgentHost(_ context.Context, tenant, asset, agent uuid.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, struct{ tenant, asset, agent uuid.UUID }{tenant, asset, agent})
	if r.err != nil {
		return false, r.err
	}
	return r.answer, nil
}

func (r *recordingApprover) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

type agentHostGateFixture struct {
	ctx      context.Context
	tenant   uuid.UUID
	agent    uuid.UUID
	ingest   *HostInventoryIngest
	approver *recordingApprover
	newJob   func() uuid.UUID
}

func newAgentHostGateFixture(t *testing.T) agentHostGateFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	app.SetMaxOpenConns(1)
	agent := seedHostInventoryAgent(t, owner, tenant)
	approver := &recordingApprover{answer: true}
	ingest := NewHostInventoryIngest(app, owner)
	ingest.SetAgentHostApprover(approver)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	return agentHostGateFixture{
		ctx: ctx, tenant: tenant, agent: agent, ingest: ingest, approver: approver,
		newJob: func() uuid.UUID { return newHostInventoryJob(t, app, owner, tenant, agent) },
	}
}

func TestIntegration_AgentHostApproval_LocalSelfReportAsksForTheHost(t *testing.T) {
	f := newAgentHostGateFixture(t)
	report := hostReport(hostinventory.ModeLocal, f.agent.String(), "SELF-REPORT-HOST", defaultPackages())

	counts, err := f.ingest.MaterialiseSelfReportAndRecord(f.ctx, f.tenant, f.agent, f.newJob(), observationsFor(t, report))
	if err != nil || !counts.FullyMaterialized() {
		t.Fatalf("materialise: %+v %v", counts, err)
	}
	if !counts.AssetCreated {
		t.Fatalf("expected a fresh asset, got %+v", counts)
	}
	if f.approver.count() != 1 {
		t.Fatalf("approver asked %d times, want 1", f.approver.count())
	}
	call := f.approver.calls[0]
	if call.tenant != f.tenant || call.asset.String() != counts.AssetID || call.agent != f.agent {
		t.Fatalf("approver asked for (tenant %s, asset %s, agent %s); run landed on asset %s for agent %s",
			call.tenant, call.asset, call.agent, counts.AssetID, f.agent)
	}
	if !counts.AutoApproved || counts.AutoApprovalError != "" {
		t.Fatalf("counts do not record the approval: %+v", counts)
	}
}

func TestIntegration_AgentHostApproval_RemoteDoorNeverAsks(t *testing.T) {
	f := newAgentHostGateFixture(t)
	// A remote collection: the agent SSH'd into some other machine. Even with
	// the payload claiming local, the door is what decides — and this door is
	// the result processor's.
	report := hostReport(hostinventory.ModeLocal, f.agent.String(), "REMOTE-DOOR-HOST", defaultPackages())

	counts, err := f.ingest.MaterialiseAndRecord(f.ctx, f.tenant, f.agent, f.newJob(), observationsFor(t, report))
	if err != nil || !counts.FullyMaterialized() {
		t.Fatalf("materialise: %+v %v", counts, err)
	}
	if n := f.approver.count(); n != 0 {
		t.Fatalf("remote door asked for approval %d times: an agent's account of ANOTHER machine is not an installed agent", n)
	}
	if counts.AutoApproved {
		t.Fatal("counts claim an approval that was never requested")
	}
}

func TestIntegration_AgentHostApproval_PayloadModeMustAgreeWithTheDoor(t *testing.T) {
	f := newAgentHostGateFixture(t)
	// Self-report door, but the report says remote. The two disagree; the
	// queue keeps it.
	report := hostReport(hostinventory.ModeRemote, f.agent.String(), "MODE-MISMATCH-HOST", defaultPackages())

	counts, err := f.ingest.MaterialiseSelfReportAndRecord(f.ctx, f.tenant, f.agent, f.newJob(), observationsFor(t, report))
	if err != nil || counts.AssetID == "" {
		t.Fatalf("materialise: %+v %v", counts, err)
	}
	if n := f.approver.count(); n != 0 {
		t.Fatalf("approval asked %d times for a payload whose mode is remote", n)
	}
}

func TestIntegration_AgentHostApproval_MonitoringHostCostsNoCall(t *testing.T) {
	f := newAgentHostGateFixture(t)
	report := hostReport(hostinventory.ModeLocal, f.agent.String(), "ALREADY-LIVE-HOST", defaultPackages())
	first, err := f.ingest.MaterialiseSelfReportAndRecord(f.ctx, f.tenant, f.agent, f.newJob(), observationsFor(t, report))
	if err != nil || first.AssetID == "" || f.approver.count() != 1 {
		t.Fatalf("baseline: %+v %v (calls %d)", first, err, f.approver.count())
	}
	// The recorder does not write status; stand in for inventory-service.
	owner := testdb.Connect(t)
	if _, err := owner.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, f.tenant, first.AssetID); err != nil {
		t.Fatal(err)
	}

	report.Collected = report.Collected.Add(time.Hour)
	second, err := f.ingest.MaterialiseSelfReportAndRecord(f.ctx, f.tenant, f.agent, f.newJob(), observationsFor(t, report))
	if err != nil || second.AssetID != first.AssetID {
		t.Fatalf("second run: %+v %v", second, err)
	}
	if n := f.approver.count(); n != 1 {
		t.Fatalf("a monitoring host was asked about again (%d calls): the status read must spare the call", n)
	}
	if second.AutoApproved {
		t.Fatal("second run claims an approval")
	}
}

func TestIntegration_AgentHostApproval_FailureIsRecordedAndTheCollectionStillLands(t *testing.T) {
	f := newAgentHostGateFixture(t)
	f.approver.err = errors.New("inventory-service unreachable")
	report := hostReport(hostinventory.ModeLocal, f.agent.String(), "APPROVAL-FAILS-HOST", defaultPackages())

	counts, err := f.ingest.MaterialiseSelfReportAndRecord(f.ctx, f.tenant, f.agent, f.newJob(), observationsFor(t, report))
	if err != nil {
		t.Fatalf("an approval failure must not fail the collection: %v", err)
	}
	if !counts.FullyMaterialized() {
		t.Fatalf("collection reported incomplete over an approval failure: %+v", counts)
	}
	if counts.AutoApproved || counts.AutoApprovalError == "" {
		t.Fatalf("counts do not carry the failure: %+v", counts)
	}
	if counts.InstallsCreated == 0 {
		t.Fatal("the software inventory did not land")
	}
}
