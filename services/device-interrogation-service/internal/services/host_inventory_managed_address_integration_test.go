package services

// WP7: a host inventory carries every address the platform knows the
// host by, not only the ones its net.interfaces section listed. A report
// without that section — a failed or opted-out step, an older collector —
// still reaches the engine with an address: the address the remote job
// dialled, or the address the local agent reported for itself.
//
// Mutation check: make managedAddress return "" and both tests fail with no
// ip_address identifier on the asset.

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_HostInventory_NoInterfacesStillCarriesTheJobsTargetAddress(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	job, err := NewJobQueueService(appDB, owner, nil).CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:   tenantID,
		JobType:    models.JobTypeHostInventory,
		AgentID:    &agentID,
		Parameters: map[string]interface{}{"mode": "remote", "transport": "ssh", "ip_address": "203.0.113.77"},
	})
	if err != nil {
		t.Fatalf("CreateJob(host_inventory): %v", err)
	}

	rep := hostReport(hostinventory.ModeRemote, "", "HOSTINV-NOIF-1", defaultPackages())
	rep.Interfaces = nil
	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(ctx, tenantID, agentID, job.ID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID == "" {
		t.Fatalf("no asset: %+v", counts)
	}
	if got := identifierValues(t, owner, tenantID, counts.AssetID, "ip_address"); len(got) != 1 || got[0] != "203.0.113.77" {
		t.Errorf("ip_address identifiers = %v, want the job's target 203.0.113.77 — a report with no interfaces section must still carry an address", got)
	}
}

func TestIntegration_HostInventory_NoInterfacesStillCarriesTheAgentsOwnAddress(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	if _, err := owner.Exec(`UPDATE device_agents SET ip_address = '198.51.100.88' WHERE tenant_id = $1 AND id = $2`, tenantID, agentID); err != nil {
		t.Fatalf("set the agent's address: %v", err)
	}

	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "HOSTINV-NOIF-2", defaultPackages())
	rep.Interfaces = nil
	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(ctx, tenantID, agentID,
		newHostInventoryJob(t, appDB, owner, tenantID, agentID), observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID == "" {
		t.Fatalf("no asset: %+v", counts)
	}
	if got := identifierValues(t, owner, tenantID, counts.AssetID, "ip_address"); len(got) != 1 || got[0] != "198.51.100.88" {
		t.Errorf("ip_address identifiers = %v, want the agent's own address 198.51.100.88", got)
	}
}
