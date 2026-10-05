package services

// through the real host-inventory intake: a two-homed host whose agent
// reports one interface static and the other DHCP. Skips without
// TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_HostInventory_EachAddressCarriesItsOwnScopeAndAssignment:
//
//	interface  address          segment          agent says   identifier
//	eno1       198.51.100.20    LAN (DHCP flag)  static       ip_address|…|LAN   static
//	wlan0      192.0.2.44       Guest (DHCP)     dhcp         ip_address|…|Guest dynamic
//	veth9a1b   10.244.1.3       —                —            none (virtual)
//
// Each address is scoped by ITS OWN segment, not by the primary's.
//
// Mutation checks: scope every address by the primary (`scope` instead of
// the per-address scoping, now Intake's) → wlan0's row carries the LAN segment and
// this fails; drop `Assignment: ha.assignment` → both rows lose their
// assignment and this fails.
func TestIntegration_HostInventory_EachAddressCarriesItsOwnScopeAndAssignment(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()
	lan, guest := uuid.New(), uuid.New()
	for _, seg := range []struct {
		id         uuid.UUID
		name, cidr string
	}{{lan, "LAN", "198.51.100.0/24"}, {guest, "Guest", "192.0.2.0/24"}} {
		if _, err := owner.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active,metadata)
		  VALUES($1,$2,$3,'cidr',$4,'production',true,'{"dynamic":true,"dynamic_source":"measured"}'::jsonb)`,
			seg.id, tenantID, seg.name, seg.cidr); err != nil {
			t.Fatal(err)
		}
	}

	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)
	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "CZ2X5Y9", defaultPackages())
	rep.Interfaces[0].StaticAddresses = []string{"198.51.100.20/24"}
	rep.Interfaces[2].DynamicAddresses = []string{"192.0.2.44/24"}

	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID == "" {
		t.Fatalf("no asset: %+v", counts)
	}

	rows, err := owner.Query(`SELECT value, coalesce(scope,''), coalesce(address_assignment,'') FROM asset_identifiers
	   WHERE tenant_id=$1 AND asset_id=$2 AND kind='ip_address' ORDER BY value`, tenantID, counts.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string][2]string{}
	for rows.Next() {
		var v, scope, a string
		if err := rows.Scan(&v, &scope, &a); err != nil {
			t.Fatal(err)
		}
		got[v] = [2]string{scope, a}
	}
	want := map[string][2]string{
		"198.51.100.20": {lan.String(), "static"},
		"192.0.2.44":    {guest.String(), "dynamic"},
	}
	if len(got) != len(want) {
		t.Fatalf("ip_address identifiers = %v, want exactly %v (the virtual interface's address is not identity)", got, want)
	}
	for v, w := range want {
		if got[v] != w {
			t.Errorf("%s = scope %q assignment %q, want scope %q assignment %q", v, got[v][0], got[v][1], w[0], w[1])
		}
	}
}
