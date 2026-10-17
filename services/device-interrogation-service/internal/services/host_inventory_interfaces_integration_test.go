package services

// DCIM row 1.5a: the device agent's host inventory writes interfaces and IP
// addresses through the identity engine, and no longer writes the
// net.interfaces fact.
//
// The parity test drives the REAL adapter from the RECORDED command output:
// `ip -d -j addr` / Get-NetAdapter bytes → the hostinventory parser → the
// collector projection (ToObservations) → hostSighting → identity.Intake →
// identity.Engine → the Postgres repository, through
// identitytest.RunAdapterParity. The materialise tests drive the whole
// MaterialiseAndRecord path, including the post to inventory-service.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// parityAgentID is the agent the recorded reports came from.
var parityAgentID = uuid.MustParse("6d1c2f0a-5b1e-4c55-9f41-0a7f3e2b1c01")

// hostInventoryParityAdapter is the device agent's host-inventory adapter,
// from one platform's recorded interface output to the sighting the platform
// posts. managed is the address the platform knows the host by (the agent's
// own reported address), "" for none.
func hostInventoryParityAdapter(platform string, managed string) identitytest.ParityAdapter {
	return identitytest.ParityAdapterFunc{
		AdapterName: "host-inventory/" + platform,
		Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
			var (
				ifaces []hostinventory.Interface
				err    error
			)
			switch platform {
			case hostinventory.PlatformLinux:
				ifaces, err = hostinventory.ParseIPJSON(response)
			case hostinventory.PlatformWindows:
				ifaces, err = hostinventory.ParseWindowsAdapters(response)
			}
			if err != nil {
				return identity.Sighting{}, err
			}
			rep := &hostinventory.Report{
				Collected:  at,
				Mode:       hostinventory.ModeLocal,
				Platform:   platform,
				AgentID:    parityAgentID.String(),
				Host:       hostinventory.Host{Hostname: "parity-" + platform},
				Interfaces: ifaces,
				Sections:   map[string]string{hostinventory.SectionInterfaces: hostinventory.SectionOK},
			}
			obs, err := hostinventory.ToObservations(rep)
			if err != nil {
				return identity.Sighting{}, err
			}
			subject, ok := hostInventorySubject(obs)
			if !ok {
				return identity.Sighting{}, os.ErrNotExist
			}
			tenant, err := uuid.Parse(tenantID)
			if err != nil {
				return identity.Sighting{}, err
			}
			jobID := uuid.NewSHA1(parityAgentID, []byte(at.String()))
			return hostSighting(tenant, subject, hostInventoryMeta(obs), obs,
				hostInventorySource(parityAgentID, jobID), hostInventoryRunRef(parityAgentID, jobID), managed)
		},
	}
}

func parityFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "host_inventory_parity", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestIntegration_HostInventory_AdapterParity: a Linux host with a bond, its
// two members and a VLAN sub-interface on the bond, and a Windows host with a
// disconnected NIC and a NIC carrying a VLAN, each become exactly the
// interfaces, addresses and VLANs the OS reported — virtual interfaces and
// link-local addresses left out — idempotently, with the secret planted in
// each recording (an interface alias, a driver description) nowhere.
//
// Mutations (each red, then restored green): drop `MTU` from
// hostInventoryInterfaces (the mtu column is NULL); drop the VLAN → Parent
// projection; remove the (asset, name) lookup in RecordObservedNetwork's
// interface upsert (the re-observation duplicates or fails); remove the
// management-address rule in primaryAddressFor (the Linux host's primary
// becomes 198.51.100.24).
func TestIntegration_HostInventory_AdapterParity(t *testing.T) {
	identitytest.RunAdapterParity(t, hostInventoryParityAdapter(hostinventory.PlatformLinux, "10.100.0.24"), []identitytest.ParityFixture{{
		Name:     "linux-bond-vlan",
		Response: parityFixture(t, "linux-bond-vlan.ip-d-j-addr.json"),
		Secrets:  []string{"PlantedLinuxSecret8842"},
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "eth0", MAC: "b4:96:91:1a:2b:3c", MTU: 9000, OperStatus: "up", LAG: "bond0"},
				{Name: "eth1", MAC: "b4:96:91:1a:2b:3c", MTU: 9000, OperStatus: "up", LAG: "bond0"},
				{Name: "bond0", Type: "lag", MAC: "b4:96:91:1a:2b:3c", MTU: 9000, OperStatus: "up",
					Addresses: []string{"198.51.100.24/24", "2001:db8:aa::24/64"}},
				{Name: "bond0.100", Type: "virtual", MAC: "b4:96:91:1a:2b:3c", MTU: 9000, OperStatus: "up",
					Parent: "bond0", Mode: "access", UntaggedVLAN: 100, Addresses: []string{"10.100.0.24/24"}},
			},
			VLANs: []identitytest.WantVLAN{{VID: 100, Name: "VLAN 100"}},
			// The management address, though bond0's address was listed first.
			PrimaryIP4: "10.100.0.24",
			PrimaryIP6: "2001:db8:aa::24",
		},
	}})
	identitytest.RunAdapterParity(t, hostInventoryParityAdapter(hostinventory.PlatformWindows, ""), []identitytest.ParityFixture{{
		Name:     "windows",
		Response: parityFixture(t, "windows.adapters.json"),
		Secrets:  []string{"PlantedWindowsSecret5531"},
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "Ethernet", MAC: "b4:96:91:1a:2b:4c", MTU: 1500, SpeedKbps: 1_000_000, OperStatus: "up",
					Addresses: []string{"198.51.100.44/24", "2001:db8:aa::44/64"}},
				{Name: "Ethernet 2", MAC: "b4:96:91:1a:2b:4d", MTU: 1500, OperStatus: "down"},
				{Name: "Ethernet 3", MAC: "b4:96:91:1a:2b:4e", MTU: 1500, SpeedKbps: 10_000_000, OperStatus: "up",
					Mode: "access", UntaggedVLAN: 30, Addresses: []string{"10.30.0.44/24"}},
			},
			VLANs:      []identitytest.WantVLAN{{VID: 30, Name: "VLAN 30"}},
			PrimaryIP4: "198.51.100.44",
			PrimaryIP6: "2001:db8:aa::44",
		},
	}})
}

// TestIntegration_HostInventory_WritesInterfacesNotFacts drives the whole
// MaterialiseAndRecord path: the host's real interfaces land as `interfaces`
// rows with their addresses on them, and no net.interfaces fact is written.
//
// Mutation: re-add the fact write (drop the KeyNetInterfaces skip in
// hostInventoryFacts) — red.
func TestIntegration_HostInventory_WritesInterfacesNotFacts(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()
	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)

	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "IFC0001", defaultPackages())
	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil {
		t.Fatalf("MaterialiseAndRecord: %v", err)
	}
	if counts.AssetID == "" {
		t.Fatalf("no asset: %+v", counts)
	}

	if _, ok := factValue(t, owner, tenantID, counts.AssetID, facts.KeyNetInterfaces); ok {
		t.Error("a net.interfaces fact was written for a host: the key is retired for hosts (DCIM row 1.5), its data lives in interfaces")
	}
	// The other facts still land: the retirement is one key, not the batch.
	if _, ok := factValue(t, owner, tenantID, counts.AssetID, facts.KeyOSName); !ok {
		t.Error("os.name is missing: retiring net.interfaces must not drop the other facts")
	}

	got := map[string][]string{}
	rows, err := owner.Query(`
		SELECT i.name, coalesce(host(ip.address) || '/' || masklen(ip.address), '')
		  FROM interfaces i
		  LEFT JOIN ip_addresses ip ON ip.tenant_id = i.tenant_id AND ip.assigned_kind = 'interface' AND ip.assigned_id = i.id
		 WHERE i.tenant_id = $1 AND i.asset_id = $2 ORDER BY i.name`, tenantID, counts.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, addr string
		if err := rows.Scan(&name, &addr); err != nil {
			t.Fatal(err)
		}
		if addr != "" {
			got[name] = append(got[name], addr)
		} else if _, ok := got[name]; !ok {
			got[name] = nil
		}
	}
	_ = rows.Close()
	// eno1 and wlan0 are real interfaces (wlan0's MAC is locally administered,
	// so it carries no MAC, but it is still an interface with an address); the
	// container veth is not an interface of the host's inventory.
	if len(got) != 2 || len(got["eno1"]) != 1 || got["eno1"][0] != "198.51.100.20/24" ||
		len(got["wlan0"]) != 1 || got["wlan0"][0] != "192.0.2.44/24" {
		t.Errorf("interfaces = %v, want eno1 198.51.100.20/24 and wlan0 192.0.2.44/24, and no veth", got)
	}
	var synthetic int
	if err := owner.QueryRow(`SELECT count(*) FROM interfaces WHERE tenant_id = $1 AND asset_id = $2 AND source_ref = $3`,
		tenantID, counts.AssetID, identity.SyntheticInterfaceSourceRef).Scan(&synthetic); err != nil {
		t.Fatal(err)
	}
	if synthetic != 0 {
		t.Errorf("%d synthetic observed-<n> interfaces: the host named every interface, so none should be invented", synthetic)
	}
}

// TestIntegration_HostInventory_PrimaryIPFromManagementAddress: the agent's
// own reported address (device_agents.ip_address) is the host's primary IPv4,
// even when another interface's address comes first in the report.
//
// Mutation: remove the management-address rule in primaryAddressFor — red
// (the primary becomes eno1's 198.51.100.20).
func TestIntegration_HostInventory_PrimaryIPFromManagementAddress(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()
	appDB := testdb.ConnectAsAppRole(t, owner)
	agentID := seedHostInventoryAgent(t, owner, tenantID)
	if _, err := owner.Exec(`UPDATE device_agents SET ip_address = '192.0.2.44' WHERE tenant_id = $1 AND id = $2`, tenantID, agentID); err != nil {
		t.Fatal(err)
	}
	jobID := newHostInventoryJob(t, appDB, owner, tenantID, agentID)
	rep := hostReport(hostinventory.ModeLocal, agentID.String(), "IFC0002", defaultPackages())
	counts, err := NewHostInventoryIngest(appDB, owner).MaterialiseAndRecord(ctx, tenantID, agentID, jobID, observationsFor(t, rep))
	if err != nil || counts.AssetID == "" {
		t.Fatalf("MaterialiseAndRecord: %v (%+v)", err, counts)
	}
	var primary string
	if err := owner.QueryRow(`
		SELECT coalesce(host(ip.address), '') FROM assets a
		  LEFT JOIN ip_addresses ip ON ip.tenant_id = a.tenant_id AND ip.id = a.primary_ip4_id
		 WHERE a.tenant_id = $1 AND a.id = $2`, tenantID, counts.AssetID).Scan(&primary); err != nil {
		t.Fatal(err)
	}
	if primary != "192.0.2.44" {
		t.Errorf("primary IPv4 = %q, want the agent's management address 192.0.2.44", primary)
	}
}
