package services

// DCIM row 1.5c: the Cisco, Palo Alto, Fortinet and F5 interrogations write
// interfaces, addresses, connected prefixes and VLANs through the identity
// engine, held to identitytest.RunAdapterParity.
//
// The adapter drives the REAL collector: a fake appliance serves the recorded
// device output (testdata/vendor_network/<vendor>/device, over SSH for Cisco
// and iControl / XML / FortiOS REST for the others), the interrogator is taken
// from the Registry (so Sanitize runs as in production), and its
// NetworkObservation becomes the sighting through snmpNetworkSighting — the
// row-1.5 network adapter persistNetwork posts for every collector that fills
// InterrogateResult.Network. The harness then runs Intake, the
// engine and the Postgres repository and holds the rows to the fixture: exact
// parity, an idempotent re-run, and the planted secret in no tenant table.
//
// The device is bound by the serial it reported (in production it is bound by
// the identifiers the platform already holds for it, knownAssetIdentifiers),
// and its management address is the scenario's (in production, the address
// the device record holds).
//
// Mutations (each red, then restored green): drop `ifc.MTU = d.mtu` from
// ciscoNetwork; drop the trunk's TaggedVLANs; drop `ifc.LAG = lagOf[...]` in
// panNetwork; drop the VDOM → VRF mapping in fortinetNetwork; drop the
// route-domain split in f5Network; drop the ifnames canonicalisation in
// ciscoCanonical (Cisco's status and trunk rows then join no interface);
// drop VirtualDeviceContexts from decodeNetwork / snmpNetworkSighting (DCIM
// gap 1: the contexts then reach no row, and the interfaces' names alone
// create them without identifiers).
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
)

const vendorNetworkDir = "testdata/vendor_network"

// vendorRecording is every file the fake appliance serves, concatenated: the
// "response" the harness searches for the planted secret.
func vendorRecording(t *testing.T, vendor string) []byte {
	t.Helper()
	dir := filepath.Join(vendorNetworkDir, vendor, "device")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var out []byte
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
		out = append(out, '\n')
	}
	return out
}

// interrogateVendorAppliance interrogates the vendor's fake appliance through
// the Registry and returns the result.
func interrogateVendorAppliance(t *testing.T, vendor string) (*di.InterrogateResult, pipelinetest.Scenario) {
	t.Helper()
	dir, err := filepath.Abs(vendorNetworkDir)
	if err != nil {
		t.Fatal(err)
	}
	s := pipelinetest.LoadScenario(t, dir, vendor)
	app := pipelinetest.StartAppliance(t, dir, s)
	device := di.DeviceInfo{DeviceType: s.DeviceType, Hostname: s.Hostname}
	if s.Transport == "rest" {
		device.ManagementURL = app.ManagementURL
		// The device record's own address: a REST collector reaches the
		// device by its management URL (the fake, on loopback) and reports
		// the record's address as the management address.
		device.IPAddress = s.ManagementIP
	} else {
		device.IPAddress, device.Port = app.Host, app.Port
	}
	interrogator, err := di.NewRegistry().Get(s.DeviceType)
	if err != nil {
		t.Fatalf("registry.Get(%s): %v", s.DeviceType, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := interrogator.Interrogate(ctx, device,
		di.Credentials{Username: "readonly", Password: "readonly-password", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("Interrogate(%s): %v", vendor, err)
	}
	if result.Network.Empty() {
		t.Fatalf("%s: the interrogation produced no network observation", vendor)
	}
	return result, s
}

// vendorNetworkParityAdapter is one vendor's 1.5c adapter: fake appliance →
// collector → Sanitize → snmpNetworkSighting.
func vendorNetworkParityAdapter(t *testing.T, vendor string) identitytest.ParityAdapter {
	return identitytest.ParityAdapterFunc{
		AdapterName: "vendor-network/" + vendor,
		Fn: func(tenantID string, _ []byte, at time.Time) (identity.Sighting, error) {
			result, scenario := interrogateVendorAppliance(t, vendor)
			tenant, err := uuid.Parse(tenantID)
			if err != nil {
				return identity.Sighting{}, err
			}
			var ids []identity.SightedIdentifier
			if result.DeviceIdentity != nil && result.DeviceIdentity.SerialNumber != "" {
				ids = append(ids, identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: result.DeviceIdentity.SerialNumber})
			}
			source := interrogationSource(uuid.NewSHA1(tenant, []byte(vendor+at.String())))
			// An SSH collector's management address is the address it dialled
			// — the fake, on loopback, which is never reported; the scenario's
			// address stands in for it. A REST collector reported the record's.
			if scenario.Transport != "rest" {
				result.Network.ManagementAddress = scenario.ManagementIP
			}
			return snmpNetworkSighting(tenant, source, at, ids, result.Network)
		},
	}
}

func createVRF(name string) func(t *testing.T, db *sql.DB, tenantID string) {
	return func(t *testing.T, db *sql.DB, tenantID string) {
		if _, err := db.Exec(`INSERT INTO public.vrfs (tenant_id, name) VALUES ($1, $2)`, tenantID, name); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIntegration_VendorNetworkParity_CiscoIOSXESwitch: access ports, a 10G
// trunk uplink with a native VLAN, a two-member port-channel trunk with a
// wrapped allowed list, an all-VLAN trunk (tagged-all), two SVIs whose
// addresses give their VLANs' connected prefixes.
func TestIntegration_VendorNetworkParity_CiscoIOSXESwitch(t *testing.T) {
	identitytest.RunAdapterParity(t, vendorNetworkParityAdapter(t, "cisco"), []identitytest.ParityFixture{{
		Name:     "access-trunk-po-svi",
		Response: vendorRecording(t, "cisco"),
		Secrets:  []string{"PlantedCiscoSecret-7731"},
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "GigabitEthernet1/0/1", Type: "1000base-t", MAC: "00:b0:e1:a2:c0:01", MTU: 1500, SpeedKbps: 1_000_000,
					OperStatus: "up", AdminStatus: "up", Mode: "access", UntaggedVLAN: 10},
				{Name: "GigabitEthernet1/0/2", Type: "1000base-t", MAC: "00:b0:e1:a2:c0:02", MTU: 1500,
					OperStatus: "down", AdminStatus: "down", Mode: "access", UntaggedVLAN: 10},
				{Name: "GigabitEthernet1/0/47", Type: "1000base-t", MAC: "00:b0:e1:a2:c0:2f", MTU: 1500, SpeedKbps: 1_000_000,
					OperStatus: "up", AdminStatus: "up", Mode: "tagged-all", UntaggedVLAN: 1, LAG: "Port-channel1"},
				{Name: "GigabitEthernet1/0/48", Type: "1000base-t", MAC: "00:b0:e1:a2:c0:30", MTU: 1500, SpeedKbps: 1_000_000,
					OperStatus: "up", AdminStatus: "up", Mode: "tagged-all", UntaggedVLAN: 1, LAG: "Port-channel1"},
				{Name: "TenGigabitEthernet1/1/1", Type: "10gbase-x-sfpp", MAC: "00:b0:e1:a2:c1:01", MTU: 9198, SpeedKbps: 10_000_000,
					OperStatus: "up", AdminStatus: "up", Mode: "tagged", UntaggedVLAN: 99, TaggedVLANs: []int{10, 20}},
				{Name: "Port-channel1", Type: "lag", MAC: "00:b0:e1:a2:c0:f1", MTU: 1500, SpeedKbps: 2_000_000,
					OperStatus: "up", AdminStatus: "up", Mode: "tagged", UntaggedVLAN: 99, TaggedVLANs: []int{10, 20, 30}},
				{Name: "Vlan10", Type: "virtual", MAC: "00:b0:e1:a2:c0:0a", MTU: 1500, OperStatus: "up", AdminStatus: "up",
					Addresses: []string{"10.20.10.1/24"}},
				{Name: "Vlan99", Type: "virtual", MAC: "00:b0:e1:a2:c0:63", MTU: 1500, OperStatus: "up", AdminStatus: "up",
					Addresses: []string{"10.20.99.2/24"}},
			},
			Prefixes: []identitytest.WantPrefix{
				{Prefix: "10.20.10.0/24", VLAN: 10},
				{Prefix: "10.20.99.0/24", VLAN: 99},
			},
			VLANs: []identitytest.WantVLAN{
				{VID: 1, Name: "default"}, {VID: 10, Name: "users"}, {VID: 20, Name: "voice"},
				{VID: 30, Name: "lab"}, {VID: 99, Name: "mgmt"},
			},
			PrimaryIP4: "10.20.99.2",
		},
	}})
}

// TestIntegration_VendorNetworkParity_PaloAlto: an aggregate (ae1) of two
// ports, tagged sub-interfaces on it — one in a non-default virtual router,
// recorded in that VRF and never identity — an untrust port and the
// management interface.
func TestIntegration_VendorNetworkParity_PaloAlto(t *testing.T) {
	identitytest.RunAdapterParity(t, vendorNetworkParityAdapter(t, "paloalto"), []identitytest.ParityFixture{{
		Name:     "ae-subinterfaces-vr",
		Response: vendorRecording(t, "paloalto"),
		Secrets:  []string{"PlantedPanSecret-5521"},
		Setup:    createVRF("corp"),
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "Ethernet1/1", MAC: "00:1b:17:0a:30:11", SpeedKbps: 1_000_000, OperStatus: "up", Addresses: []string{"198.51.100.2/24"}},
				{Name: "Ethernet1/5", MAC: "00:1b:17:0a:30:15", SpeedKbps: 10_000_000, OperStatus: "up", LAG: "ae1"},
				{Name: "Ethernet1/6", MAC: "00:1b:17:0a:30:16", SpeedKbps: 10_000_000, OperStatus: "up", LAG: "ae1"},
				{Name: "ae1", Type: "lag", MAC: "00:1b:17:0a:30:a1", SpeedKbps: 20_000_000, OperStatus: "up"},
				{Name: "ae1.100", Type: "virtual", Mode: "access", UntaggedVLAN: 100, Parent: "ae1", Addresses: []string{"10.30.100.1/24"}},
				{Name: "ae1.200", Type: "virtual", Mode: "access", UntaggedVLAN: 200, Parent: "ae1", Addresses: []string{"corp|10.30.200.1/24"}},
				{Name: "management", MAC: "00:1b:17:0a:30:0c", Addresses: []string{"10.30.0.5/24"}},
			},
			Prefixes: []identitytest.WantPrefix{
				{Prefix: "10.30.0.0/24"},
				{Prefix: "10.30.100.0/24", VLAN: 100},
				{Prefix: "10.30.200.0/24", VRF: "corp", VLAN: 200},
				{Prefix: "198.51.100.0/24"},
			},
			VLANs: []identitytest.WantVLAN{{VID: 100, Name: "VLAN 100"}, {VID: 200, Name: "VLAN 200"}},
			// DCIM gap 1: <vsys> is the context; management is in none.
			VirtualDeviceContexts: []identitytest.WantVirtualDeviceContext{
				{Name: "vsys1", Identifier: "1", Interfaces: []string{"Ethernet1/1", "ae1", "ae1.100"}},
				{Name: "vsys2", Identifier: "2", Interfaces: []string{"ae1.200"}},
			},
			PrimaryIP4: "10.30.0.5",
		},
	}})
}

// TestIntegration_VendorNetworkParity_FortiGate: a WAN port, an aggregate of
// two ports, VLAN interfaces on it — one in a non-root VDOM (its VRF) — with an
// overridden MTU.
func TestIntegration_VendorNetworkParity_FortiGate(t *testing.T) {
	identitytest.RunAdapterParity(t, vendorNetworkParityAdapter(t, "fortinet"), []identitytest.ParityFixture{{
		Name:     "aggregate-vlans-vdom",
		Response: vendorRecording(t, "fortinet"),
		Secrets:  []string{"PlantedFortiSecret-3390"},
		Setup:    createVRF("guest"),
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "port1", MAC: "00:09:0f:aa:39:01", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
					Addresses: []string{"203.0.113.2/29"}},
				{Name: "port2", MAC: "00:09:0f:aa:39:02", SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up", LAG: "agg1"},
				{Name: "port3", MAC: "00:09:0f:aa:39:03", OperStatus: "down", AdminStatus: "down", LAG: "agg1"},
				{Name: "agg1", Type: "lag", MAC: "00:09:0f:aa:39:a1", SpeedKbps: 2_000_000, OperStatus: "up", AdminStatus: "up",
					Addresses: []string{"10.40.0.1/24"}},
				{Name: "vlan-users", Type: "virtual", MTU: 9000, SpeedKbps: 2_000_000, OperStatus: "up", AdminStatus: "up",
					Mode: "access", UntaggedVLAN: 40, Parent: "agg1", Addresses: []string{"10.40.40.1/24"}},
				{Name: "vlan-guest", Type: "virtual", SpeedKbps: 2_000_000, OperStatus: "up", AdminStatus: "up",
					Mode: "access", UntaggedVLAN: 50, Parent: "agg1", Addresses: []string{"guest|10.40.50.1/24"}},
			},
			Prefixes: []identitytest.WantPrefix{
				{Prefix: "10.40.0.0/24"},
				{Prefix: "10.40.40.0/24", VLAN: 40},
				{Prefix: "10.40.50.0/24", VRF: "guest", VLAN: 50},
				{Prefix: "203.0.113.0/29"},
			},
			VLANs: []identitytest.WantVLAN{{VID: 40, Name: "vlan-users"}, {VID: 50, Name: "vlan-guest"}},
			// DCIM gap 1: each VDOM is a context, root included; a VDOM has
			// no identifier.
			VirtualDeviceContexts: []identitytest.WantVirtualDeviceContext{
				{Name: "root", Interfaces: []string{"agg1", "port1", "port2", "port3", "vlan-users"}},
				{Name: "guest", Interfaces: []string{"vlan-guest"}},
			},
			PrimaryIP4: "203.0.113.2",
		},
	}})
}

// TestIntegration_VendorNetworkParity_F5: a copper port untagged in one VLAN,
// a two-port trunk tagged in two, each VLAN a layer-3 interface carrying its
// self IP, one self IP in route domain 2 (its VRF).
func TestIntegration_VendorNetworkParity_F5(t *testing.T) {
	identitytest.RunAdapterParity(t, vendorNetworkParityAdapter(t, "f5"), []identitytest.ParityFixture{{
		Name:     "trunk-vlans-self-routedomain",
		Response: vendorRecording(t, "f5"),
		Secrets:  []string{"PlantedF5Secret-6102"},
		Setup:    createVRF("tenant-a"),
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "1.1", Type: "1000base-t", MAC: "00:23:e9:aa:00:11", MTU: 1500, SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
					Mode: "access", UntaggedVLAN: 101},
				{Name: "1.2", Type: "10gbase-x-sfpp", MAC: "00:23:e9:aa:00:12", MTU: 9198, SpeedKbps: 10_000_000, OperStatus: "up", AdminStatus: "up",
					LAG: "trunk1"},
				{Name: "1.3", Type: "10gbase-x-sfpp", MAC: "00:23:e9:aa:00:13", MTU: 9198, SpeedKbps: 10_000_000, OperStatus: "up", AdminStatus: "up",
					LAG: "trunk1"},
				{Name: "mgmt", Type: "100base-tx", MAC: "00:23:e9:aa:00:ff", SpeedKbps: 100_000, OperStatus: "up", AdminStatus: "up"},
				{Name: "trunk1", Type: "lag", MAC: "00:23:e9:aa:00:21", Mode: "tagged", TaggedVLANs: []int{201, 301}},
				{Name: "external", Type: "virtual", MTU: 1500, Mode: "access", UntaggedVLAN: 101, Addresses: []string{"198.51.100.10/24"}},
				{Name: "internal", Type: "virtual", MTU: 9000, Mode: "access", UntaggedVLAN: 201, Addresses: []string{"tenant-a|10.50.201.5/24"}},
				{Name: "servers", Type: "virtual", MTU: 9000, Mode: "access", UntaggedVLAN: 301, Addresses: []string{"10.50.31.5/24"}},
			},
			Prefixes: []identitytest.WantPrefix{
				{Prefix: "10.50.201.0/24", VRF: "tenant-a", VLAN: 201},
				{Prefix: "10.50.31.0/24", VLAN: 301},
				{Prefix: "198.51.100.0/24", VLAN: 101},
			},
			VLANs: []identitytest.WantVLAN{{VID: 101, Name: "external"}, {VID: 201, Name: "internal"}, {VID: 301, Name: "servers"}},
			// DCIM gap 1: each route domain is a context. external and
			// internal by the route domains' VLAN lists; servers, in no list,
			// by its self IP (no %N: route domain 0).
			VirtualDeviceContexts: []identitytest.WantVirtualDeviceContext{
				{Name: "0", Identifier: "0", Interfaces: []string{"external", "servers"}},
				{Name: "tenant-a", Identifier: "2", Interfaces: []string{"internal"}},
			},
			PrimaryIP4: "198.51.100.10",
		},
	}})
}
