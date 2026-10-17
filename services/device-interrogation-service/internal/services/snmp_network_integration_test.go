package services

// DCIM row 1.5d: the SNMP collector writes interfaces, addresses and VLANs
// through the identity engine, and its ARP cache as supporting evidence.
//
// The parity test drives the REAL adapter from a RECORDED walk: the text walk
// (snmpfake.Recording) is served by a fake UDP agent, the shared SNMP
// interrogator walks it, snmpNetworkSighting builds the sighting, and
// identitytest.RunAdapterParity runs it through Intake, the engine and the
// Postgres repository.
//
// Skips unless TEST_DATABASE_URL is set (`make test-integration-db`).

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/snmpfake"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// snmpParityAdapter is the SNMP adapter from one recorded walk to the sighting
// the platform posts. managed is the address the platform knows the device by.
func snmpParityAdapter(t *testing.T, name, managed string) identitytest.ParityAdapter {
	return identitytest.ParityAdapterFunc{
		AdapterName: "snmp/" + name,
		Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
			rec, err := snmpfake.Unmarshal(response)
			if err != nil {
				return identity.Sighting{}, err
			}
			host, port := snmpfake.Serve(t, rec.MIB, rec.Community)
			devicetest.AllowListener(t, net.JoinHostPort(host, strconv.Itoa(port)))
			res, err := (&di.SNMPInterrogator{}).Interrogate(context.Background(),
				di.DeviceInfo{DeviceType: "generic_snmp", IPAddress: host, Port: port},
				di.Credentials{Custom: map[string]interface{}{"community": rec.Community}})
			if err != nil {
				return identity.Sighting{}, err
			}
			tenant, err := uuid.Parse(tenantID)
			if err != nil {
				return identity.Sighting{}, err
			}
			// What binds the sighting to the device: its serial when it has
			// one, its name always (sysName). Production binds by the
			// identifiers the platform already holds (persistNetwork).
			var ids []identity.SightedIdentifier
			if res.DeviceIdentity != nil && res.DeviceIdentity.SerialNumber != "" {
				ids = append(ids, identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: res.DeviceIdentity.SerialNumber})
			}
			if sysName, _ := res.DeviceInfo["1.3.6.1.2.1.1.5.0"].(string); sysName != "" {
				ids = append(ids, identity.SightedIdentifier{Kind: identity.KindHostname, Value: sysName})
			}
			n := res.Network
			n.ManagementAddress = managed // the fake agent listens on loopback
			return snmpNetworkSighting(tenant, identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:snmp-parity", Mode: identity.ModeActive}, at, ids, n)
		},
	}
}

// switchWant is what L3Switch48's walk describes, completely — written from the
// fixture's construction, not from the collector's output.
func switchWant() identitytest.ParityWant {
	var ifs []identitytest.WantInterface
	for p := 1; p <= 48; p++ {
		w := identitytest.WantInterface{
			Name: fmt.Sprintf("GigabitEthernet1/0/%d", p), MAC: fmt.Sprintf("00:1b:17:aa:00:%02x", p),
			MTU: 1500, OperStatus: "down", AdminStatus: "up",
		}
		if p <= 24 {
			w.Type, w.SpeedKbps, w.OperStatus = "1000base-t", 1_000_000, "up"
		}
		switch {
		case p <= 12:
			w.Mode, w.UntaggedVLAN = "access", 10
		case p <= 23:
			w.Mode, w.UntaggedVLAN = "access", 20
		case p == 24:
			w.Mode, w.UntaggedVLAN, w.TaggedVLANs = "tagged", 1, []int{10, 20, 99}
		case p >= 25 && p <= 45:
			w.Mode, w.UntaggedVLAN = "access", 99
		case p == 46:
			w.Addresses = []string{"172.16.46.9/24"}
		case p >= 47:
			w.LAG = "Port-channel1"
		}
		if p == 47 {
			w.AdminStatus = "down"
		}
		ifs = append(ifs, w)
	}
	ifs = append(ifs,
		identitytest.WantInterface{Name: "Port-channel1", Type: "lag", MAC: "00:1b:17:aa:00:31", MTU: 1500, SpeedKbps: 2_000_000,
			OperStatus: "up", AdminStatus: "up", Mode: "tagged", UntaggedVLAN: 1, TaggedVLANs: []int{10, 20, 99}},
		identitytest.WantInterface{Name: "Vlan10", Type: "virtual", MAC: "00:1b:17:aa:01:0a", MTU: 1500, SpeedKbps: 1_000_000,
			OperStatus: "up", AdminStatus: "up", Addresses: []string{"10.0.10.1/24", "2001:db8:10::1/64"}},
		identitytest.WantInterface{Name: "Vlan20", Type: "virtual", MAC: "00:1b:17:aa:01:14", MTU: 1500, SpeedKbps: 1_000_000,
			OperStatus: "up", AdminStatus: "up", Addresses: []string{"10.0.20.1/24"}},
		identitytest.WantInterface{Name: "Vlan99", Type: "virtual", MAC: "00:1b:17:aa:01:63", MTU: 1500, SpeedKbps: 1_000_000,
			OperStatus: "up", AdminStatus: "up", Addresses: []string{"10.0.99.2/24"}},
		identitytest.WantInterface{Name: "Loopback0", Type: "virtual", MTU: 1514,
			OperStatus: "up", AdminStatus: "up", Addresses: []string{"10.255.0.2/32"}},
		identitytest.WantInterface{Name: "GigabitEthernet1/0/2.200", Type: "virtual", MAC: "00:1b:17:aa:00:02", MTU: 1500, SpeedKbps: 1_000_000,
			OperStatus: "up", AdminStatus: "up", Parent: "GigabitEthernet1/0/2", Mode: "access", UntaggedVLAN: 200,
			Addresses: []string{"192.0.2.1/30"}},
	)
	return identitytest.ParityWant{
		Interfaces: ifs,
		VLANs: []identitytest.WantVLAN{{VID: 1, Name: "default"}, {VID: 10, Name: "users"}, {VID: 20, Name: "voice"},
			{VID: 99, Name: "infra"}, {VID: 200, Name: "VLAN 200"}},
		// Vlan99 is the management address; the IPv6 primary is the only
		// global v6 address.
		PrimaryIP4: "10.0.99.2",
		PrimaryIP6: "2001:db8:10::1",
	}
}

func linuxWant() identitytest.ParityWant {
	return identitytest.ParityWant{
		Interfaces: []identitytest.WantInterface{
			{Name: "lo", Type: "virtual", MTU: 65536, SpeedKbps: 10_000, OperStatus: "up", AdminStatus: "up"},
			{Name: "eth0", Type: "1000base-t", MAC: "3c:ec:ef:11:22:33", MTU: 9000, SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
				Addresses: []string{"198.51.100.24/24", "2001:db8:aa::24/128"}},
			{Name: "eth0.100", Type: "virtual", MAC: "3c:ec:ef:11:22:33", MTU: 9000, SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
				Parent: "eth0", Mode: "access", UntaggedVLAN: 100, Addresses: []string{"10.100.0.24/24"}},
			// The container bridge and veth: interfaces, but no MAC and no
			// address of the host's.
			{Name: "docker0", Type: "bridge", MTU: 1500, OperStatus: "down", AdminStatus: "up"},
			{Name: "veth3a9c1d2", Type: "virtual", MTU: 1500, SpeedKbps: 10_000_000, OperStatus: "up", AdminStatus: "up"},
		},
		VLANs:      []identitytest.WantVLAN{{VID: 100, Name: "VLAN 100"}},
		PrimaryIP4: "198.51.100.24",
		PrimaryIP6: "2001:db8:aa::24",
	}
}

// TestIntegration_SNMP_AdapterParity: a 48-port layer-3 switch (LAG, PVIDs and
// trunks, SVIs with IPv4 and IPv6 addresses, a loopback whose length comes from
// ipAddrTable, a routed sub-interface) and a net-snmp Linux host (VLAN
// sub-interface by name, container bridge) each become exactly the interfaces,
// addresses and VLANs the walk describes — idempotently, with the community
// string and the secrets planted in sysDescr, sysContact, sysLocation and
// ifAlias in no table.
//
// Mutations (each red, then restored green): drop ifMtu from the projection
// (mtu is NULL on every port); remove the LAG attachment walk; map ifType 161
// to `other`; drop the container-interface rule (docker0 holds 172.17.0.1);
// remove the (asset, name) lookup in RecordObservedNetwork's interface upsert.
func TestIntegration_SNMP_AdapterParity(t *testing.T) {
	sw := snmpfake.L3Switch48()
	identitytest.RunAdapterParity(t, snmpParityAdapter(t, "l3-switch-48", "10.0.99.2"), []identitytest.ParityFixture{{
		Name:     "l3-switch-48",
		Response: sw.Marshal(),
		Secrets:  []string{snmpfake.SwitchCommunity, "uplink to HR vpn psk " + snmpfake.SwitchSecret},
		Want:     switchWant(),
	}})
	lx := snmpfake.LinuxNetSNMP()
	identitytest.RunAdapterParity(t, snmpParityAdapter(t, "linux-net-snmp", "198.51.100.24"), []identitytest.ParityFixture{{
		Name:     "linux-net-snmp",
		Response: lx.Marshal(),
		Secrets:  []string{snmpfake.LinuxCommunity, "mgmt " + snmpfake.LinuxSecret},
		Want:     linuxWant(),
	}})
}

// TestIntegration_SNMP_NetworkThroughTheSink drives the real sink path: the
// interrogated device already exists (known by its serial); Persist posts the
// network sighting bound to it, so its interfaces and addresses land on THAT
// asset, no net.interfaces fact is written, and the ARP cache is recorded as
// supporting evidence — an address another asset holds gains its MAC, an unknown
// one is parked, and no asset, interface or address is created from it.
//
// Mutation: let ARP create — turn the park branch of recordSNMPARPEvidence into
// an INSERT of the address — red (ip_addresses grows).
func TestIntegration_SNMP_NetworkThroughTheSink(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	src := identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:" + uuid.NewString(), Mode: identity.ModeActive}

	// The device the session is opened to (added at its management address),
	// and a second asset that already owns
	// 10.0.10.11 (a host on the switch's Vlan10).
	post := func(sg identity.Sighting) uuid.UUID {
		t.Helper()
		_, res, err := postSighting(ctx, db, sg)
		if err != nil {
			t.Fatalf("postSighting: %v", err)
		}
		id, err := uuid.Parse(res.Asset.ID)
		if err != nil {
			t.Fatalf("no asset: %+v", res)
		}
		return id
	}
	device := post(identity.Sighting{TenantID: tenant.String(), Source: src, Channel: identity.ChannelAuthenticatedSession, ObservedAt: at,
		Confidence: 1, Ownership: identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "FOC2432L0AB"},
			{Kind: identity.KindIPAddress, Value: "10.0.99.2"}}})
	other := post(identity.Sighting{TenantID: tenant.String(), Source: src, Channel: identity.ChannelAuthenticatedSession, ObservedAt: at,
		Confidence: 1, Ownership: identity.OwnershipInternal,
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "HOST-11"}},
		Interfaces:  []identity.ObservedInterface{{Name: "eth0", Addresses: []identity.ObservedAddress{{Address: "10.0.10.11", PrefixLen: 24}}}}})

	rec := snmpfake.L3Switch48()
	host, port := snmpfake.Serve(t, rec.MIB, rec.Community)
	devicetest.AllowListener(t, net.JoinHostPort(host, strconv.Itoa(port)))
	res, err := (&di.SNMPInterrogator{}).Interrogate(ctx, di.DeviceInfo{DeviceType: "generic_snmp", IPAddress: host, Port: port},
		di.Credentials{Custom: map[string]interface{}{"community": rec.Community}})
	if err != nil {
		t.Fatal(err)
	}
	res.Network.ManagementAddress = "10.0.99.2"

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	persist := func(when time.Time) {
		t.Helper()
		if err := NewObservationSink(db).Persist(ctx, tenant, device, src, InterrogationObservations{ObservedAt: when, Network: res.Network}); err != nil {
			t.Fatalf("Persist: %v", err)
		}
	}

	persist(at.Add(time.Minute))
	// (The empty synthetic `observed-1` the Add-device sighting filed for the
	// management address is the identity seam's, not the collector's: a named
	// report moves the address onto Vlan99 and leaves the placeholder behind.)
	if n := count(`SELECT count(*) FROM interfaces WHERE tenant_id=$1 AND asset_id=$2 AND status <> 'rejected' AND source_ref <> $3`,
		tenant, device, identity.SyntheticInterfaceSourceRef); n != 54 {
		t.Fatalf("the device has %d interfaces, want 54", n)
	}
	if n := count(`SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key='net.interfaces'`, tenant, device); n != 0 {
		t.Errorf("a net.interfaces fact was written for SNMP (%d rows): the key is retired for this collector", n)
	}
	var primary string
	if err := db.QueryRow(`SELECT coalesce(host(ip.address),'') FROM assets a LEFT JOIN ip_addresses ip ON ip.tenant_id=a.tenant_id AND ip.id=a.primary_ip4_id
		WHERE a.tenant_id=$1 AND a.id=$2`, tenant, device).Scan(&primary); err != nil {
		t.Fatal(err)
	}
	if primary != "10.0.99.2" {
		t.Errorf("primary IPv4 = %q, want the management address 10.0.99.2", primary)
	}

	// ARP: 10.0.10.11 is `other`'s, so it gains its MAC; 10.0.10.12 and
	// 10.0.20.21 are nobody's, so they are parked against the interface that
	// learned them.
	var mac string
	if err := db.QueryRow(`SELECT coalesce(mac_address::text,'') FROM ip_addresses WHERE tenant_id=$1 AND host(address)='10.0.10.11'`, tenant).Scan(&mac); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mac, "00:00:5e:ff:fe:00:53:11") && !strings.HasPrefix(mac, "00:00:5e:00:53:11") {
		t.Errorf("10.0.10.11 (held by %s) has MAC %q, want 00:00:5e:00:53:11", other, mac)
	}
	if n := count(`SELECT count(*) FROM ip_addresses WHERE tenant_id=$1 AND host(address) IN ('10.0.10.12','10.0.20.21','10.0.10.13','10.0.10.14')`, tenant); n != 0 {
		t.Errorf("ARP created %d address rows", n)
	}
	assets := count(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant)
	if assets != 2 {
		t.Errorf("%d assets, want the device and its neighbour only: ARP must never create an asset", assets)
	}
	rows, err := db.Query(`SELECT far_identity->>'mac_address', attributes->>'address', observation_count FROM unresolved_terminations
		WHERE tenant_id=$1 AND producer='snmp' AND intent='assignment' ORDER BY 2`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	var parked []string
	for rows.Next() {
		var m, a string
		var c int
		if err := rows.Scan(&m, &a, &c); err != nil {
			t.Fatal(err)
		}
		parked = append(parked, fmt.Sprintf("%s=%s×%d", a, m, c))
	}
	_ = rows.Close()
	if got := strings.Join(parked, " "); got != "10.0.10.12=00:00:5e:00:53:12×1 10.0.20.21=00:00:5e:00:53:21×1" {
		t.Errorf("parked terminations = %q", got)
	}

	// A second run bumps the parked rows and duplicates nothing.
	ifaces, addrs := count(`SELECT count(*) FROM interfaces WHERE tenant_id=$1`, tenant), count(`SELECT count(*) FROM ip_addresses WHERE tenant_id=$1`, tenant)
	persist(at.Add(2 * time.Minute))
	if n := count(`SELECT count(*) FROM interfaces WHERE tenant_id=$1`, tenant); n != ifaces {
		t.Errorf("interfaces %d → %d on re-run", ifaces, n)
	}
	if n := count(`SELECT count(*) FROM ip_addresses WHERE tenant_id=$1`, tenant); n != addrs {
		t.Errorf("ip_addresses %d → %d on re-run", addrs, n)
	}
	if n := count(`SELECT count(*) FROM unresolved_terminations WHERE tenant_id=$1 AND producer='snmp' AND observation_count=2`, tenant); n != 2 {
		t.Errorf("%d parked rows were bumped on the re-run, want 2", n)
	}
	if n := count(`SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant); n != 2 {
		t.Errorf("%d assets after the re-run, want 2", n)
	}
}
