package deviceinterrogation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/snmpfake"
)

// DCIM row 1.5d: the SNMP collector's network posture, driven end to end
// through snmpfake's UDP agent over the synthesised walks (the same walks the
// intake parity tests record).

func snmpNetworkOf(t *testing.T, rec snmpfake.Recording) *InterrogateResult {
	t.Helper()
	host, port := snmpfake.Serve(t, rec.MIB, rec.Community)
	result, err := (&SNMPInterrogator{}).Interrogate(context.Background(),
		DeviceInfo{DeviceType: "generic_snmp", IPAddress: host, Port: port},
		Credentials{Custom: map[string]interface{}{"community": rec.Community}})
	if err != nil {
		t.Fatalf("Interrogate: %v", err)
	}
	if result.Network == nil {
		t.Fatal("no network observation")
	}
	if hasFact(result, factNetInterfaces) {
		t.Errorf("net.interfaces is retired for SNMP but was emitted")
	}
	return result
}

func ifaceNamed(t *testing.T, n *NetworkObservation, name string) ObservedInterface {
	t.Helper()
	for _, i := range n.Interfaces {
		if i.Name == name {
			return i
		}
	}
	t.Fatalf("no interface %q in %d interfaces", name, len(n.Interfaces))
	return ObservedInterface{}
}

func addrStrings(i ObservedInterface) []string {
	var out []string
	for _, a := range i.Addresses {
		s := a.Address
		if a.PrefixLen > 0 {
			s += "/" + itoa(a.PrefixLen)
		}
		if a.Assignment != "" {
			s += " " + a.Assignment
		}
		out = append(out, s)
	}
	return out
}

func TestSNMPNetwork_L3Switch48(t *testing.T) {
	n := snmpNetworkOf(t, snmpfake.L3Switch48()).Network
	if len(n.Interfaces) != 54 {
		t.Fatalf("got %d interfaces, want 54", len(n.Interfaces))
	}
	// Names are the vendor's long form whatever ifName said.
	for _, want := range []string{"GigabitEthernet1/0/1", "Port-channel1", "Vlan99", "Loopback0", "GigabitEthernet1/0/2.200"} {
		ifaceNamed(t, n, want)
	}

	g1 := ifaceNamed(t, n, "GigabitEthernet1/0/1")
	if g1.Type != "1000base-t" || g1.MTU == nil || *g1.MTU != 1500 || g1.SpeedKbps == nil || *g1.SpeedKbps != 1_000_000 ||
		g1.OperStatus != "up" || g1.Enabled == nil || !*g1.Enabled || g1.Mode != "access" || g1.UntaggedVLAN != 10 {
		t.Errorf("access port projection wrong: %+v", g1)
	}
	if got := ifaceNamed(t, n, "GigabitEthernet1/0/47"); got.Enabled == nil || *got.Enabled || got.LAG != "Port-channel1" {
		t.Errorf("shut LAG member: %+v", got)
	}
	trunk := ifaceNamed(t, n, "GigabitEthernet1/0/24")
	if trunk.Mode != "tagged" || trunk.UntaggedVLAN != 1 || !equalInts(trunk.TaggedVLANs, []int{10, 20, 99}) {
		t.Errorf("trunk port: %+v", trunk)
	}
	if po := ifaceNamed(t, n, "Port-channel1"); po.Type != "lag" || po.Mode != "tagged" {
		t.Errorf("LAG: %+v", po)
	}
	if sub := ifaceNamed(t, n, "GigabitEthernet1/0/2.200"); sub.Parent != "GigabitEthernet1/0/2" || sub.Type != "virtual" || sub.UntaggedVLAN != 200 {
		t.Errorf("sub-interface: %+v", sub)
	}
	if lo := ifaceNamed(t, n, "Loopback0"); strings.Join(addrStrings(lo), ",") != "10.255.0.2/32 static" {
		t.Errorf("loopback address (prefix from ipAddrTable's netmask): %v", addrStrings(lo))
	}
	if v10 := ifaceNamed(t, n, "Vlan10"); strings.Join(addrStrings(v10), ",") != "10.0.10.1/24 static,2001:db8:10::1/64 static" {
		t.Errorf("SVI addresses (link-local skipped): %v", addrStrings(v10))
	}
	if dhcp := ifaceNamed(t, n, "GigabitEthernet1/0/46"); strings.Join(addrStrings(dhcp), ",") != "172.16.46.9/24 dynamic" {
		t.Errorf("leased routed port: %v", addrStrings(dhcp))
	}

	var vids []int
	for _, v := range n.VLANs {
		vids = append(vids, v.VID)
	}
	if !equalInts(vids, []int{1, 10, 20, 99, 200}) {
		t.Errorf("VLANs: %v", vids)
	}
	if len(n.ARP) != 3 {
		t.Errorf("ARP evidence: want the 3 complete foreign entries, got %+v", n.ARP)
	}
}

func TestSNMPNetwork_LinuxNetSNMP(t *testing.T) {
	n := snmpNetworkOf(t, snmpfake.LinuxNetSNMP()).Network
	if n.Vendor != "linux" {
		t.Errorf("vendor family = %q, want linux (Net-SNMP enterprise 8072)", n.Vendor)
	}
	eth0 := ifaceNamed(t, n, "eth0")
	if eth0.MAC != "3c:ec:ef:11:22:33" || eth0.Type != "1000base-t" {
		t.Errorf("eth0: %+v", eth0)
	}
	// 127.0.0.1 and fe80:: are not on any interface; v6 length is unknown here.
	if got := strings.Join(addrStrings(eth0), ","); got != "198.51.100.24/24 dynamic,2001:db8:aa::24 static" {
		t.Errorf("eth0 addresses: %v", got)
	}
	if lo := ifaceNamed(t, n, "lo"); len(lo.Addresses) != 0 || lo.Type != "virtual" {
		t.Errorf("loopback address was kept or type wrong: %+v", lo)
	}
	vl := ifaceNamed(t, n, "eth0.100")
	if vl.Parent != "eth0" || vl.UntaggedVLAN != 100 || vl.Mode != "access" || vl.Type != "virtual" {
		t.Errorf("VLAN sub-interface: %+v", vl)
	}
	// A container bridge's address (172.17.0.1 is on every Docker host) never
	// identifies the host.
	if a := ifaceNamed(t, n, "docker0").Addresses; len(a) != 0 {
		t.Errorf("docker0's address was projected: %+v", a)
	}
	// Locally administered MACs (bridge, veth) never identify the host.
	if ifaceNamed(t, n, "docker0").MAC != "" || ifaceNamed(t, n, "veth3a9c1d2").MAC != "" {
		t.Error("a locally administered MAC was projected")
	}
}

// An agent with no ipAddressTable still gets its IPv4 addresses, from RFC 1213.
func TestSNMPNetwork_IPAddrTableFallback(t *testing.T) {
	rec := snmpfake.L3Switch48()
	var kept []snmpfake.Value
	for _, v := range rec.MIB {
		if !strings.HasPrefix(v.OID, "1.3.6.1.2.1.4.34.") {
			kept = append(kept, v)
		}
	}
	rec.MIB = kept
	n := snmpNetworkOf(t, rec).Network
	if got := strings.Join(addrStrings(ifaceNamed(t, n, "Vlan99")), ","); got != "10.0.99.2/24" {
		t.Errorf("fallback address = %q", got)
	}
	if len(ifaceNamed(t, n, "Vlan10").Addresses) != 1 {
		t.Errorf("IPv6 has no ipAddrTable: %+v", ifaceNamed(t, n, "Vlan10").Addresses)
	}
}

// The same interface reaches us as ifName `Gi1/0/1` or, when ifXTable is
// absent, as ifDescr `GigabitEthernet1/0/1`. Both are one interface, so a
// re-run after the agent changed spelling does not file a second copy.
//
// Mutation: use the raw name in snmpInterfaceTable instead of ifnames.Canonical.
func TestSNMPNetwork_NameSpellingsFoldToOne(t *testing.T) {
	short := snmpNetworkOf(t, snmpfake.L3Switch48()).Network
	rec := snmpfake.L3Switch48()
	var kept []snmpfake.Value
	for _, v := range rec.MIB {
		if !strings.HasPrefix(v.OID, oidTestIfName+".") {
			kept = append(kept, v)
		}
	}
	rec.MIB = kept
	long := snmpNetworkOf(t, rec).Network
	for i := range short.Interfaces {
		if short.Interfaces[i].Name != long.Interfaces[i].Name {
			t.Errorf("ifName %q vs ifDescr-only %q are two interfaces", short.Interfaces[i].Name, long.Interfaces[i].Name)
		}
	}
}

const oidTestIfName = "1.3.6.1.2.1.31.1.1.1.1"

// Communities and every other secret an agent echoes into a free-text field
// stay out of the projection: only typed fields are carried.
func TestSNMPNetwork_NoSecretsInTheProjection(t *testing.T) {
	for _, rec := range []snmpfake.Recording{snmpfake.L3Switch48(), snmpfake.LinuxNetSNMP()} {
		blob, _ := json.Marshal(snmpNetworkOf(t, rec).Network)
		for _, secret := range []string{snmpfake.SwitchCommunity, snmpfake.SwitchSecret, snmpfake.LinuxCommunity, snmpfake.LinuxSecret} {
			if strings.Contains(string(blob), secret) {
				t.Errorf("%q reached the network observation: %s", secret, blob)
			}
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The community is stripped from every free-text value read off the device
// before it can become os.version or asset metadata.
//
// Mutation: remove the snmpScrubCommunity loop in Interrogate.
func TestSNMPInterrogate_CommunityEchoedInSysDescrIsNotKept(t *testing.T) {
	for _, rec := range []snmpfake.Recording{snmpfake.L3Switch48(), snmpfake.LinuxNetSNMP()} {
		result := snmpNetworkOf(t, rec)
		Sanitize(result)
		blob, _ := json.Marshal(result)
		if strings.Contains(string(blob), rec.Community) {
			t.Errorf("the community string survives in the interrogation result: %s", blob)
		}
	}
}
