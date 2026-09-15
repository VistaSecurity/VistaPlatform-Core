package deviceinterrogation

import (
	"context"
	"net"
	"testing"
)

// An IP literal must never become a `hostname` or an `fqdn` identifier.
//
// Digits and dots are legal in a DNS name, so "198.51.100.20" normalises as
// one. A peer named after its own address — an F5 pool member almost always is,
// and a printer or an IP phone commonly advertises one as its LLDP system name
// — would then carry THREE identifiers for one address, two of them names it
// does not have. The identification engine merges on identifiers, so the moment
// something really is called that, two unrelated assets become one.
//
// [addHostIdentifiers] is the guard, and this is the test that it exists. Every
// collector that can attach a name to a peer is driven through its REAL path
// here, because the guard was applied to five of the six and nothing said so:
// snmpLLDPObservations kept its own inline AddIdentifier(fqdn)/(hostname) pair.
//
// To mutation-test: delete the canonicalIP guard from addHostIdentifiers and
// every subtest below fails. Delete only the canonicalMAC guard and
// TestAddHostIdentifiers_RejectsAMACWearingANameSClothing fails.
func TestAddHostIdentifiers_AnIPLiteralNeverBecomesAName(t *testing.T) {
	const literal = "198.51.100.20"

	// assertAddressOnly is both polarities at once: the name kinds must be
	// absent, AND the address must still be there. A guard that drops the peer
	// entirely has not fixed the bug, it has lost the edge.
	assertAddressOnly := func(t *testing.T, collector string, peer PeerRef) {
		t.Helper()
		if got := peer.Identifier(IdentifierFQDN); got != "" {
			t.Errorf("%s: an IP literal was offered as an fqdn (%q); identifiers: %+v", collector, got, peer.Identifiers)
		}
		if got := peer.Identifier(IdentifierHostname); got != "" {
			t.Errorf("%s: an IP literal was offered as a hostname (%q); identifiers: %+v", collector, got, peer.Identifiers)
		}
		if got := peer.Identifier(IdentifierIPAddress); got != literal {
			t.Errorf("%s: the address identity was lost: %+v", collector, peer.Identifiers)
		}
	}

	t.Run("cisco cdp", func(t *testing.T) {
		_, edges := ciscoParseCDPNeighbors(`-------------------------
Device ID: ` + literal + `
Entry address(es):
  IP address: ` + literal + `
Platform: cisco WS-C3750X-48P,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24
`)
		if len(edges) != 1 {
			t.Fatalf("expected one CDP edge, got %d", len(edges))
		}
		assertAddressOnly(t, "cisco cdp", edges[0].Peer)
	})

	t.Run("cisco lldp", func(t *testing.T) {
		_, edges := ciscoParseLLDPNeighbors(`------------------------------------------------
Chassis id: ` + literal + `
Port id: Gi0/0/1
System Name: ` + literal + `
Management Addresses:
    IP: ` + literal + `
`)
		if len(edges) != 1 {
			t.Fatalf("expected one LLDP edge, got %d", len(edges))
		}
		assertAddressOnly(t, "cisco lldp", edges[0].Peer)
	})

	t.Run("palo alto lldp", func(t *testing.T) {
		_, edges, err := panLLDPObservations(`<response status="success"><result><entry>
  <local-interface>ethernet1/1</local-interface>
  <lldp-neighbors><entry>
    <chassis-id>` + literal + `</chassis-id>
    <port-id>Gi0/0/1</port-id>
    <system-name>` + literal + `</system-name>
    <management-address>` + literal + `</management-address>
  </entry></lldp-neighbors>
</entry></result></response>`)
		if err != nil {
			t.Fatalf("panLLDPObservations: %v", err)
		}
		if len(edges) != 1 {
			t.Fatalf("expected one LLDP edge, got %d", len(edges))
		}
		assertAddressOnly(t, "palo alto lldp", edges[0].Peer)
	})

	t.Run("unifi lldp", func(t *testing.T) {
		edges := unifiLLDPEdges(PeerRef{}, map[string]interface{}{
			"lldp_table": []interface{}{map[string]interface{}{
				"chassis_id":      "00:1b:17:00:00:01",
				"system_name":     literal,
				"port_id":         "Gi1/0/24",
				"local_port_name": "Uplink",
			}},
		})
		if len(edges) != 1 {
			t.Fatalf("expected one LLDP edge, got %d", len(edges))
		}
		peer := edges[0].Peer
		if got := peer.Identifier(IdentifierFQDN); got != "" {
			t.Errorf("unifi lldp: an IP literal was offered as an fqdn (%q)", got)
		}
		if got := peer.Identifier(IdentifierHostname); got != "" {
			t.Errorf("unifi lldp: an IP literal was offered as a hostname (%q)", got)
		}
		// UniFi's lldp_table states a chassis MAC rather than an address, so
		// the MAC is what has to survive here.
		if got := peer.Identifier(IdentifierMACAddress); got != "00:1b:17:00:00:01" {
			t.Errorf("unifi lldp: the chassis identity was lost: %+v", peer.Identifiers)
		}
	})

	t.Run("f5 pool member", func(t *testing.T) {
		peer, port := f5PoolMemberPeer(f5PoolMember{
			Name:     literal + ":8080",
			FullPath: "/Common/" + literal + ":8080",
			Address:  literal,
			State:    "up",
		})
		if port != 8080 {
			t.Errorf("member port = %d, want 8080", port)
		}
		assertAddressOnly(t, "f5 pool member", peer)
	})

	t.Run("snmp lldp", func(t *testing.T) {
		mib := append(snmpTestMIB(), snmpTestOctet(snmpOIDLLDPRemSysName+".0.1.1", literal))
		addr := startSNMPTestAgent(t, mib)
		host, portStr, _ := net.SplitHostPort(addr)
		port := 0
		for _, c := range portStr {
			port = port*10 + int(c-'0')
		}

		registry := NewRegistry()
		interrogator, err := registry.Get("generic_snmp")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		result, err := interrogator.Interrogate(
			context.Background(),
			DeviceInfo{DeviceType: "generic_snmp", IPAddress: host, Port: port},
			Credentials{Custom: map[string]interface{}{"community": "public"}},
		)
		if err != nil {
			t.Fatalf("Interrogate: %v", err)
		}
		edges := relationshipsOfType(result, relTypeConnectsTo)
		if len(edges) != 1 {
			t.Fatalf("expected one LLDP edge, got %d: %+v", len(edges), edges)
		}
		peer := edges[0].Peer
		if got := peer.Identifier(IdentifierFQDN); got != "" {
			t.Errorf("snmp lldp: an IP literal was offered as an fqdn (%q); identifiers: %+v", got, peer.Identifiers)
		}
		if got := peer.Identifier(IdentifierHostname); got != "" {
			t.Errorf("snmp lldp: an IP literal was offered as a hostname (%q); identifiers: %+v", got, peer.Identifiers)
		}
		// The neighbour is still identified — by its chassis MAC, and by the
		// address it advertised as a name, under the kind that address is.
		if got := peer.Identifier(IdentifierMACAddress); got != "00:1b:17:00:00:aa" {
			t.Errorf("snmp lldp: the chassis identity was lost: %+v", peer.Identifiers)
		}
		if got := peer.Identifier(IdentifierIPAddress); got != literal {
			t.Errorf("snmp lldp: the address identity was lost: %+v", peer.Identifiers)
		}
	})
}

// Inverse polarity: a real name must still become both kinds, or the guard has
// destroyed the identity resolution it was written to protect.
func TestAddHostIdentifiers_KeepsARealName(t *testing.T) {
	peer := PeerRef{}
	addHostIdentifiers(&peer, "core-sw-1.example.net")
	if got := peer.Identifier(IdentifierFQDN); got != "core-sw-1.example.net" {
		t.Errorf("fqdn = %q, want the advertised name", got)
	}
	if got := peer.Identifier(IdentifierHostname); got != "core-sw-1.example.net" {
		t.Errorf("hostname = %q, want the advertised name", got)
	}

	// A single-label name is not an FQDN, and canonicalDNSName is the arbiter
	// of that rather than this function.
	short := PeerRef{}
	addHostIdentifiers(&short, "core-sw-1")
	if got := short.Identifier(IdentifierFQDN); got != "" {
		t.Errorf("a single-label name was stored as an fqdn: %q", got)
	}
	if got := short.Identifier(IdentifierHostname); got != "core-sw-1" {
		t.Errorf("hostname = %q, want the short name", got)
	}
}

// A MAC is an identity too, and it is not a name either. LLDP's Chassis id is a
// MAC on most implementations, and CDP's Device ID is one on several
// third-party stacks.
func TestAddHostIdentifiers_RejectsAMACWearingANameSClothing(t *testing.T) {
	for _, form := range []string{"00:1b:17:00:00:aa", "00-1B-17-00-00-AA", "001b.1700.00aa"} {
		peer := PeerRef{}
		addHostIdentifiers(&peer, form)
		if got := peer.Identifier(IdentifierHostname); got != "" {
			t.Errorf("addHostIdentifiers(%q) stored a MAC as a hostname: %q", form, got)
		}
		if got := peer.Identifier(IdentifierFQDN); got != "" {
			t.Errorf("addHostIdentifiers(%q) stored a MAC as an fqdn: %q", form, got)
		}
	}
}
