package services

// The hop-1 claims, per vendor: what the in-cluster interrogation must write
// for a tenant to get the right answer downstream.
//
// Every Want is the CORRECT behaviour (spec discovery-beyond-the-lab §A).
// A claim with KnownGap still asserts, but asserts TODAY's behaviour (Current)
// and fails when either the gap is fixed (flip it to a hard assertion) or the
// behaviour drifts somewhere else. See pipelinetest.Expectation.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
)

// row returns the one hop-1 row matching protocol and hostname ("" matches
// any), failing the test when there is not exactly one — a claim about a row
// that is not there must not quietly pass.
func hop1Row(t *testing.T, h pipelinetest.Hop1Handoff, protocol, destIP string) pipelinetest.SensorDiscoveryRow {
	t.Helper()
	var found []pipelinetest.SensorDiscoveryRow
	for _, r := range h.SensorDiscoveries {
		if r.Protocol == protocol && (destIP == "" || r.DestIP == destIP) {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want exactly one %s row at %q, found %d", h.Vendor, protocol, destIP, len(found))
	}
	return found[0]
}

// hop1RowByPeer returns the one row of protocol whose vpn_peer_address is peer.
func hop1RowByPeer(t *testing.T, h pipelinetest.Hop1Handoff, protocol, peer string) pipelinetest.SensorDiscoveryRow {
	t.Helper()
	var found []pipelinetest.SensorDiscoveryRow
	for _, r := range h.SensorDiscoveries {
		if r.Protocol == protocol && r.Metadata["vpn_peer_address"] == peer {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want exactly one %s row with peer %q, found %d", h.Vendor, protocol, peer, len(found))
	}
	return found[0]
}

// hop1RowsOnPort returns the rows of a protocol on a port.
func hop1RowsOnPort(h pipelinetest.Hop1Handoff, protocol string, port int) []pipelinetest.SensorDiscoveryRow {
	var found []pipelinetest.SensorDiscoveryRow
	for _, r := range h.SensorDiscoveries {
		if r.Protocol == protocol && fmt.Sprint(r.Port) == fmt.Sprint(port) {
			found = append(found, r)
		}
	}
	return found
}

// hop1RowOnPort returns the one row of a protocol on a port.
func hop1RowOnPort(t *testing.T, h pipelinetest.Hop1Handoff, protocol string, port int) pipelinetest.SensorDiscoveryRow {
	t.Helper()
	found := hop1RowsOnPort(h, protocol, port)
	if len(found) != 1 {
		t.Fatalf("%s: want exactly one %s row on port %d, found %d", h.Vendor, protocol, port, len(found))
	}
	return found[0]
}

// hop1RowNamed returns the one row whose hostname column is name.
func hop1RowNamed(t *testing.T, h pipelinetest.Hop1Handoff, name string) pipelinetest.SensorDiscoveryRow {
	t.Helper()
	var found []pipelinetest.SensorDiscoveryRow
	for _, r := range h.SensorDiscoveries {
		if r.Hostname != nil && *r.Hostname == name {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want exactly one row named %q, found %d", h.Vendor, name, len(found))
	}
	return found[0]
}

func metaValue(r pipelinetest.SensorDiscoveryRow, key string) any { return r.Metadata[key] }

// metaKeyContains reports whether any metadata key contains one of subs.
func metaKeyContains(r pipelinetest.SensorDiscoveryRow, subs ...string) bool {
	for k := range r.Metadata {
		for _, s := range subs {
			if strings.Contains(k, s) {
				return true
			}
		}
	}
	return false
}

func deviceFact(o hop1Observed, key string) any {
	for _, f := range o.Facts {
		if f["asset"] == "device" && f["key"] == key {
			return f["value"]
		}
	}
	return nil
}

func hop1HasFact(o hop1Observed, key string) bool { return deviceFact(o, key) != nil }

func deviceClass(o hop1Observed) any {
	for _, a := range o.Assets {
		if a["asset"] == "device" {
			return a["class_key"]
		}
	}
	return nil
}

// retainedState is the identity-observation state for the peer carrying an
// identifier value (under enforced admission): "linked" when admission let it
// resolve, "unresolved" when it was held back, "" when there is none.
func retainedState(o hop1Observed, value string) (state, reasons string) {
	for _, r := range o.Retained {
		ids, _ := r["identifiers"].([]any)
		for _, raw := range ids {
			id, _ := raw.(map[string]any)
			if id["value"] == value {
				s, _ := r["state"].(string)
				why, _ := r["admission_reasons"].(string)
				return s, why
			}
		}
	}
	return "", ""
}

// peerAssetFor reports whether some asset carries the identifier value.
func peerAssetFor(o hop1Observed, value string) bool {
	for _, a := range o.Assets {
		if label, _ := a["asset"].(string); strings.Contains(label, "="+value+",") || strings.HasSuffix(label, "="+value+"]") {
			return true
		}
	}
	return false
}

func learnedSegmentValues(h pipelinetest.Hop1Handoff) []string {
	out := []string{}
	for _, s := range h.LearnedSegments {
		out = append(out, s.Value)
	}
	return out
}

func segmentProvenance(h pipelinetest.Hop1Handoff, cidr string) map[string]any {
	for _, s := range h.LearnedSegments {
		if s.Value == cidr {
			return map[string]any{
				"source":             s.Metadata["source"],
				"source_device_type": s.Metadata["source_device_type"],
				"source_asset_id":    s.Metadata["source_asset_id"],
				"dhcp":               s.Metadata["dhcp"],
			}
		}
	}
	return nil
}

func warningEndpoints(o hop1Observed) []string {
	out := []string{}
	for _, w := range o.Warnings {
		e, _ := w["endpoint"].(string)
		r, _ := w["reason"].(string)
		out = append(out, e+" "+r)
	}
	return out
}

// vendorPipelineHop1Claims is the table. Adding a vendor without claims fails
// the test (see the caller).
func vendorPipelineHop1Claims(t *testing.T, vendor string, h pipelinetest.Hop1Handoff, off, enforced hop1Observed) []pipelinetest.Expectation {
	t.Helper()
	device := pipelinetest.PlaceholderDeviceAssetID
	appliance := pipelinetest.PlaceholderApplianceIP
	switch vendor {
	case "unifi":
		ipsec := hop1Row(t, h, "IPSec", "192.0.2.1")
		wg := hop1Row(t, h, "WireGuard", "192.0.2.1")
		mgmt := hop1Row(t, h, "TLS", appliance)
		return []pipelinetest.Expectation{
			// P-01/P-02/P-03,: the IKE version is the protocol
			// version, the DH group is the key exchange, and key_size is the
			// group's size rather than the AES length.
			{What: "UniFi IPsec protocol version", Got: metaValue(ipsec, "version"), Want: "IKEv2"},
			{What: "UniFi IPsec key exchange", Got: metaValue(ipsec, "key_exchange_algorithm"), Want: "DH-MODP-2048"},
			{What: "UniFi IPsec offered groups", Got: metaValue(ipsec, "kex_algorithms"), Want: []any{"DH-MODP-2048"}},
			{What: "UniFi IPsec key size is the group's", Got: metaValue(ipsec, "key_size"), Want: 2048},
			{What: "UniFi WireGuard key exchange", Got: metaValue(wg, "key_exchange_algorithm"), Want: "Curve25519"},
			// E-01,: the management TLS handshake negotiated a
			// group (Go's default, the hybrid X25519MLKEM768) and the row names
			// it, where it used to say "ECDHE".
			{What: "UniFi management TLS key exchange is the negotiated group",
				Got: metaValue(mgmt, "key_exchange_algorithm"), Want: "X25519MLKEM768"},
			// W1.9: the support answers reach the row. The fake
			// supports exactly X25519MLKEM768 and X25519 (pipelinetest.
			// ApplianceTLSConfig), so both questions have a known answer:
			// hybrid proven by the main handshake, classical by the
			// X25519-only offer.
			{What: "UniFi management TLS support flags",
				Got:  []any{metaValue(mgmt, "tls_supports_classical_kex"), metaValue(mgmt, "tls_supports_pqc_hybrid_kex"), metaValue(mgmt, "tls_pqc_hybrid_kex_group")},
				Want: []any{true, true, "X25519MLKEM768"}},
			// P-15,: both networks become segments, labelled
			// with the device that taught them.
			{What: "UniFi learned segments", Got: learnedSegmentValues(h), Want: []string{"192.0.2.0/24", "198.51.100.0/24"}},
			{What: "UniFi LAN segment provenance", Got: segmentProvenance(h, "192.0.2.0/24"),
				Want: map[string]any{"source": "interrogation", "source_device_type": "unifi", "source_asset_id": device, "dhcp": "enabled"}},
			{What: "UniFi management plane", Got: []any{deviceFact(off, "mgmt.protocol"), deviceFact(off, "mgmt.plaintext")}, Want: []any{"https", false}},
			{What: "UniFi collection warnings", Got: warningEndpoints(off), Want: []string{}},
			// Enforced admission: the adopted devices resolve by their
			// authoritative serial, the wired client by its port (the
			// behaviour every other vendor is measured against).
			{What: "UniFi adopted switch under enforce", Got: first(retainedState(enforced, "788A204BEE41")), Want: "linked"},
			{What: "UniFi wired client under enforce", Got: first(retainedState(enforced, "4c:6e:0a:87:d4:80")), Want: "linked"},
			// Q1: a neighbour counts as direct only with an address in a known
			// segment. This LLDP neighbour reports a MAC and a name and no
			// address, so it is correctly held.
			{What: "UniFi address-less LLDP neighbour under enforce", Got: first(retainedState(enforced, "core-sw-1.corp.example.test")), Want: "unresolved"},
		}

	case "cisco":
		ssh := hop1Row(t, h, "SSH", appliance)
		isakmp := hop1Row(t, h, "IKE", "")
		// Every VPN row is now on the device (P-07), so the crypto map is
		// told from the two real IPsec SAs by its port: the SAs are
		// NAT-traversed (4500), the crypto map entry is plain IKE (500).
		cryptoMap := hop1RowOnPort(t, h, "IPSec", 500)
		ikev2 := hop1Row(t, h, "IKEv2", "")
		emptyIPsec := 0
		for _, r := range h.SensorDiscoveries {
			if r.Protocol == "IPSec" && metaValue(r, "cipher_suite") == "" && metaValue(r, "kex_algorithms") == nil {
				emptyIPsec++
			}
		}
		return []pipelinetest.Expectation{
			// P-04 (the SSH half) and P-09,: the version comes from
			// the banner, and the banner and host key reach the row.
			{What: "Cisco SSH protocol version comes from the banner (SSH-1.99-Cisco-1.25)",
				Got: metaValue(ssh, "version"), Want: "SSH-1.99"},
			{What: "Cisco SSH row carries the banner or host-key type",
				Got: metaKeyContains(ssh, "banner", "host_key"), Want: true},
			{What: "Cisco SSH row carries the negotiated key exchange",
				Got: metaValue(ssh, "key_exchange_algorithm") != nil, Want: true,
				KnownGap: "K-01 / W4.1", Current: false},
			// P-07 (placement) and P-11,: an address that is the
			// tunnel's peer is not the row's; the peer is kept as
			// vpn_peer_address and the row lands on the device.
			{What: "Cisco ISAKMP SA lands on the device, not the remote peer",
				Got: isakmp.DestIP, Want: appliance},
			{What: "Cisco ISAKMP SA port", Got: isakmp.Port, Want: 500},
			{What: "Cisco ISAKMP SA IKE version comes from the command", Got: metaValue(isakmp, "version"), Want: "IKEv1"},
			{What: "Cisco IKEv2 SA port", Got: ikev2.Port, Want: 500},
			{What: "Cisco crypto map lands on the device, not the remote peer",
				Got: cryptoMap.DestIP, Want: appliance},
			{What: "Cisco crypto map IKE version is unknown, not assumed IKEv2",
				Got: metaValue(cryptoMap, "version"), Want: ""},
			{What: "Cisco crypto map transform set (IOS `Transform sets={` block) is read",
				Got: []any{metaValue(cryptoMap, "cipher_suite"), metaValue(cryptoMap, "hash_algorithm")}, Want: []any{"AES-256-CBC", "SHA256"}},
			// P-03,: the crypto map's PFS group is an offer,
			// never the key exchange.
			{What: "Cisco crypto map PFS group is offered, not the key exchange",
				Got:  []any{metaValue(cryptoMap, "kex_algorithms"), metaValue(cryptoMap, "key_exchange_algorithm")},
				Want: []any{[]any{"DH-MODP-2048"}, nil}},
			{What: "Cisco IKEv2 SA key exchange from `DH Grp:14`", Got: metaValue(ikev2, "key_exchange_algorithm"), Want: "DH-MODP-2048"},
			{What: "Cisco IKEv2 SA encryption (`Encr: AES-CBC, keysize: 256`) is read",
				Got: metaValue(ikev2, "cipher_suite"), Want: "AES-256-CBC"},
			{What: "Cisco rows parsed from real `show crypto ipsec sa` that carry no crypto at all",
				Got: emptyIPsec, Want: 0},
			{What: "Cisco real IPsec SAs are NAT-traversed: UDP 4500 on the device",
				Got: len(hop1RowsOnPort(h, "IPSec", 4500)), Want: 2},
			{What: "Cisco VLAN interfaces become segments",
				Got: len(h.LearnedSegments) > 0, Want: true,
				KnownGap: "K-02 / W4.2", Current: false},
			{What: "Cisco identity facts", Got: []any{deviceFact(off, "hw.vendor"), deviceFact(off, "os.name")}, Want: []any{"Cisco Systems", "IOS-XE"}},
			{What: "Cisco management plane", Got: []any{deviceFact(off, "mgmt.protocol"), deviceFact(off, "mgmt.plaintext")}, Want: []any{"ssh", false}},
			{What: "Cisco collection warnings", Got: warningEndpoints(off), Want: []string{}},
			// Q1: CDP/LLDP neighbours whose address is in a registered segment
			// are directly observed and admitted under enforce.
			{What: "Cisco CDP neighbour in a known segment under enforce",
				Got: first(retainedState(enforced, "94:f1:28:79:55:55")), Want: "linked",
				KnownGap: "P-16 / W4.7", Current: "unresolved"},
			{What: "Cisco LLDP neighbour in a known segment under enforce",
				Got: first(retainedState(enforced, "desktop-switch")), Want: "linked",
				KnownGap: "P-16 / W4.7", Current: "unresolved"},
		}

	case "fortinet":
		ipsec := hop1Row(t, h, "IPSec", "")
		sslvpn := hop1Row(t, h, "SSL VPN", "")
		sha1Visible := metaValue(ipsec, "hash_algorithm") == "SHA1"
		certRows := 0
		for _, r := range h.SensorDiscoveries {
			if r.Metadata["certificates"] != nil {
				certRows++
			}
		}
		return []pipelinetest.Expectation{
			{What: "FortiGate IPsec key exchange (dhgrp \"14 5\")", Got: metaValue(ipsec, "key_exchange_algorithm"), Want: "DH-MODP-2048"},
			{What: "FortiGate IPsec offered groups", Got: metaValue(ipsec, "kex_algorithms"), Want: []any{"DH-MODP-2048", "DH-MODP-1536"}},
			{What: "FortiGate IPsec protocol version from ike-version \"2\"",
				Got: metaValue(ipsec, "version"), Want: "IKEv2",
				KnownGap: "NEW-02 (FortiOS ike-version unread) / W4.4", Current: ""},
			{What: "FortiGate proposal list `aes256-sha256 aes128-sha1` does not hide SHA-1",
				Got: sha1Visible, Want: true,
				KnownGap: "P-14 / W2.5", Current: false},
			{What: "FortiGate SSL-VPN minimum version from ssl-min-proto-ver",
				Got: metaValue(sslvpn, "version"), Want: "TLS 1.2",
				KnownGap: "C-04 / W3.3", Current: ""},
			{What: "FortiGate local certificate reaches a row", Got: certRows > 0, Want: true,
				KnownGap: "P-13 / W2.4", Current: false},
			{What: "FortiGate learned segments", Got: learnedSegmentValues(h), Want: []string{"198.51.100.0/24"}},
			{What: "FortiGate segment provenance", Got: segmentProvenance(h, "198.51.100.0/24"),
				Want: map[string]any{"source": "interrogation", "source_device_type": "fortinet", "source_asset_id": device, "dhcp": "unknown"}},
			{What: "FortiGate device class", Got: deviceClass(off), Want: "firewall"},
			{What: "FortiGate collection warnings", Got: warningEndpoints(off), Want: []string{}},
		}

	case "paloalto":
		decrypt := hop1RowNamed(t, h, "ssl-fwd-proxy-default")
		return []pipelinetest.Expectation{
			{What: "PAN-OS decryption profile carries its forward-trust CA certificate",
				Got: decrypt.Metadata["certificates"] != nil, Want: true,
				KnownGap: "P-13 / W2.4", Current: false},
			{What: "PAN-OS data-plane interfaces become segments",
				Got: len(h.LearnedSegments) > 0, Want: true,
				KnownGap: "K-02 / W4.2", Current: false},
			{What: "PAN-OS device class", Got: deviceClass(off), Want: "firewall"},
			{What: "PAN-OS identity", Got: []any{deviceFact(off, "hw.vendor"), deviceFact(off, "os.name")}, Want: []any{"Palo Alto Networks", "PAN-OS"}},
			{What: "PAN-OS collection warnings", Got: warningEndpoints(off), Want: []string{}},
			{What: "PAN-OS LLDP neighbour in a known segment under enforce",
				Got: first(retainedState(enforced, "00:1b:17:00:00:01")), Want: "linked",
				KnownGap: "P-16 / W4.7", Current: "unresolved"},
		}

	case "f5":
		secure := hop1RowNamed(t, h, "vs_web_443")
		hardened := hop1RowNamed(t, h, "vs_legacy_443")
		excluded := false
		ciphers, _ := metaValue(hardened, "supported_ciphers").([]any)
		for _, c := range ciphers {
			if s, _ := c.(string); strings.HasPrefix(s, "!") {
				excluded = true
			}
		}
		var dataSource any
		if certs, ok := secure.Metadata["certificates"].([]any); ok && len(certs) > 0 {
			dataSource = certs[0].(map[string]any)["data_source"]
		}
		return []pipelinetest.Expectation{
			{What: "F5 profile with no tlsVersion: the version is not fabricated (the writer spells unknown \"\")",
				Got: metaValue(hardened, "version"), Want: "",
				KnownGap: "P-04 / W1.2", Current: "TLS 1.2"},
			// P-05,: the OpenSSL cipher string is parsed, so
			// what it excludes is never read as what it enables.
			{What: "F5 `!MD5` exclusion is not read as the hash",
				Got: metaValue(hardened, "hash_algorithm") == "MD5", Want: false},
			{What: "F5 cipher-string exclusions are not listed as supported ciphers",
				Got: excluded, Want: false},
			{What: "F5 tlsVersion \"1.2\" in the catalogue's spelling",
				Got: metaValue(secure, "version"), Want: "TLS 1.2",
				KnownGap: "P-14 / W2.5", Current: "1.2"},
			{What: "F5 certificate read from config says so",
				Got: dataSource, Want: "config",
				KnownGap: "P-13 / W2.4", Current: nil},
			{What: "F5 uptime", Got: hop1HasFact(off, "net.uptime_seconds"), Want: true,
				KnownGap: "K-08 / W4.6", Current: false},
			{What: "F5 learned segments", Got: learnedSegmentValues(h), Want: []string{"192.0.2.0/24", "198.51.100.0/24"}},
			{What: "F5 segment provenance", Got: segmentProvenance(h, "198.51.100.0/24"),
				Want: map[string]any{"source": "interrogation", "source_device_type": "f5", "source_asset_id": device, "dhcp": "unknown"}},
			// P-17,: the refused endpoint is on the job.
			{What: "F5 collection warnings", Got: warningEndpoints(off), Want: []string{"/mgmt/tm/ltm/profile/server-ssl permission_denied"}},
			{What: "F5 device class", Got: deviceClass(off), Want: "load_balancer"},
		}

	case "snmp":
		row := hop1Row(t, h, "SNMP", "")
		return []pipelinetest.Expectation{
			{What: "SNMP management plane is plaintext v2c",
				Got: []any{deviceFact(off, "mgmt.protocol"), deviceFact(off, "mgmt.plaintext")}, Want: []any{"snmpv2c", true}},
			{What: "SNMP row is on the SNMP port",
				Got: row.Port, Want: 161,
				KnownGap: "NEW-01 (unset port defaults to 443 in writeSensorDiscovery) / unassigned", Current: 443},
			{What: "SNMP device class from its sysObjectID class hint",
				Got: deviceClass(off), Want: "network_device",
				KnownGap: "P-12 / W2.3", Current: "unknown_host"},
			{What: "SNMP ARP entry becomes a peer (decided Q2)",
				Got: peerAssetFor(off, "192.0.2.1"), Want: true,
				KnownGap: "K-04 / W4.8", Current: false},
			{What: "SNMP identity", Got: []any{deviceFact(off, "hw.vendor"), deviceFact(off, "hw.model"), deviceFact(off, "hw.serial")},
				Want: []any{"Cisco Systems", "C9300-48P", "FOC2432L0AB"}},
			{What: "SNMP collection warnings", Got: warningEndpoints(off), Want: []string{}},
			// Q1: an address-less LLDP neighbour stays held.
			{What: "SNMP address-less LLDP neighbour under enforce",
				Got: first(retainedState(enforced, "00:1b:17:00:00:aa")), Want: "unresolved"},
		}
	}
	return nil
}

func first(a, _ string) string { return a }
