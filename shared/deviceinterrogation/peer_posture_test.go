package deviceinterrogation

// What a neighbour advertises about ITSELF, and how much of it we keep.
//
// A peer reference used to carry identifiers and a display name. Its class was
// therefore argued from an OUI alone, and an OUI names a manufacturer — every
// one of which makes switches, access points and desk phones — so almost every
// neighbour came back `unknown_host` while the interrogators were parsing, and
// discarding, the device's own statement of what it is.
//
// The fields added for that are deliberately PROJECTIONS and not copies. An
// LLDP `System Description` is free text an operator can put anything into
// (this package's own PAN-OS fixture has an SNMP community string in one), so
// the peer carries the product segment and the version token, never the banner.
// These tests are both halves of that: the posture survives, the rest does not.

import (
	"strings"
	"testing"
)

func TestAdvertisedProduct_KeepsTheProductAndDropsTheRest(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "the leading segment is the product",
			in:   "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10, RELEASE SOFTWARE (fc1)",
			want: "Cisco IOS Software",
		},
		{
			name: "a configured value after the comma never arrives",
			in:   "Cisco IOS Software, snmp community s3cr3t-community",
			want: "Cisco IOS Software",
		},
		{
			name: "a CDP platform line is already a product",
			in:   "cisco WS-C3750X-48P",
			want: "cisco WS-C3750X-48P",
		},
		{
			name: "only the first LINE, because a description is a banner",
			in:   "Juniper Networks EX2300\n*** UNAUTHORISED ACCESS PROHIBITED ***\nkey: s3cr3t",
			want: "Juniper Networks EX2300",
		},
		{
			name: "nothing advertised is nothing kept",
			in:   "   ",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := advertisedProduct(tc.in); got != tc.want {
				t.Errorf("advertisedProduct(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// The comma cut is not a security rule. An operator who typed the credential
	// FIRST would have had it kept and the product thrown away, and nothing
	// downstream could catch it: `Sanitize` is name-based and the field is
	// called `platform`. A segment that names a credential is not a product.
	t.Run("a segment that names a credential is dropped whole", func(t *testing.T) {
		for _, in := range []string{
			"snmp community MUST-NOT-BE-COLLECTED, Cisco IOS Software",
			"password hunter2 Cisco IOS",
			"private_key AAAA Cisco",
			"Bearer token abc123",
		} {
			if got := advertisedProduct(in); got != "" {
				t.Errorf("advertisedProduct(%q) = %q, want \"\" — the segment names a "+
					"credential, so none of it is a product", in, got)
			}
		}
	})

	t.Run("bounded", func(t *testing.T) {
		got := advertisedProduct(strings.Repeat("A", 4096))
		if len(got) > maxAdvertisementLength {
			t.Errorf("advertisedProduct kept %d bytes; the bound exists so a device "+
				"cannot decide how much of our database it occupies", len(got))
		}
	})
}

func TestAdvertisedVersion_IsATokenNeverABanner(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "the token after the word Version",
			in:   "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10, RELEASE SOFTWARE (fc1)",
			want: "15.2(4)E10",
		},
		{
			name: "the colon form",
			in:   "Version: 11.1.4-h7",
			want: "11.1.4-h7",
		},
		{
			name: "a banner with no version token yields NOTHING, not the line",
			in:   "*** Property of Example Corp. Password is hunter2 ***",
			want: "",
		},
		{
			name: "the word alone, with nothing after it",
			in:   "Version",
			want: "",
		},
		{
			name: "only the first line is read",
			in:   "Compiled by somebody\nVersion 15.2",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := advertisedVersion(tc.in); got != tc.want {
				t.Errorf("advertisedVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The three renderings of one bitmask normalise to one vocabulary.
//
// IOS prints the legend letters, PAN-OS prints the words, a controller returns
// a hyphenated array. A rule fires on the decoder's spelling, so a switch has
// to classify the same however we happened to see it.
func TestLLDPCapabilityNames_OneVocabularyFromThreeRenderings(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string
	}{
		{"IOS letters", "B,R", []string{"bridge", "router"}},
		{"IOS letters with spaces", "B, R, W", []string{"bridge", "router", "wlan_access_point"}},
		{"PAN-OS words", "Bridge, Router", []string{"bridge", "router"}},
		{"controller hyphens", "bridge,wlan-access-point", []string{"bridge", "wlan_access_point"}},
		{"duplicates collapse", "B,Bridge,b", []string{"bridge"}},
		// The half that matters as much: a token the vocabulary does not know
		// is DROPPED. Passing it through lower-cased would put a capability
		// name into the engine that no rule can ever match, which reads as
		// evidence and is not.
		{"unknown tokens are dropped", "B,Quux,ZZ", []string{"bridge"}},
		{"nothing advertised", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lldpCapabilityNames(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("lldpCapabilityNames(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("lldpCapabilityNames(%q) = %v, want %v", tc.in, got, tc.want)
					return
				}
			}
		})
	}
}

// Cisco CDP: the platform, the version token and the capabilities reach the
// peer; the banner does not.
func TestCiscoCDP_PeerCarriesPosture(t *testing.T) {
	output := `-------------------------
Device ID: core-sw-1.example.net
Entry address(es):
  IP address: 198.51.100.1
Platform: cisco WS-C3750X-48P,  Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24
Holdtime : 143 sec

Version :
Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10, ` + poison + `

advertisement version: 2
`
	_, edges := ciscoParseCDPNeighbors(output)
	if len(edges) != 1 {
		t.Fatalf("expected one edge, got %d", len(edges))
	}
	peer := edges[0].Peer
	if peer.Platform != "cisco WS-C3750X-48P" {
		t.Errorf("peer.Platform = %q, want the advertised platform", peer.Platform)
	}
	if peer.SoftwareVersion != "15.2(4)E10" {
		t.Errorf("peer.SoftwareVersion = %q, want the version TOKEN — a banner is not a version",
			peer.SoftwareVersion)
	}
	wantCaps := map[string]bool{"router": true, "switch": true, "igmp_capable": true}
	if len(peer.CDPCapabilities) != len(wantCaps) {
		t.Errorf("peer.CDPCapabilities = %v, want %v", peer.CDPCapabilities, wantCaps)
	}
	for _, c := range peer.CDPCapabilities {
		if !wantCaps[c] {
			t.Errorf("unexpected capability %q in %v", c, peer.CDPCapabilities)
		}
	}
	assertNoPoison(t, "cisco cdp peer", edges)
}

// Cisco LLDP: the product segment and the ENABLED capabilities reach the peer;
// the rest of the system description does not.
func TestCiscoLLDP_PeerCarriesPosture(t *testing.T) {
	output := `------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 00:1b:17:00:00:02
Port id: Gi0/1
Port Description: uplink
System Name: edge-sw-2

System Description:
Juniper Networks EX2300, JUNOS 21.4R3, ` + poison + `

Time remaining: 97 seconds
System Capabilities: B,R
Enabled Capabilities: B
Management Addresses:
    IP: 198.51.100.2
`
	_, edges := ciscoParseLLDPNeighbors(output)
	if len(edges) != 1 {
		t.Fatalf("expected one edge, got %d", len(edges))
	}
	peer := edges[0].Peer
	if peer.Platform != "Juniper Networks EX2300" {
		t.Errorf("peer.Platform = %q, want the product segment of the system description",
			peer.Platform)
	}
	// ENABLED wins over merely capable: a switch with routing compiled in but
	// not configured is a switch, and classifying it as a router because the
	// silicon could would be a fact nobody observed.
	if len(peer.LLDPCapabilities) != 1 || peer.LLDPCapabilities[0] != "bridge" {
		t.Errorf("peer.LLDPCapabilities = %v, want just [bridge] — the ENABLED line, not the "+
			"System Capabilities line", peer.LLDPCapabilities)
	}
	assertNoPoison(t, "cisco lldp peer", edges)
}

// UniFi: the controller's LLDP table, projected the same way.
func TestUnifiLLDP_PeerCarriesPosture(t *testing.T) {
	device := map[string]interface{}{
		"lldp_table": []interface{}{
			map[string]interface{}{
				"chassis_id":    "00:1b:17:00:00:03",
				"system_name":   "floor2-sw",
				"port_id":       "Gi0/3",
				"chassis_descr": "Cisco IOS Software, Version 15.2(7)E3, " + poison,
				"capabilities":  []interface{}{"bridge", "wlan-access-point", "not-a-capability"},
				// Not on the allowlist, and must not arrive by any other route.
				"management_password": poison,
			},
		},
	}
	edges := unifiLLDPEdges(PeerRef{}, device)
	if len(edges) != 1 {
		t.Fatalf("expected one edge, got %d", len(edges))
	}
	peer := edges[0].Peer
	if peer.Platform != "Cisco IOS Software" {
		t.Errorf("peer.Platform = %q, want the product segment", peer.Platform)
	}
	if peer.SoftwareVersion != "15.2(7)E3" {
		t.Errorf("peer.SoftwareVersion = %q, want 15.2(7)E3", peer.SoftwareVersion)
	}
	if len(peer.LLDPCapabilities) != 2 {
		t.Errorf("peer.LLDPCapabilities = %v, want bridge + wlan_access_point and nothing else",
			peer.LLDPCapabilities)
	}
	assertNoPoison(t, "unifi lldp peer", edges)
}

// The backstop still runs over the new fields.
//
// Name-based redaction cannot help on `platform` or `software_version` — the
// names are innocent and the VALUES come from outside — so the defence is the
// projection above. What Sanitize must still do is leave the projected posture
// alone: a redactor that masked a product string would make the classification
// evidence useless while proving nothing.
func TestSanitize_LeavesProjectedPeerPostureAlone(t *testing.T) {
	result := &InterrogateResult{
		Relationships: []RelationshipObservation{{
			Type: relTypeConnectsTo,
			Peer: PeerRef{
				DisplayName:      "core-sw-1",
				Platform:         "cisco WS-C3750X-48P",
				SoftwareVersion:  "15.2(4)E10",
				LLDPCapabilities: []string{"bridge", "router"},
				CDPCapabilities:  []string{"switch"},
			},
		}},
	}
	Sanitize(result)
	peer := result.Relationships[0].Peer
	if peer.Platform != "cisco WS-C3750X-48P" || peer.SoftwareVersion != "15.2(4)E10" {
		t.Errorf("Sanitize redacted posture: %+v", peer)
	}
	if len(peer.LLDPCapabilities) != 2 || len(peer.CDPCapabilities) != 1 {
		t.Errorf("Sanitize dropped capabilities: %+v", peer)
	}
}

// And a PEM block that somehow reached a peer's free-text fields is masked, the
// way it already is for the display name.
func TestSanitize_MasksAPEMBlockInPeerPosture(t *testing.T) {
	const key = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----"
	result := &InterrogateResult{
		Relationships: []RelationshipObservation{{
			Type: relTypeConnectsTo,
			Peer: PeerRef{Platform: key, SoftwareVersion: key},
		}},
	}
	Sanitize(result)
	peer := result.Relationships[0].Peer
	if strings.Contains(peer.Platform, "BEGIN PRIVATE KEY") ||
		strings.Contains(peer.SoftwareVersion, "BEGIN PRIVATE KEY") {
		t.Errorf("a PEM block survived in a peer's posture fields: %+v", peer)
	}
}
