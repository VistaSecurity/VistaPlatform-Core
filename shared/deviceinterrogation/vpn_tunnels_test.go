package deviceinterrogation

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const plantedPSK = "ENC Zm9ydGlnYXRlLXNlY3JldC1wc2stZG8tbm90LXN0b3Jl"

// The FortiOS phase-1 object carries the tunnel's pre-shared key. The tunnel
// projection keeps THAT one is configured and nothing of its value.
//
// Mutation: give fortinetPhase1 a `PSK string json:"psksecret"` and copy it
// into the tunnel's name — red.
func TestFortinetTunnels_ProjectProposalsAndNeverThePSK(t *testing.T) {
	phase1 := []map[string]interface{}{{
		"name": "to-branch", "interface": "wan1", "ike-version": "2",
		"proposal": "aes256-sha256 3des-sha1", "dhgrp": "14 5", "keylife": 86400,
		"remote-gw": "198.51.100.7", "local-gw": "0.0.0.0", "mode": "main",
		"authmethod": "psk", "psksecret": plantedPSK,
	}}
	phase2 := []map[string]interface{}{{
		"name": "to-branch-p2", "phase1name": "to-branch", "proposal": "aes128gcm",
		"pfs": "enable", "dhgrp": "19", "keylifeseconds": 3600, "keylifekbs": 5120,
	}}
	result := &InterrogateResult{collector: fortinetCollector}
	(&fortinetClient{}).addFortinetTunnels(result, phase1, phase2)
	if result.Network == nil || len(result.Network.Tunnels) != 1 {
		t.Fatalf("network = %+v", result.Network)
	}
	got := result.Network.Tunnels[0]
	want := ObservedTunnel{
		Name: "to-branch", Encapsulation: "ipsec-tunnel", LocalInterface: "to-branch", LocalIP: "0.0.0.0", PeerIP: "198.51.100.7",
		IKEVersion: 2, IKEMode: "main", AuthenticationMethod: "preshared-keys", PresharedKeyPresent: true,
		IKEProposals: []ObservedIKEProposal{
			{Encryption: "aes-256-cbc", Integrity: "hmac-sha256", Group: 14, LifetimeSeconds: 86400},
			{Encryption: "aes-256-cbc", Integrity: "hmac-sha256", Group: 5, LifetimeSeconds: 86400},
			{Encryption: "3des-cbc", Integrity: "hmac-sha1", Group: 14, LifetimeSeconds: 86400},
			{Encryption: "3des-cbc", Integrity: "hmac-sha1", Group: 5, LifetimeSeconds: 86400},
		},
		IPsecProposals: []ObservedIPsecProposal{{Encryption: "aes-128-gcm", LifetimeSeconds: 3600, LifetimeKB: 5120}},
		PFSGroup:       19,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tunnel =\n%+v\nwant\n%+v", got, want)
	}
	Sanitize(result)
	b, _ := json.Marshal(result)
	if strings.Contains(string(b), "Zm9ydGlnYXRl") || strings.Contains(string(b), "psksecret") {
		t.Fatalf("the pre-shared key reached the result: %s", b)
	}
}

const panIKEXML = `<response status="success"><result><ike>
<gateway><entry name="gw-branch">
  <protocol><version>ikev2</version><ikev2><ike-crypto-profile>ike-strong</ike-crypto-profile></ikev2></protocol>
  <authentication><pre-shared-key><key>-AQ==PLANTEDPANPSKdonotstore==</key></pre-shared-key></authentication>
  <local-address><interface>ethernet1/1</interface><ip>203.0.113.2/24</ip></local-address>
  <peer-address><ip>198.51.100.9</ip></peer-address>
</entry></gateway>
<crypto-profiles>
  <ike-crypto-profiles><entry name="ike-strong">
    <encryption><member>aes-256-cbc</member></encryption><hash><member>sha256</member></hash>
    <dh-group><member>group14</member></dh-group><lifetime><hours>8</hours></lifetime>
  </entry></ike-crypto-profiles>
  <ipsec-crypto-profiles><entry name="esp-strong">
    <esp><encryption><member>aes-256-gcm</member></encryption><authentication><member>none</member></authentication></esp>
    <dh-group>group19</dh-group><lifetime><hours>1</hours></lifetime>
  </entry></ipsec-crypto-profiles>
</crypto-profiles></ike></result></response>`

const panTunnelXML = `<response status="success"><result><ipsec>
<entry name="tun-branch"><auto-key><ike-gateway><entry name="gw-branch"/></ike-gateway>
<ipsec-crypto-profile>esp-strong</ipsec-crypto-profile></auto-key><tunnel-interface>tunnel.1</tunnel-interface></entry>
</ipsec></result></response>`

// Mutation: make panIKEGateway.PSK a string bound to
// `authentication>pre-shared-key>key` and put it in the tunnel name — red.
func TestPanTunnels_JoinGatewayProfilesAndNeverThePSK(t *testing.T) {
	ikes, err := panFindElements[panIKE](panIKEXML, "ike")
	if err != nil || len(ikes) != 1 {
		t.Fatalf("ike: %v %d", err, len(ikes))
	}
	blocks, err := panFindElements[panIPsecTunnels](panTunnelXML, "ipsec")
	if err != nil || len(blocks) != 1 {
		t.Fatalf("tunnels: %v %d", err, len(blocks))
	}
	got := panTunnels(ikes[0], blocks[0].Entries)
	want := []ObservedTunnel{{
		Name: "tun-branch", Encapsulation: "ipsec-tunnel", LocalInterface: "tunnel.1", LocalIP: "203.0.113.2", PeerIP: "198.51.100.9",
		IKEVersion: 2, AuthenticationMethod: "preshared-keys", PresharedKeyPresent: true,
		IKEProposals:   []ObservedIKEProposal{{Encryption: "aes-256-cbc", Integrity: "hmac-sha256", Group: 14, LifetimeSeconds: 28800}},
		IPsecProposals: []ObservedIPsecProposal{{Encryption: "aes-256-gcm", LifetimeSeconds: 3600}},
		PFSGroup:       19,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tunnels =\n%+v\nwant\n%+v", got, want)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "PLANTEDPANPSK") {
		t.Fatalf("the PAN-OS pre-shared key reached the tunnel: %s", b)
	}
}

func TestCiscoTunnels_CryptoMapEntriesWithISAKMPPolicies(t *testing.T) {
	policies := parseISAKMPPolicy(`Global IKE policy
Protection suite of priority 10
        encryption algorithm:   AES - Advanced Encryption Standard (256 bit keys).
        hash algorithm:         Secure Hash Standard 2 (256 bit)
        authentication method:  Pre-Shared Key
        Diffie-Hellman group:   #14 (2048 bit)
        lifetime:               86400 seconds, no volume limit
Default protection suite
        encryption algorithm:   DES - Data Encryption Standard (56 bit keys).
        hash algorithm:         Secure Hash Standard
        authentication method:  Rivest-Shamir-Adleman Signature
        Diffie-Hellman group:   #1 (768 bit)
`)
	if len(policies) != 1 || policies[0] != (ciscoISAKMPPolicy{Priority: 10, Encryption: "aes-256-cbc", Integrity: "hmac-sha256", Group: 14, Auth: "preshared-keys", Lifetime: 86400}) {
		t.Fatalf("policies = %+v", policies)
	}
	maps := []ciscoCryptoConfig{{Type: "crypto_map", Name: "CMAP", Interface: "GigabitEthernet0/1", PeerAddress: "198.51.100.2", IKEVersion: "IKEv1",
		Offered: []ciscoTransform{{Cipher: "AES-256-CBC", Bits: 256, Hash: "SHA1"}}, PFSGroup: "group14", Metadata: map[string]interface{}{"sequence": "10"}}}
	got := ciscoTunnels(maps, policies)
	if len(got) != 1 || got[0].Name != "CMAP 10" || got[0].IKEVersion != 1 || got[0].PFSGroup != 14 ||
		len(got[0].IKEProposals) != 1 || got[0].IKEProposals[0].Group != 14 ||
		len(got[0].IPsecProposals) != 1 || got[0].IPsecProposals[0].Encryption != "AES-256-CBC" || !got[0].PresharedKeyPresent {
		t.Fatalf("tunnels = %+v", got)
	}
}
