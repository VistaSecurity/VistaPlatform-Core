package deviceinterrogation

import (
	"strings"
	"testing"
)

// The DH group is an IPsec tunnel's key exchange — its one Shor-breakable
// component. Every collector used to keep it only in metadata, which nothing
// downstream links, so a tunnel linked AES and SHA-2 and nothing else and was
// counted as quantum-safe. These tests pin that each VPN collector now reports
// the group as the key exchange, in the catalogue's own vocabulary, with the
// group's key size beside it.

func assertIKEKeyExchange(t *testing.T, a CryptoAsset, wantKex string, wantBits int, wantRawGroup string) {
	t.Helper()
	if a.KeyExchangeAlg == nil || *a.KeyExchangeAlg != wantKex {
		t.Errorf("KeyExchangeAlg = %v, want %s", derefString(a.KeyExchangeAlg), wantKex)
	}
	if a.KeySize == nil || *a.KeySize != wantBits {
		t.Errorf("KeySize = %v, want %d (the group's key size, not the cipher's)", derefInt(a.KeySize), wantBits)
	}
	if a.Metadata["dh_group"] != wantRawGroup {
		t.Errorf("metadata dh_group = %v, want the collector's own spelling %q", a.Metadata["dh_group"], wantRawGroup)
	}
}

func derefString(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func derefInt(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

// FortiOS phase1-interface `dhgrp` is a space-separated list in preference
// order. The first group is the key exchange; the full list survives in
// metadata, where the result processor reads the whole offer.
func TestFortinetIPSec_DHGroupListBecomesKeyExchange(t *testing.T) {
	c := &fortinetClient{}
	a := c.convertIPSecToAsset(map[string]interface{}{
		"name":      "branch-tunnel",
		"remote-gw": "198.51.100.7",
		"proposal":  "aes256-sha256",
		"dhgrp":     "14 5",
	})
	assertIKEKeyExchange(t, a, "DH-MODP-2048", 2048, "14 5")
}

func TestFortinetIPSec_ECPGroupFirst(t *testing.T) {
	c := &fortinetClient{}
	a := c.convertIPSecToAsset(map[string]interface{}{
		"name":     "hq-tunnel",
		"proposal": "aes128gcm-prfsha256",
		"dhgrp":    "19 14",
	})
	assertIKEKeyExchange(t, a, "DH-ECP-256", 256, "19 14")
}

// An unassigned group names nothing we can assess: no key exchange is
// invented, and the cipher's key length is left as the collector found it.
func TestFortinetIPSec_UnknownGroupLinksNothing(t *testing.T) {
	c := &fortinetClient{}
	a := c.convertIPSecToAsset(map[string]interface{}{
		"name":     "odd-tunnel",
		"proposal": "aes256-sha256",
		"dhgrp":    "99",
	})
	if a.KeyExchangeAlg != nil {
		t.Errorf("KeyExchangeAlg = %s, want unset for an unassigned group", *a.KeyExchangeAlg)
	}
	if a.Metadata["dh_group"] != "99" {
		t.Errorf("the raw setting must still be kept, got %v", a.Metadata["dh_group"])
	}
}

// UniFi: group 14 is the key exchange, and the IKE version — which the
// collector used to put in the key-exchange field — is the protocol version.
func TestUnifiIPsec_DHGroupIsKeyExchangeAndIKEVersionIsProtocolVersion(t *testing.T) {
	a := unifiVPNAsset(sampleIPsecSiteVPN(), "192.0.2.1")
	assertIKEKeyExchange(t, a, "DH-MODP-2048", 2048, "14")
	if a.ProtocolVersion == nil || *a.ProtocolVersion != "IKEv2" {
		t.Errorf("ProtocolVersion = %v, want IKEv2", derefString(a.ProtocolVersion))
	}
}

func TestUnifiIPsec_IKEVersionWithoutDHGroupIsNotAKeyExchange(t *testing.T) {
	conf := sampleIPsecSiteVPN()
	delete(conf, "ipsec_dh_group")
	conf["ipsec_key_exchange"] = "ikev1"

	a := unifiVPNAsset(conf, "192.0.2.1")
	if a.KeyExchangeAlg != nil {
		t.Errorf("KeyExchangeAlg = %s — an IKE version is not a key exchange", *a.KeyExchangeAlg)
	}
	if a.ProtocolVersion == nil || *a.ProtocolVersion != "IKEv1" {
		t.Errorf("ProtocolVersion = %v, want IKEv1", derefString(a.ProtocolVersion))
	}
	// Without a group, the key size stays what the collector read (the cipher's).
	if a.KeySize == nil || *a.KeySize != 256 {
		t.Errorf("KeySize = %v, want 256", derefInt(a.KeySize))
	}
}

// A version string UniFi might send that we do not recognise is kept as
// evidence but not promoted to a protocol version we would have to invent.
func TestUnifiIPsec_UnrecognisedIKEVersionIsKeptButNotPromoted(t *testing.T) {
	conf := sampleIPsecSiteVPN()
	conf["ipsec_key_exchange"] = "auto"

	a := unifiVPNAsset(conf, "192.0.2.1")
	if a.ProtocolVersion != nil {
		t.Errorf("ProtocolVersion = %s, want unset for %q", *a.ProtocolVersion, "auto")
	}
	if a.Metadata["ike_version"] != "auto" {
		t.Errorf("ike_version = %v, want the raw value kept", a.Metadata["ike_version"])
	}
}

// WireGuard's key exchange is fixed by the protocol: Curve25519 must still
// land, unchanged by any of this.
func TestUnifiWireGuard_KeyExchangeIsCurve25519(t *testing.T) {
	a := unifiVPNAsset(map[string]interface{}{
		"name":     "wg-remote-access",
		"purpose":  "remote-user-vpn",
		"vpn_type": "wireguard-server",
	}, "192.0.2.1")
	if a.KeyExchangeAlg == nil || *a.KeyExchangeAlg != "Curve25519" {
		t.Errorf("KeyExchangeAlg = %v, want Curve25519", derefString(a.KeyExchangeAlg))
	}
}

// Cisco IOS `show crypto ikev2 sa` reports the NEGOTIATED group on the SA
// line ("DH Grp:14"). The collector used to report it as "DH Group 14", which
// is no catalogue code — and which the key-size rules read as a finite-field
// key the size of the AES key.
func TestCiscoIKEv2SA_NegotiatedGroupIsKeyExchange(t *testing.T) {
	output := `IPv4 Crypto IKEv2  SA

Tunnel-id Local                 Remote                fvrf/ivrf            Status
1         192.0.2.1/500         198.51.100.2/500      none/none            READY
      Encr: AES-CBC, keysize: 256, PRF: SHA256, Hash: SHA256, DH Grp:14, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 86400/735 sec
`
	c := &ciscoSSHClient{host: "192.0.2.1"}
	configs := c.parseIKEv2SA(output)
	var found bool
	for _, cfg := range configs {
		if cfg.DiffieGroup == "" {
			continue
		}
		found = true
		a := c.convertCryptoConfigToAsset(cfg)
		assertIKEKeyExchange(t, a, "DH-MODP-2048", 2048, "Group 14")
	}
	if !found {
		t.Fatalf("no SA carried a DH group: %+v", configs)
	}
}

// `show crypto map` prints the PFS (phase-2) group of an ipsec-isakmp entry as
// "DH group:  group19". It is a Diffie-Hellman exchange, so the result
// processor offers it for scoring — but it is NOT the tunnel's key exchange.
// That is the IKE SA's group, from the isakmp policy, which this collector
// does not read; so the key exchange stays unknown and the AES length is
// cleared from key_size.
func TestCiscoCryptoMap_PFSGroupIsOfferedNotTheKeyExchange(t *testing.T) {
	output := `Crypto Map IPv4 "CMAP" 10 ipsec-isakmp
        Peer = 198.51.100.2
        Extended IP access list 101
        Current peer: 198.51.100.2
        Security association lifetime: 4608000 kilobytes/3600 seconds
        Responder-Only (Y/N): N
        PFS (Y/N): Y
        DH group:  group19
        Mixed-mode : Disabled
        Transform sets={
                TS1:  { esp-256-aes esp-sha256-hmac  } ,
        }
`
	c := &ciscoSSHClient{host: "192.0.2.1"}
	configs := c.parseCryptoMap(output)
	if len(configs) != 1 {
		t.Fatalf("configs = %d, want 1: %+v", len(configs), configs)
	}
	a := c.convertCryptoConfigToAsset(configs[0])
	if a.KeyExchangeAlg != nil {
		t.Errorf("KeyExchangeAlg = %s — a PFS group is not the IKE key exchange", *a.KeyExchangeAlg)
	}
	if a.KeySize != nil {
		t.Errorf("KeySize = %d, want unset: the AES length must not sit beside a DH exchange", *a.KeySize)
	}
	if a.Metadata["pfs_dh_group"] != "group19" {
		t.Errorf("pfs_dh_group = %v, want group19", a.Metadata["pfs_dh_group"])
	}
	if _, present := a.Metadata["dh_group"]; present {
		t.Errorf("dh_group = %v, want absent — that key is the IKE group", a.Metadata["dh_group"])
	}
}

// Real IOS `show crypto ipsec sa detail` output (ntc-templates corpus) says
// "PFS (Y/N): N, DH group: none": PFS off, no group, nothing to offer, and the
// cipher's key length is left alone.
func TestCiscoIPSecSA_RealOutputPFSOffIsNoGroup(t *testing.T) {
	output := readRealFixture(t, "cisco_ios", "show_crypto_ipsec_sa_detail.txt")
	c := &ciscoSSHClient{host: "192.0.2.1"}
	configs := c.parseIPSecSA(output)
	if len(configs) == 0 {
		t.Fatal("no SAs parsed from the real fixture")
	}
	for _, cfg := range configs {
		if cfg.PFSGroup != "" {
			t.Errorf("PFSGroup = %q from a PFS-off SA, want none", cfg.PFSGroup)
		}
		a := c.convertCryptoConfigToAsset(cfg)
		if _, present := a.Metadata["pfs_dh_group"]; present || a.KeyExchangeAlg != nil {
			t.Errorf("PFS-off SA produced a group: kex=%v meta=%v", a.KeyExchangeAlg, a.Metadata["pfs_dh_group"])
		}
	}

	// The same SA with PFS on: the group is read, and offered.
	pfsOn := strings.Replace(output, "PFS (Y/N): N, DH group: none", "PFS (Y/N): Y, DH group: group14", 1)
	if pfsOn == output {
		t.Fatal("fixture no longer carries the PFS line this test rewrites")
	}
	var found bool
	for _, cfg := range c.parseIPSecSA(pfsOn) {
		if cfg.PFSGroup == "" {
			continue
		}
		found = true
		a := c.convertCryptoConfigToAsset(cfg)
		if a.Metadata["pfs_dh_group"] != "group14" || a.KeyExchangeAlg != nil || a.KeySize != nil {
			t.Errorf("PFS SA: pfs_dh_group=%v kex=%v keySize=%v, want group14/unset/unset",
				a.Metadata["pfs_dh_group"], a.KeyExchangeAlg, a.KeySize)
		}
	}
	if !found {
		t.Error("PFS group not read from `PFS (Y/N): Y, DH group: group14`")
	}
}

// When both are known, the IKE group is the key exchange and the PFS group
// is recorded beside it for the offered list.
func TestApplyIKEDHGroups_IKEGroupWinsOverPFS(t *testing.T) {
	a := CryptoAsset{KeySize: intPtr(256)}
	applyIKEDHGroups(&a, "19", "5")
	assertIKEKeyExchange(t, a, "DH-ECP-256", 256, "19")
	if a.Metadata["pfs_dh_group"] != "5" {
		t.Errorf("pfs_dh_group = %v, want 5", a.Metadata["pfs_dh_group"])
	}
}

// The preferred group has no catalogue row (GOST): the key exchange is
// unknown — never the second choice — and the AES length is cleared.
func TestFortinetIPSec_UnassessableFirstGroupLeavesKeyExchangeUnknown(t *testing.T) {
	c := &fortinetClient{}
	a := c.convertIPSecToAsset(map[string]interface{}{
		"name":     "gost-first",
		"proposal": "aes256-sha256",
		"dhgrp":    "33 14",
	})
	if a.KeyExchangeAlg != nil {
		t.Errorf("KeyExchangeAlg = %s, want unset — group 14 is the second choice, not the one in use", *a.KeyExchangeAlg)
	}
	if a.KeySize != nil {
		t.Errorf("KeySize = %d, want unset once a group is configured", *a.KeySize)
	}
	if a.Metadata["dh_group"] != "33 14" {
		t.Errorf("dh_group = %v, want the raw list kept", a.Metadata["dh_group"])
	}
}
