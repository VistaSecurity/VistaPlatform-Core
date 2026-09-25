package services

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/forwardmeta"
)

// pipelineMetadataKeys are the keys buildSensorDiscoveryMetadata writes from
// the asset's TYPED fields — the protocol, cipher, key exchange, certificate
// and source-tracking contract the discovery pipeline reads. Everything else it
// may emit comes from forwardmeta's allowlist.
var pipelineMetadataKeys = []string{
	"discovery_method", "version", "cipher_suite",
	"device_id", "source_device_id", "source_asset_id",
	"integration_id", "source_integration_id",
	"hash_algorithm", "key_exchange_algorithm", "key_size", "kex_algorithms",
	"tls_versions", "supported_ciphers", "asset_type", "cert_validation_status",
	"cloud_provider", "cloud_region", "cloud_account_id", "vpc_id",
	"certificates",
}

// The projection test at the WIRING ( W2.1). forwardmeta's own test pins
// the allowlist; this one pins that the writer both runtimes share forwards
// nothing else — so re-introducing `for k, v := range asset.Metadata` here, or
// forwarding the device identity, fails.
func TestBuildSensorDiscoveryMetadata_ForwardsOnlyTheVettedSubset(t *testing.T) {
	allowed := map[string]bool{}
	for _, k := range pipelineMetadataKeys {
		allowed[k] = true
	}
	for _, k := range forwardmeta.Keys() {
		allowed[k] = true
	}

	deviceID := uuid.New()
	asset := models.DiscoveredAsset{
		IPAddress: "203.0.113.20",
		Port:      500,
		Protocol:  "IPSec",
		AssetType: "vpn_gateway",
		// What an agent attaches to every asset: the DEVICE's identity. Its
		// serial must never ride on a finding — the identity builder reads
		// serial_number as an identifier and would merge every tunnel into one.
		DeviceInfo: &models.DeviceIdentity{Vendor: "Fortinet", Model: "FortiGate-60F", SerialNumber: "FGT60F0000000001"},
		SSHInfo:    &models.SSHInfo{Banner: "SSH-2.0-x", HostKeyType: "ssh-ed25519"},
		ServiceHints: &models.ServiceHints{
			ServiceName: "FortiGate IPsec", ServiceVersion: "7.2",
		},
		Metadata: map[string]interface{}{
			// FortiOS phase-1, projected by the collector.
			"name": "Site-A", "remote-gw": "203.0.113.20", "interface": "wan1",
			"ike-version": float64(2), "proposal": "aes256-sha256", "dhgrp": "14 5",
			"authmethod": "psk", "keylife": float64(86400), "certificate": "Fortinet_Factory",
			"certificate_name": "Fortinet_Factory", "certificate_source": "ipsec_config",
			"phase1_proposal": "p1", "encryption_algorithm": "aes256", "dh_group": "14 5",
			// Things that must never cross.
			"psksecret": "hunter2", "private-key": "-----BEGIN PRIVATE KEY-----",
			"serial_number": "FGT60F0000000001", "raw_line": "set remote-gw 203.0.113.20",
			"remote_subnets": []interface{}{"192.0.2.0/24"},
		},
	}

	meta := buildSensorDiscoveryMetadata(&deviceID, nil, asset)
	for k, v := range meta {
		if !allowed[k] {
			t.Errorf("forwarded non-allowlisted key %q = %#v", k, v)
		}
	}
	for _, forbidden := range []string{"serial_number", "psksecret", "private-key", "raw_line", "remote_subnets", "authmethod", "interface"} {
		if _, ok := meta[forbidden]; ok {
			t.Errorf("%q crossed into sensor_discoveries", forbidden)
		}
	}
	want := map[string]interface{}{
		forwardmeta.KeyVPNPeerAddress:  "203.0.113.20",
		forwardmeta.KeyIKEVersion:      "IKEv2",
		forwardmeta.KeyCertificateName: "Fortinet_Factory",
		forwardmeta.KeyConfigName:      "Site-A",
		forwardmeta.KeySSHHostKeyType:  "ssh-ed25519",
		"source_asset_id":              deviceID.String(),
	}
	for k, v := range want {
		if meta[k] != v {
			t.Errorf("%s = %#v, want %#v", k, meta[k], v)
		}
	}
}

// Cisco names its peer `peer_address`; it lands on the same key as FortiOS's
// `remote-gw` and UniFi's `peer_ip`, normalised here rather than in the
// collector (which another slice owns).
func TestBuildSensorDiscoveryMetadata_CiscoPeerNormalised(t *testing.T) {
	asset := models.DiscoveredAsset{
		Hostname: "192.0.2.1", IPAddress: "198.51.100.44", Protocol: "IKEv2", AssetType: "vpn_gateway",
		Metadata: map[string]interface{}{"peer_address": "198.51.100.44", "config_name": "OUTSIDE_MAP"},
	}
	meta := buildSensorDiscoveryMetadata(nil, nil, asset)
	if meta[forwardmeta.KeyVPNPeerAddress] != "198.51.100.44" || meta[forwardmeta.KeyConfigName] != "OUTSIDE_MAP" {
		t.Fatalf("Cisco peer/config not normalised: %#v", meta)
	}
	if _, ok := meta["peer_address"]; ok {
		t.Error("the vendor spelling crossed as well as the canonical key")
	}
}

// No DNS, ever, and a tunnel's far end is not the device's address.
func TestInterrogatedDestIP(t *testing.T) {
	peer := map[string]interface{}{forwardmeta.KeyVPNPeerAddress: "203.0.113.9"}
	cases := []struct {
		name     string
		reported string
		hostname string
		meta     map[string]interface{}
		want     string
	}{
		{"reported address", "198.51.100.10", "", nil, "198.51.100.10"},
		{"ipv6", "2001:db8::10", "", nil, "2001:db8::10"},
		// `localhost` resolves on every host that runs this test. A resolver
		// anywhere on this path would turn it into 127.0.0.1.
		{"a name is not an address", "localhost", "", nil, unspecifiedDestIP},
		{"a name in the hostname is a label, not an address", "", "localhost", nil, unspecifiedDestIP},
		{"no address", "", "", nil, unspecifiedDestIP},
		{"unspecified", "0.0.0.0", "", nil, unspecifiedDestIP},
		{"zone refused by inet", "fe80::1%eth0", "", nil, unspecifiedDestIP},
		{"the address is the tunnel peer", "203.0.113.9", "", peer, unspecifiedDestIP},
		{"a different peer leaves the address", "198.51.100.10", "", peer, "198.51.100.10"},
		// Cisco: hostname is the device's own address (an IP literal), the
		// address field is the peer. The row lands on the device.
		{"peer in the address, device literal in the hostname", "203.0.113.9", "192.0.2.1", peer, "192.0.2.1"},
		{"no address, IP-literal hostname", "", "192.0.2.1", nil, "192.0.2.1"},
		{"a hostname literal that is the peer is still the peer", "", "203.0.113.9", peer, unspecifiedDestIP},
	}
	for _, c := range cases {
		if got := interrogatedDestIP(c.reported, c.hostname, c.meta); got != c.want {
			t.Errorf("%s: interrogatedDestIP(%q, %q) = %q, want %q", c.name, c.reported, c.hostname, got, c.want)
		}
	}
}

// An IOS box advertising SSH-1.99 still accepts SSH-1. The Cisco collector
// writes a constant SSH-2.0; the banner is the measurement and wins.
func TestApplySSHBannerVersion(t *testing.T) {
	cisco := models.DiscoveredAsset{
		IPAddress: "192.0.2.1", Port: 22, Protocol: "SSH", ProtocolVersion: "SSH-2.0",
		SSHInfo:  &models.SSHInfo{Banner: "SSH-1.99-Cisco-1.25"},
		Metadata: map[string]interface{}{"ssh_banner": "SSH-1.99-Cisco-1.25"},
	}
	if got := buildSensorDiscoveryMetadata(nil, nil, cisco)["version"]; got != "SSH-1.99" {
		t.Errorf("SSH-1.99 banner: version = %#v, want SSH-1.99", got)
	}

	modern := cisco
	modern.SSHInfo = &models.SSHInfo{Banner: "SSH-2.0-OpenSSH_9.6"}
	modern.Metadata = nil
	if got := buildSensorDiscoveryMetadata(nil, nil, modern)["version"]; got != "SSH-2.0" {
		t.Errorf("SSH-2.0 banner: version = %#v", got)
	}

	// No banner, or one that states no version: the version is UNKNOWN. The
	// collector's constant SSH-2.0 is not a measurement and is not forwarded.
	for _, banner := range []string{"", "garbage", "SSH-", "SSH-9.9-x", "SSH-2.0-OpenSSH\r\nX"} {
		bare := cisco
		bare.Metadata = nil
		bare.SSHInfo = &models.SSHInfo{Banner: banner}
		if got, ok := buildSensorDiscoveryMetadata(nil, nil, bare)["version"]; ok {
			t.Errorf("banner %q: version = %#v, want absent (unknown)", banner, got)
		}
	}

	// Not SSH: a stray banner does not rewrite a TLS version.
	tls := models.DiscoveredAsset{Protocol: "TLS", ProtocolVersion: "TLS 1.2", Metadata: map[string]interface{}{"ssh_banner": "SSH-1.99-x"}}
	if got := buildSensorDiscoveryMetadata(nil, nil, tls)["version"]; got != "TLS 1.2" {
		t.Errorf("TLS asset: version = %#v, want TLS 1.2", got)
	}
}

func TestJobResultDeviceIdentity(t *testing.T) {
	onAsset := &models.DeviceIdentity{Vendor: "Palo Alto Networks", Model: "PA-220", SerialNumber: "OLD"}

	// A current agent: the result's copy, with no asset at all.
	got := jobResultDeviceIdentity(&models.JobResult{DeviceIdentity: &di.DeviceIdentity{Vendor: "Palo Alto Networks", Model: "PA-3220", SerialNumber: "013201001234", ClassHint: "firewall"}})
	if got == nil || got.Model != "PA-3220" || got.SerialNumber != "013201001234" || got.ClassHint != "firewall" {
		t.Errorf("zero-asset result: identity = %+v", got)
	}

	// Both: the result's copy wins.
	got = jobResultDeviceIdentity(&models.JobResult{
		DeviceIdentity: &di.DeviceIdentity{Model: "PA-3220"},
		Assets:         []models.DiscoveredAsset{{DeviceInfo: onAsset}},
	})
	if got == nil || got.Model != "PA-3220" {
		t.Errorf("result-level identity did not win: %+v", got)
	}

	// An older agent: the first asset's copy.
	got = jobResultDeviceIdentity(&models.JobResult{Assets: []models.DiscoveredAsset{{DeviceInfo: onAsset}}})
	if got == nil || got.Model != "PA-220" || got.SerialNumber != "OLD" {
		t.Errorf("old-agent fallback lost: %+v", got)
	}

	// An empty result-level identity is not an answer; nor is nothing.
	if got := jobResultDeviceIdentity(&models.JobResult{DeviceIdentity: &di.DeviceIdentity{}}); got != nil {
		t.Errorf("empty identity treated as an answer: %+v", got)
	}
	if got := jobResultDeviceIdentity(&models.JobResult{}); got != nil {
		t.Errorf("no identity at all produced %+v", got)
	}
}
