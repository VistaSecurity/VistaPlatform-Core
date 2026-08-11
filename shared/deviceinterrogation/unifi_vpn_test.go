package deviceinterrogation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newMockUnifiOSController serves the minimal UniFi-OS (UDM) API surface
// interrogate() touches: JSON login at /api/auth/login (so the client selects
// the /proxy/network prefix) and the proxied Network API reads.
func newMockUnifiOSController(t *testing.T) *httptest.Server {
	t.Helper()
	ok := func(w http.ResponseWriter, data []map[string]interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"meta": map[string]string{"rc": "ok"},
			"data": data,
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
		w.Header().Set("X-CSRF-Token", "csrf-123")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/self", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{{"model": "UDM-Pro", "version": "8.0.7"}})
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{{"name": "office-switch", "ip": "10.0.0.2", "mac": "aa:bb", "model": "USW24"}})
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{
			{"name": "corporate-lan", "purpose": "corporate", "ip_subnet": "10.0.1.1/24"},
			sampleIPsecSiteVPN(),
		})
	})
	mux.HandleFunc("/proxy/network/api/s/default/list/setting", func(w http.ResponseWriter, r *http.Request) {
		ok(w, []map[string]interface{}{{"key": "mgmt"}})
	})
	return httptest.NewTLSServer(mux)
}

// Tests for UniFi gateway VPN extraction: networkconf entries with a
// VPN purpose become vpn_gateway assets carrying the API-reported crypto,
// secrets (x_-prefixed) never reach metadata, and ordinary LAN networks are
// skipped.

func sampleIPsecSiteVPN() map[string]interface{} {
	return map[string]interface{}{
		"_id":                    "abc123",
		"name":                   "branch-office-s2s",
		"purpose":                "site-vpn",
		"vpn_type":               "ipsec-vpn",
		"ipsec_key_exchange":     "ikev2",
		"ipsec_encryption":       "aes256",
		"ipsec_hash":             "sha256",
		"ipsec_dh_group":         float64(14),
		"ipsec_pfs":              true,
		"ipsec_profile":          "customized",
		"ipsec_peer_ip":          "203.0.113.50",
		"ipsec_local_ip":         "198.51.100.1",
		"remote_vpn_subnets":     []interface{}{"10.20.0.0/16"},
		"x_ipsec_pre_shared_key": "SUPER-SECRET-PSK",
	}
}

func TestUnifiVPNAssets_IPsecSiteToSite(t *testing.T) {
	confs := []map[string]interface{}{
		sampleIPsecSiteVPN(),
		{"name": "corporate-lan", "purpose": "corporate", "ip_subnet": "10.0.1.1/24"},
	}

	assets := unifiVPNAssets(confs, "192.0.2.1")
	if len(assets) != 1 {
		t.Fatalf("expected 1 VPN asset (LAN skipped), got %d", len(assets))
	}
	a := assets[0]

	if a.AssetType != "vpn_gateway" {
		t.Errorf("AssetType = %q, want vpn_gateway", a.AssetType)
	}
	if a.Protocol != "IPSec" || a.Port != 500 {
		t.Errorf("protocol/port = %s/%d, want IPSec/500", a.Protocol, a.Port)
	}
	if a.Hostname != "branch-office-s2s" {
		t.Errorf("Hostname = %q", a.Hostname)
	}
	if a.IPAddress != "198.51.100.1" {
		t.Errorf("IPAddress = %q, want the ipsec_local_ip", a.IPAddress)
	}
	if a.CipherSuite == nil || *a.CipherSuite != "aes256-sha256" {
		t.Errorf("CipherSuite = %v, want aes256-sha256", a.CipherSuite)
	}
	if a.KeySize == nil || *a.KeySize != 256 {
		t.Errorf("KeySize = %v, want 256", a.KeySize)
	}
	if a.HashAlgorithm == nil || *a.HashAlgorithm != "SHA256" {
		t.Errorf("HashAlgorithm = %v, want SHA256", a.HashAlgorithm)
	}
	if a.KeyExchangeAlg == nil || *a.KeyExchangeAlg != "IKEV2" {
		t.Errorf("KeyExchangeAlg = %v, want IKEV2", a.KeyExchangeAlg)
	}
	if a.Metadata["dh_group"] != "14" {
		t.Errorf("dh_group = %v, want 14", a.Metadata["dh_group"])
	}
	if a.Metadata["pfs_enabled"] != true {
		t.Errorf("pfs_enabled = %v, want true", a.Metadata["pfs_enabled"])
	}
	if a.Metadata["peer_ip"] != "203.0.113.50" {
		t.Errorf("peer_ip = %v", a.Metadata["peer_ip"])
	}
}

func TestUnifiVPNAssets_SecretsNeverReachMetadata(t *testing.T) {
	confs := []map[string]interface{}{
		sampleIPsecSiteVPN(),
		{
			"name":                    "wg-remote-access",
			"purpose":                 "remote-user-vpn",
			"vpn_type":                "wireguard-server",
			"wireguard_port":          float64(51821),
			"wireguard_public_key":    "pub-key-ok-to-expose",
			"x_wireguard_private_key": "PRIVATE-KEY-SECRET",
		},
	}

	for _, a := range unifiVPNAssets(confs, "192.0.2.1") {
		for k := range a.Metadata {
			if len(k) > 2 && k[:2] == "x_" {
				t.Fatalf("secret field %q leaked into metadata of %q", k, a.Hostname)
			}
		}
	}
}

func TestUnifiVPNAssets_WireGuardProtocolConstants(t *testing.T) {
	confs := []map[string]interface{}{{
		"name":                 "wg-remote-access",
		"purpose":              "remote-user-vpn",
		"vpn_type":             "wireguard-server",
		"wireguard_port":       float64(51821),
		"wireguard_public_key": "pub-key",
	}}

	assets := unifiVPNAssets(confs, "192.0.2.1")
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	a := assets[0]

	if a.Protocol != "WireGuard" || a.Port != 51821 {
		t.Errorf("protocol/port = %s/%d, want WireGuard/51821", a.Protocol, a.Port)
	}
	if a.KeyExchangeAlg == nil || *a.KeyExchangeAlg != "Curve25519" {
		t.Errorf("KeyExchangeAlg = %v, want Curve25519", a.KeyExchangeAlg)
	}
	if a.CipherSuite == nil || *a.CipherSuite != "ChaCha20-Poly1305" {
		t.Errorf("CipherSuite = %v, want ChaCha20-Poly1305", a.CipherSuite)
	}
	if a.Metadata["crypto_source"] != "protocol_constant" {
		t.Errorf("crypto_source = %v, want protocol_constant (spec values, not observed)", a.Metadata["crypto_source"])
	}
	if a.Metadata["wireguard_public_key"] != "pub-key" {
		t.Errorf("public key should be surfaced, got %v", a.Metadata["wireguard_public_key"])
	}
	// Falls back to the controller/gateway host when the conf names no IP.
	if a.IPAddress != "192.0.2.1" {
		t.Errorf("IPAddress = %q, want controller host fallback", a.IPAddress)
	}
}

func TestUnifiVPNAssets_OpenVPNNoFabricatedCrypto(t *testing.T) {
	confs := []map[string]interface{}{{
		"name":               "ovpn-server",
		"purpose":            "remote-user-vpn",
		"vpn_type":           "openvpn-server",
		"openvpn_local_port": "1195",
		"openvpn_mode":       "server",
	}}

	assets := unifiVPNAssets(confs, "192.0.2.1")
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	a := assets[0]

	if a.Protocol != "OpenVPN" || a.Port != 1195 {
		t.Errorf("protocol/port = %s/%d, want OpenVPN/1195", a.Protocol, a.Port)
	}
	// The controller API does not expose OpenVPN's negotiated cipher — the
	// typed crypto fields must stay unset rather than carry invented values.
	if a.CipherSuite != nil || a.KeySize != nil || a.HashAlgorithm != nil || a.KeyExchangeAlg != nil {
		t.Errorf("OpenVPN crypto fields must stay unset (got cipher=%v keySize=%v hash=%v kex=%v)",
			a.CipherSuite, a.KeySize, a.HashAlgorithm, a.KeyExchangeAlg)
	}
}

func TestUnifiVPNAssets_L2TPCarriesIPsecCrypto(t *testing.T) {
	confs := []map[string]interface{}{{
		"name":                   "legacy-remote",
		"purpose":                "remote-user-vpn",
		"vpn_type":               "l2tp-server",
		"ipsec_encryption":       "aes128",
		"ipsec_hash":             "sha1",
		"x_ipsec_pre_shared_key": "SECRET",
	}}

	assets := unifiVPNAssets(confs, "192.0.2.1")
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	a := assets[0]

	if a.Protocol != "L2TP/IPSec" || a.Port != 1701 {
		t.Errorf("protocol/port = %s/%d, want L2TP/IPSec/1701", a.Protocol, a.Port)
	}
	if a.CipherSuite == nil || *a.CipherSuite != "aes128-sha1" {
		t.Errorf("CipherSuite = %v, want aes128-sha1", a.CipherSuite)
	}
	if a.KeySize == nil || *a.KeySize != 128 {
		t.Errorf("KeySize = %v, want 128", a.KeySize)
	}
}

// TestUnifiInterrogate_EmitsVPNAssets drives the full interrogate() flow
// against a mock UniFi-OS (UDM-style) controller and asserts the VPN
// networkconf entry surfaces as a vpn_gateway asset alongside the managed
// device + management-interface assets.
func TestUnifiInterrogate_EmitsVPNAssets(t *testing.T) {
	srv := newMockUnifiOSController(t)
	defer srv.Close()

	c := newUnifiClient(srv.URL, "admin", "secret", "", true)
	result, err := c.interrogate(t.Context())
	if err != nil {
		t.Fatalf("interrogate: %v", err)
	}

	var vpn *CryptoAsset
	for i := range result.Assets {
		if result.Assets[i].AssetType == "vpn_gateway" {
			vpn = &result.Assets[i]
		}
	}
	if vpn == nil {
		t.Fatalf("no vpn_gateway asset emitted; assets: %+v", result.Assets)
	}
	if vpn.Hostname != "branch-office-s2s" || vpn.Protocol != "IPSec" {
		t.Errorf("vpn asset = %s/%s, want branch-office-s2s/IPSec", vpn.Hostname, vpn.Protocol)
	}
	if vpn.CipherSuite == nil || *vpn.CipherSuite != "aes256-sha256" {
		t.Errorf("CipherSuite = %v", vpn.CipherSuite)
	}
	if _, leaked := vpn.Metadata["x_ipsec_pre_shared_key"]; leaked {
		t.Error("pre-shared key leaked into asset metadata")
	}
}

func TestUnifiKeySize(t *testing.T) {
	cases := map[string]int{"aes256": 256, "aes192": 192, "aes128": 128, "3des": 168, "AES-256": 256, "": 0, "chacha": 0}
	for in, want := range cases {
		if got := unifiKeySize(in); got != want {
			t.Errorf("unifiKeySize(%q) = %d, want %d", in, got, want)
		}
	}
}
