package forwardmeta

import (
	"sort"
	"strings"
	"testing"
)

// hostileMetadata is every key a collector writes into per-asset metadata
// today, plus the secret-bearing names a vendor response carries, all on one
// asset. Only the allowlisted concepts may come out of Project.
func hostileMetadata() map[string]interface{} {
	return map[string]interface{}{
		// Real collector keys that ARE forwarded, under their vendor names.
		"peer_ip":          "198.51.100.7",
		"ike_version":      "ikev2",
		"ssh_banner":       "SSH-1.99-Cisco-1.25",
		"host_key_type":    "ssh-rsa",
		"mac_address":      "F0:9F:C2:00:00:01",
		"profile_name":     "clientssl-strict",
		"certificate_name": "Fortinet_Factory",
		"certificate_ca":   "Corp-Root-CA",
		"rule_name":        "decrypt-outbound",

		// Real collector keys that are NOT forwarded.
		"raw_line":             "crypto map OUTSIDE 10 set peer 198.51.100.7",
		"remote_subnets":       []interface{}{"192.0.2.0/24"},
		"wireguard_public_key": "not-a-secret-but-not-posture",
		"cert_key_chain":       []interface{}{map[string]interface{}{"cert": "/Common/x.crt"}},
		"site_id":              "default",
		"source":               "unifi_networkconf",
		"state":                "ACTIVE",
		"sysContact":           "noc@example.net",

		// The interrogated device's identity — the one thing that must never
		// ride on a finding (see the package comment).
		"serial_number":    "FGT60F0000000001",
		"serial":           "FGT60F0000000001",
		"model":            "FortiGate-60F",
		"firmware_version": "7.2.5",

		// Secret-bearing names a vendor object carries.
		"psksecret":   "hunter2",
		"x_ipsec_psk": "hunter2",
		"private-key": "-----BEGIN PRIVATE KEY-----",
		"password":    "hunter2",
		"token":       "abc",
	}
}

func TestProject_EmitsOnlyAllowlistedKeys(t *testing.T) {
	allowed := map[string]bool{}
	for _, k := range Keys() {
		allowed[k] = true
	}
	for _, assetType := range []string{"", "vpn_gateway", "load_balancer", "firewall", "appliance"} {
		md := hostileMetadata()
		md["name"] = "Site-A-VPN"
		out := Project(Source{AssetType: assetType, Metadata: md, SSH: SSH{
			Banner: "SSH-2.0-OpenSSH_9.6", HostKeyType: "ssh-ed25519",
			HostKeyFingerprint: "SHA256:AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		}})
		for k, v := range out {
			if !allowed[k] {
				t.Errorf("assetType %q: forwarded non-allowlisted key %q=%v", assetType, k, v)
			}
			if s, ok := v.(string); !ok || s == "" {
				t.Errorf("assetType %q: key %q forwarded an empty or non-string value %#v", assetType, k, v)
			}
		}
		for _, forbidden := range []string{"serial_number", "serial", "model", "firmware_version", "psksecret", "x_ipsec_psk", "private-key", "password", "token", "raw_line", "remote_subnets", "wireguard_public_key", "cert_key_chain"} {
			if _, ok := out[forbidden]; ok {
				t.Errorf("assetType %q: %q crossed the boundary", assetType, forbidden)
			}
		}
	}
}

// Keys is the allowlist the wiring test in device-interrogation-service checks
// against, so it must be exactly the set Project can produce — no more.
func TestKeys_AreExactlyWhatProjectCanEmit(t *testing.T) {
	md := map[string]interface{}{}
	for _, k := range Keys() {
		md[k] = "x"
	}
	md[KeyVPNPeerAddress] = "198.51.100.9"
	md[KeyIKEVersion] = "IKEv1"
	md[KeySSHBanner] = "SSH-2.0-x"
	md[KeySSHHostKeyFingerprint] = "SHA256:abc"
	md[KeyMACAddress] = "02:00:00:00:00:01"
	out := Project(Source{Metadata: md})
	got := make([]string, 0, len(out))
	for k := range out {
		got = append(got, k)
	}
	want := Keys()
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Project emitted %v, Keys() says %v", got, want)
	}
}

// One canonical key per concept, whichever vendor said it.
func TestProject_NormalisesVendorSpellings(t *testing.T) {
	cases := []struct {
		name      string
		assetType string
		md        map[string]interface{}
		key       string
		want      string
	}{
		{"unifi peer", "vpn_gateway", map[string]interface{}{"peer_ip": "198.51.100.1"}, KeyVPNPeerAddress, "198.51.100.1"},
		{"cisco peer", "vpn_gateway", map[string]interface{}{"peer_address": "198.51.100.2"}, KeyVPNPeerAddress, "198.51.100.2"},
		{"fortinet peer", "vpn_gateway", map[string]interface{}{"remote-gw": "203.0.113.3"}, KeyVPNPeerAddress, "203.0.113.3"},
		{"ipv6 peer", "vpn_gateway", map[string]interface{}{"remote-gw": "2001:db8::1"}, KeyVPNPeerAddress, "2001:db8::1"},
		{"unifi ike", "vpn_gateway", map[string]interface{}{"ike_version": "ikev2"}, KeyIKEVersion, "IKEv2"},
		{"fortinet ike as JSON number", "vpn_gateway", map[string]interface{}{"ike-version": float64(1)}, KeyIKEVersion, "IKEv1"},
		{"fortinet ike as string", "vpn_gateway", map[string]interface{}{"ike-version": "2"}, KeyIKEVersion, "IKEv2"},
		{"unifi mac", "", map[string]interface{}{"mac_address": "F0-9F-C2-AA-BB-CC"}, KeyMACAddress, "f0:9f:c2:aa:bb:cc"},
		{"f5 profile", "load_balancer", map[string]interface{}{"profile_name": "/Common/clientssl"}, KeyProfileName, "/Common/clientssl"},
		{"unifi ipsec profile", "vpn_gateway", map[string]interface{}{"ipsec_profile": "customized"}, KeyProfileName, "customized"},
		{"pan-os ca", "firewall", map[string]interface{}{"certificate_ca": "Forward-Trust"}, KeyCACertificateName, "Forward-Trust"},
		{"pan-os rule", "firewall", map[string]interface{}{"rule_name": "postgres"}, KeyConfigName, "postgres"},
		{"f5 vip", "load_balancer", map[string]interface{}{"virtual_server": "/Common/app_vs"}, KeyConfigName, "/Common/app_vs"},
		{"cisco crypto map", "vpn_gateway", map[string]interface{}{"config_name": "OUTSIDE_MAP"}, KeyConfigName, "OUTSIDE_MAP"},
		{"fortinet tunnel name", "vpn_gateway", map[string]interface{}{"name": "Site-A"}, KeyConfigName, "Site-A"},
		{"ssh host key type (prober)", "", map[string]interface{}{"host_key_type": "ssh-rsa"}, KeySSHHostKeyType, "ssh-rsa"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := Project(Source{AssetType: c.assetType, Metadata: c.md})
			if got := out[c.key]; got != c.want {
				t.Fatalf("%s = %#v, want %q (all: %#v)", c.key, got, c.want, out)
			}
		})
	}
}

// `name` is a tunnel label only on a VPN asset. On a UniFi managed device it is
// the device's display name, and on anything else it could be anything.
func TestProject_NameIsAConfigLabelOnlyForVPNs(t *testing.T) {
	out := Project(Source{AssetType: "appliance", Metadata: map[string]interface{}{"name": "Office AP"}})
	if _, ok := out[KeyConfigName]; ok {
		t.Fatalf("a non-VPN asset's `name` was forwarded as config_name: %#v", out)
	}
}

func TestProject_TypedSSHBeatsMetadataCopy(t *testing.T) {
	out := Project(Source{
		Metadata: map[string]interface{}{"ssh_banner": "SSH-2.0-stale"},
		SSH:      SSH{Banner: "SSH-1.99-Cisco-1.25", KexAlgorithm: "diffie-hellman-group14-sha1"},
	})
	if out[KeySSHBanner] != "SSH-1.99-Cisco-1.25" {
		t.Errorf("ssh_banner = %#v, want the typed handshake value", out[KeySSHBanner])
	}
	if out[KeySSHKexAlgorithm] != "diffie-hellman-group14-sha1" {
		t.Errorf("ssh_kex_algorithm = %#v", out[KeySSHKexAlgorithm])
	}
}

// Both polarities for every validator: a value that would be refused on receipt
// is never sent, and a value that validates always is.
func TestValidators(t *testing.T) {
	type tc struct {
		in   string
		ok   bool
		want string
	}
	check := func(t *testing.T, name string, fn func(string) (string, bool), cases []tc) {
		t.Helper()
		for _, c := range cases {
			got, ok := fn(c.in)
			if ok != c.ok || (ok && c.want != "" && got != c.want) {
				t.Errorf("%s(%q) = %q,%v; want %q,%v", name, c.in, got, ok, c.want, c.ok)
			}
		}
	}
	check(t, "address", validAddress, []tc{
		{"198.51.100.1", true, "198.51.100.1"},
		{"2001:db8::1", true, "2001:db8::1"},
		{"0.0.0.0", false, ""},
		{"::", false, ""},
		{"fe80::1%eth0", false, ""},
		{"vpn.example.net", false, ""},
		{"", false, ""},
	})
	check(t, "ike", validIKEVersion, []tc{
		{"IKEv2", true, "IKEv2"}, {"ike-v1", true, "IKEv1"}, {"2", true, "IKEv2"}, {"3", false, ""}, {"IKEv3", false, ""},
	})
	check(t, "banner", validBanner, []tc{
		{"SSH-1.99-Cisco-1.25", true, ""},
		{"SSH-2.0-OpenSSH_9.6", true, ""},
		{"HTTP/1.1 200 OK", false, ""},
		{"SSH-2.0-x\r\nevil", false, ""},
		{"SSH-2.0-" + strings.Repeat("a", 300), false, ""},
	})
	check(t, "algorithm", validAlgorithm, []tc{
		{"curve25519-sha256@libssh.org", true, ""}, {"ssh-rsa,ssh-dss", false, ""}, {"a b", false, ""}, {strings.Repeat("a", 65), false, ""},
	})
	check(t, "fingerprint", validFingerprint, []tc{
		{"SHA256:AAAAC3NzaC1lZDI1NTE5", true, ""},
		{"MD5:16:27:ac:a5", true, ""},
		{"-----BEGIN OPENSSH PRIVATE KEY-----", false, ""},
		{"SHA256:" + strings.Repeat("A", 200), false, ""},
		{"nocolon", false, ""},
	})
	check(t, "mac", validMAC, []tc{
		{"F0:9F:C2:AA:BB:CC", true, "f0:9f:c2:aa:bb:cc"},
		{"f09f.c2aa.bbcc", true, "f0:9f:c2:aa:bb:cc"},
		{"00:00:00:00:00:00", false, ""},
		{"ff:ff:ff:ff:ff:ff", false, ""},
		{"01:00:5e:00:00:01", false, ""},
		{"f0:9f:c2", false, ""},
	})
	check(t, "label", validLabel, []tc{
		{"/Common/app_vs", true, ""},
		{"Site-A VPN", true, ""},
		{"line\nbreak", false, ""},
		{"-----BEGIN CERTIFICATE-----", false, ""},
		{strings.Repeat("a", 129), false, ""},
		{"a\u202egnp.exe", false, ""},
		{"zero\u200bwidth", false, ""},
		{"psk=Sup3rS3cret!", false, ""},
		{"Site-A password: hunter2", false, ""},
		{"api_KEY = abc", false, ""},
		{"keyring-profile", true, ""},
		{"Café VPN", true, ""},
	})
}

func TestSanitize_OnReceipt(t *testing.T) {
	meta := map[string]interface{}{
		KeyVPNPeerAddress: "0.0.0.0",           // placeholder: removed
		KeyIKEVersion:     "ikev2",             // normalised
		KeyMACAddress:     "F0:9F:C2:AA:BB:CC", // normalised
		KeySSHBanner:      42.0,                // wrong type: removed
		KeyConfigName:     "ok",
		"cipher_suite":    "TLS_AES_128_GCM_SHA256", // not ours: untouched
		"serial_number":   "untouched-here",         // not ours: untouched
	}
	removed := Sanitize(meta)
	sort.Strings(removed)
	if strings.Join(removed, ",") != KeySSHBanner+","+KeyVPNPeerAddress {
		t.Errorf("removed = %v", removed)
	}
	if meta[KeyIKEVersion] != "IKEv2" || meta[KeyMACAddress] != "f0:9f:c2:aa:bb:cc" || meta[KeyConfigName] != "ok" {
		t.Errorf("normalisation lost: %#v", meta)
	}
	if meta["cipher_suite"] != "TLS_AES_128_GCM_SHA256" || meta["serial_number"] != "untouched-here" {
		t.Errorf("Sanitize touched a key outside the allowlist: %#v", meta)
	}
	if _, ok := meta[KeyVPNPeerAddress]; ok {
		t.Error("an invalid peer survived Sanitize")
	}
}
