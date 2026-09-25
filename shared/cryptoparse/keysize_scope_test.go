package cryptoparse

import "testing"

// P-06: the asymmetric floor must not be applied to a symmetric key length,
// and must still be applied to an asymmetric one. The symmetric component is
// what ingest stores for the cipher (SymmetricComponent), exactly as the rule's
// SQL twin reads it.
func TestConfigurationKeySizeSeverity(t *testing.T) {
	cases := []struct {
		name, kex, cipher string
		bits              int
		want              string
	}{
		// Symmetric sizes, as the collectors report them.
		{"IPsec AES-256, no kex", "", "aes256-sha256", 256, ""},
		{"IPsec AES-256 beside an IKE DH group", "DH Group 14", "ESP-AES-256", 256, ""},
		{"Cisco AES-256-GCM transform", "DH Group 19", "AES-256-GCM", 256, ""},
		{"UniFi AES-128", "DH", "aes128-sha1", 128, ""},
		{"3DES proposal (168)", "DH Group 2", "3des-sha1", 168, ""},
		{"WireGuard", "Curve25519", "ChaCha20-Poly1305", 256, ""},
		{"TLS suite, AES-256", "DHE", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 256, ""},
		{"F5 resolved list sharing AES-256", "DHE", "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256", 256, ""},

		// AES-192 is ambiguous with a 192-bit curve: exempt only beside a
		// finite-field key exchange that names no elliptic-curve group.
		{"AES-192 over MODP group 14", "DH Group 14", "aes192-sha256", 192, ""},
		{"AES-192 over W1.1's MODP code", "DH-MODP-2048", "AES-192-CBC", 192, ""},
		{"AES-192 over ECP group 25 (192-bit curve)", "DH Group 25", "aes192-sha256", 192, SeverityCritical},
		{"AES-192 over W1.1's ECP-192 code", "DH-ECP-192", "aes192-sha256", 192, SeverityHigh},
		{"AES-192 with an unknown key exchange", "", "aes192-sha256", 192, ""},
		{"AES-192 beside ECDHE", "ECDHE", "aes192", 192, SeverityHigh},

		// Asymmetric sizes are still measured.
		{"RSA-1024 behind an AES suite", "RSA", "TLS_RSA_WITH_AES_256_CBC_SHA", 1024, SeverityHigh},
		{"RSA-512", "RSA", "AES128-SHA", 512, SeverityCritical},
		{"RSA-1024, no cipher", "RSA", "", 1024, SeverityHigh},
		{"P-192 certificate with a 3DES suite", "ECDHE", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 192, SeverityHigh},
		{"DH-1024", "DHE", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 1024, SeverityHigh},
		{"size is not the cipher's length", "DH Group 14", "ESP-AES-256", 128, SeverityCritical},
		// An EXCLUDED cipher does not vouch for the size, nor does a list whose
		// enabled suites disagree on it.
		{"excluded AES-256 does not vouch", "DHE", "DHE-RSA-AES128-GCM-SHA256:!AES256", 256, SeverityCritical},
		{"mixed list does not vouch", "DHE", "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256", 256, SeverityCritical},
		{"healthy RSA", "RSA", "AES128-SHA", 2048, ""},
	}
	for _, tc := range cases {
		if got := ConfigurationKeySizeSeverity(tc.kex, SymmetricComponent(tc.cipher), tc.cipher, tc.bits); got != tc.want {
			t.Errorf("%s: ConfigurationKeySizeSeverity(%q, %q, %d) = %q, want %q",
				tc.name, tc.kex, tc.cipher, tc.bits, got, tc.want)
		}
	}
}

// The rule reads the STORED symmetric component and does not re-derive it, so
// a row without one is measured exactly as its SQL twin measures it.
func TestConfigurationKeySizeSeverity_ReadsTheStoredComponentOnly(t *testing.T) {
	if got := ConfigurationKeySizeSeverity("DH Group 14", "", "ESP-AES-256", 256); got != SeverityCritical {
		t.Errorf("no stored symmetric component: got %q, want the asymmetric rule's critical", got)
	}
	if got := ConfigurationKeySizeSeverity("DH Group 14", "AES256", "", 256); got != "" {
		t.Errorf("stored AES256 component: got %q, want exempt", got)
	}
}

// The IKE ECP pattern names exactly the elliptic-curve groups of IANA IKEv2
// Transform Type 4, and not the MODP groups numbered among them.
func TestIKEECPGroupPattern(t *testing.T) {
	for g, ecp := range map[string]bool{
		"DH GROUP 19": true, "DH GROUP 20": true, "DH GROUP 21": true, "GROUP 25": true, "GROUP26": true,
		"GROUP 27": true, "GROUP 30": true, "GROUP 31": true, "GROUP 32": true,
		"DH GROUP 14": false, "DH GROUP 2": false, "DH GROUP 22": false, "DH GROUP 23": false,
		"DH GROUP 24": false, "GROUP 190": false, "GROUP 5": false,
	} {
		if got := ikeGroupIsECP(g); got != ecp {
			t.Errorf("ikeGroupIsECP(%q) = %v, want %v", g, got, ecp)
		}
	}
}
