package capture

import "testing"

func TestIsEnergyRelevantPort(t *testing.T) {
	t.Parallel()
	cases := []struct {
		port int
		want bool
	}{
		{102, true},   // MMS / ICCP
		{443, true},   // HTTPS HMI
		{4712, true},  // CIM
		{8443, true},  // alt-HTTPS
		{20000, true}, // DNP3/TLS
		{22, false},
		{80, false},
		{502, false}, // Modbus is not TLS — never IEC 62351
		{0, false},
	}
	for _, c := range cases {
		if got := IsEnergyRelevantPort(c.port); got != c.want {
			t.Errorf("IsEnergyRelevantPort(%d)=%v, want %v", c.port, got, c.want)
		}
	}
}

func TestIsTLSVersionCompliantIEC62351(t *testing.T) {
	t.Parallel()
	cases := []struct {
		version string
		want    bool
	}{
		{"TLS 1.3", true},
		{"TLS 1.2", true},
		{"TLS 1.1", false},
		{"TLS 1.0", false},
		{"SSL 3.0", false},
		{"", false},
		{"unknown", false},
	}
	for _, c := range cases {
		if got := IsTLSVersionCompliantIEC62351(c.version); got != c.want {
			t.Errorf("IsTLSVersionCompliantIEC62351(%q)=%v, want %v", c.version, got, c.want)
		}
	}
}

func TestIsCipherSuiteCompliantIEC62351(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cipher string
		want   bool
	}{
		// TLS 1.3 — all compliant by protocol design
		{"TLS_AES_128_GCM_SHA256", true},
		{"TLS_AES_256_GCM_SHA384", true},
		{"TLS_CHACHA20_POLY1305_SHA256", true},

		// Compliant TLS 1.2 — ECDHE/DHE + AES-GCM or ChaCha20-Poly1305
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", true},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", true},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", true},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", true},
		{"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", true},
		{"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", true},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", true},
		{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", true},

		// Non-compliant: no forward secrecy (static RSA key exchange)
		{"TLS_RSA_WITH_AES_128_GCM_SHA256", false},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", false},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", false},

		// Non-compliant: CBC mode (not AEAD), even with ECDHE
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", false},
		{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", false},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", false},

		// Non-compliant: banned primitives
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", false},
		{"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", false},
		{"TLS_RSA_WITH_RC4_128_SHA", false},
		{"TLS_RSA_WITH_RC4_128_MD5", false},
		{"TLS_NULL_WITH_NULL_NULL", false},
		{"TLS_DH_anon_WITH_AES_128_CBC_SHA", false},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", false},
		{"TLS_RSA_WITH_DES_CBC_SHA", false},

		// Edge cases
		{"", false},
		{"Unknown-0xC02F", false},
		{"NotARealCipher", false},
	}
	for _, c := range cases {
		if got := IsCipherSuiteCompliantIEC62351(c.cipher); got != c.want {
			t.Errorf("IsCipherSuiteCompliantIEC62351(%q)=%v, want %v", c.cipher, got, c.want)
		}
	}
}

func TestIsCertificateKeyCompliantIEC62351(t *testing.T) {
	t.Parallel()
	cases := []struct {
		alg  string
		bits int
		want bool
	}{
		{"RSA", 4096, true},
		{"RSA", 3072, true},
		{"RSA", 2048, true},
		{"RSA", 1024, false},
		{"RSA", 512, false},
		{"ECDSA", 384, true},  // P-384
		{"ECDSA", 256, true},  // P-256
		{"ECDSA", 224, true},  // boundary
		{"ECDSA", 192, false}, // P-192
		{"Ed25519", 256, true},
		{"DSA", 2048, false}, // not in profile
		{"", 4096, false},
		{"RSA", 0, false},
		{"rsa", 2048, true}, // case-insensitive
	}
	for _, c := range cases {
		if got := IsCertificateKeyCompliantIEC62351(c.alg, c.bits); got != c.want {
			t.Errorf("IsCertificateKeyCompliantIEC62351(%q,%d)=%v, want %v", c.alg, c.bits, got, c.want)
		}
	}
}

func TestClassifyIEC62351_NotApplicable(t *testing.T) {
	t.Parallel()
	if r := ClassifyIEC62351(22, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "RSA", 2048); r != nil {
		t.Errorf("expected nil for non-energy port 22, got %+v", r)
	}
	if r := ClassifyIEC62351(80, "TLS 1.2", "", "", 0); r != nil {
		t.Errorf("expected nil for non-energy port 80, got %+v", r)
	}
}

func TestClassifyIEC62351_FullyCompliant(t *testing.T) {
	t.Parallel()
	r := ClassifyIEC62351(102, "TLS 1.3", "TLS_AES_256_GCM_SHA384", "ECDSA", 256)
	if r == nil {
		t.Fatal("expected non-nil result for energy port")
	}
	if !r.Applicable || !r.TLSVersionOK || !r.CipherOK || !r.CertOK || !r.Overall {
		t.Errorf("expected fully compliant, got %+v", r)
	}
	if r.NonComplianceCode != "" {
		t.Errorf("expected empty NonComplianceCode for compliant result, got %q", r.NonComplianceCode)
	}
}

func TestClassifyIEC62351_NonCompliantCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		port       int
		version    string
		cipher     string
		keyAlg     string
		keyBits    int
		wantOAll   bool
		wantCode   string
		wantVerOK  bool
		wantCipOK  bool
		wantCertOK bool
	}{
		{
			name: "weak cipher only",
			port: 20000, version: "TLS 1.2", cipher: "TLS_RSA_WITH_AES_128_CBC_SHA",
			keyAlg: "RSA", keyBits: 2048,
			wantOAll: false, wantCode: "cipher",
			wantVerOK: true, wantCipOK: false, wantCertOK: true,
		},
		{
			name: "weak version only",
			port: 102, version: "TLS 1.0", cipher: "TLS_AES_128_GCM_SHA256",
			keyAlg: "RSA", keyBits: 2048,
			wantOAll: false, wantCode: "version",
			wantVerOK: false, wantCipOK: true, wantCertOK: true,
		},
		{
			name: "weak cert only",
			port: 443, version: "TLS 1.3", cipher: "TLS_AES_128_GCM_SHA256",
			keyAlg: "RSA", keyBits: 1024,
			wantOAll: false, wantCode: "cert",
			wantVerOK: true, wantCipOK: true, wantCertOK: false,
		},
		{
			name: "all three failing",
			port: 8443, version: "SSL 3.0", cipher: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			keyAlg: "RSA", keyBits: 512,
			wantOAll: false, wantCode: "version+cipher+cert",
			wantVerOK: false, wantCipOK: false, wantCertOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ClassifyIEC62351(c.port, c.version, c.cipher, c.keyAlg, c.keyBits)
			if r == nil {
				t.Fatal("expected non-nil result")
			}
			if r.Overall != c.wantOAll {
				t.Errorf("Overall=%v, want %v", r.Overall, c.wantOAll)
			}
			if r.NonComplianceCode != c.wantCode {
				t.Errorf("NonComplianceCode=%q, want %q", r.NonComplianceCode, c.wantCode)
			}
			if r.TLSVersionOK != c.wantVerOK {
				t.Errorf("TLSVersionOK=%v, want %v", r.TLSVersionOK, c.wantVerOK)
			}
			if r.CipherOK != c.wantCipOK {
				t.Errorf("CipherOK=%v, want %v", r.CipherOK, c.wantCipOK)
			}
			if r.CertOK != c.wantCertOK {
				t.Errorf("CertOK=%v, want %v", r.CertOK, c.wantCertOK)
			}
		})
	}
}

func TestIEC62351Result_ToMetadata_Nil(t *testing.T) {
	t.Parallel()
	var r *IEC62351Result
	m := r.ToMetadata()
	if len(m) != 0 {
		t.Errorf("expected empty map for nil result, got %v", m)
	}
}

func TestIEC62351Result_ToMetadata_Compliant(t *testing.T) {
	t.Parallel()
	r := ClassifyIEC62351(102, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "RSA", 2048)
	m := r.ToMetadata()
	if m["iec62351_applicable"] != true {
		t.Errorf("expected iec62351_applicable=true, got %v", m["iec62351_applicable"])
	}
	if m["iec62351_overall"] != true {
		t.Errorf("expected iec62351_overall=true, got %v", m["iec62351_overall"])
	}
	if _, present := m["iec62351_noncompliance"]; present {
		t.Errorf("expected iec62351_noncompliance to be absent for compliant result, got %v", m["iec62351_noncompliance"])
	}
}

func TestIEC62351Result_ToMetadata_NonCompliant(t *testing.T) {
	t.Parallel()
	r := ClassifyIEC62351(102, "TLS 1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", 1024)
	m := r.ToMetadata()
	if m["iec62351_overall"] != false {
		t.Errorf("expected iec62351_overall=false, got %v", m["iec62351_overall"])
	}
	if m["iec62351_noncompliance"] != "version+cipher+cert" {
		t.Errorf("expected noncompliance=version+cipher+cert, got %v", m["iec62351_noncompliance"])
	}
}
