package services

// Every inventory rule that substring-matched a stored cipher value, driven
// with a cipher STRING (P-05), and every key-size rule driven with a symmetric
// key length (P-06). One test per site, so deleting the fix at any one site
// fails here rather than being masked by the others.

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

const hardenedF5 = "ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5"

func implWithCipher(cipher string) *models.CryptoImplementation {
	c := cipher
	return &models.CryptoImplementation{ID: uuid.New(), Protocol: "TLS", CipherSuite: &c}
}

// Site 1: WeakCryptoDetector.AnalyzeCryptoImplementation, cipher-suite rules.
func TestWeakCryptoDetector_CipherStringExclusionsAreNotIssues(t *testing.T) {
	d := NewWeakCryptoDetector(nil)
	for _, cipher := range []string{
		hardenedF5,
		"DEFAULT:!SSLv3:!RC4",
		"!SSLv3:!RC4:!EXP:!DES",
		"ECDHE:RSA:!SSLV3:!RC4:!EXP:!DES", // F5 f5-secure
		"AES256-SHA:!3DES:DES-CBC3-SHA",   // "!" is permanent
		"ECDHE-RSA-AES256-GCM-SHA384:!aNULL:!eNULL:!EXPORT:!MD5:!SHA1",
	} {
		if issues := d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), implWithCipher(cipher)); len(issues) > 0 {
			t.Errorf("%q: excluded tokens reported as weak crypto: %+v", cipher, issues)
		}
	}

	// A suite the string really enables is still caught, at the same
	// severities a plain suite name gets.
	issues := d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), implWithCipher("ECDHE-RSA-AES256-GCM-SHA384:DES-CBC3-SHA:!RC4"))
	if len(issues) != 1 || issues[0].IssueType != "deprecated_cipher" || issues[0].Severity != SeverityHigh {
		t.Fatalf("enabled 3DES suite: want one high deprecated_cipher issue, got %+v", issues)
	}
	issues = d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), implWithCipher("AES128-SHA:RC4-SHA"))
	if len(issues) == 0 || issues[0].Severity != SeverityCritical {
		t.Fatalf("enabled RC4 suite: want a critical issue, got %+v", issues)
	}
	// Single DES is still told apart from 3DES inside a resolved list.
	issues = d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), implWithCipher("DES-CBC3-SHA:DES-CBC-SHA"))
	if len(issues) == 0 || issues[0].IssueType != "weak_cipher" {
		t.Fatalf("enabled single-DES suite beside 3DES: want a critical weak_cipher, got %+v", issues)
	}
	// Plain suite names behave exactly as before.
	issues = d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), implWithCipher("TLS_RSA_WITH_RC4_128_SHA"))
	if len(issues) == 0 || issues[0].Severity != SeverityCritical {
		t.Fatalf("plain RC4 suite name: want a critical issue, got %+v", issues)
	}
}

// Site 2: AssetService.AnalyzeCryptoRisk, the per-configuration risk factors.
func TestAnalyzeCryptoRisk_CipherStringExclusionsAreNotWeakCiphers(t *testing.T) {
	s := &AssetService{}
	if f := s.AnalyzeCryptoRisk(implWithCipher(hardenedF5)); slices.Contains(f, "Weak cipher suite") {
		t.Errorf("hardened profile reported a weak cipher: %v", f)
	}
	if f := s.AnalyzeCryptoRisk(implWithCipher("AES256-SHA:RC4-SHA")); !slices.Contains(f, "Weak cipher suite") {
		t.Errorf("an enabled RC4 suite must still be reported: %v", f)
	}
}

// P-06, AnalyzeCryptoRisk: the <2048 rule applies to asymmetric keys only.
func TestAnalyzeCryptoRisk_KeySizeRuleIsAsymmetricOnly(t *testing.T) {
	s := &AssetService{}
	str := func(v string) *string { return &v }
	num := func(v int) *int { return &v }
	cases := []struct {
		name   string
		impl   models.CryptoImplementation
		expect bool
	}{
		// The symmetric component is the stored column, as ingest writes it.
		{"IPsec AES-256, no key exchange", models.CryptoImplementation{Protocol: "IPSec", CipherSuite: str("aes256-sha256"), SymmetricEncryption: str("AES256"), KeySize: num(256)}, false},
		{"IPsec AES-256 beside a DH group", models.CryptoImplementation{Protocol: "IPSec", CipherSuite: str("ESP-AES-256"), SymmetricEncryption: str("AES256"), KeyExchangeAlgorithm: str("DH Group 14"), KeySize: num(256)}, false},
		{"IPsec AES-192 beside MODP group 14", models.CryptoImplementation{Protocol: "IPSec", CipherSuite: str("aes192-sha256"), KeyExchangeAlgorithm: str("DH Group 14"), KeySize: num(192)}, false},
		{"IPsec AES-192 beside ECP group 25", models.CryptoImplementation{Protocol: "IPSec", CipherSuite: str("aes192-sha256"), KeyExchangeAlgorithm: str("DH Group 25"), KeySize: num(192)}, true},
		{"WireGuard", models.CryptoImplementation{Protocol: "WireGuard", CipherSuite: str("ChaCha20-Poly1305"), SymmetricEncryption: str("CHACHA20"), KeyExchangeAlgorithm: str("Curve25519"), KeySize: num(256)}, false},
		{"TLS with a P-256 key", models.CryptoImplementation{Protocol: "TLS", CipherSuite: str("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), KeyExchangeAlgorithm: str("ECDHE"), KeySize: num(256)}, false},
		{"RSA-1024", models.CryptoImplementation{Protocol: "TLS", CipherSuite: str("TLS_RSA_WITH_AES_256_CBC_SHA"), KeyExchangeAlgorithm: str("RSA"), KeySize: num(1024)}, true},
		{"DH-1024", models.CryptoImplementation{Protocol: "TLS", CipherSuite: str("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"), KeyExchangeAlgorithm: str("DHE"), KeySize: num(1024)}, true},
	}
	for _, tc := range cases {
		got := slices.Contains(s.AnalyzeCryptoRisk(&tc.impl), "Weak key size")
		if got != tc.expect {
			t.Errorf("%s: Weak key size = %v, want %v", tc.name, got, tc.expect)
		}
	}
}

// P-06, WeakCryptoDetector: Cisco's IKEv2 SA puts "DH Group 14" beside an
// AES-256 transform; the 256 is the cipher's key, not a DH modulus.
func TestWeakCryptoDetector_SymmetricKeySizeIsNotAWeakKey(t *testing.T) {
	d := NewWeakCryptoDetector(nil)
	str := func(v string) *string { return &v }
	num := func(v int) *int { return &v }
	ipsec := &models.CryptoImplementation{ID: uuid.New(), Protocol: "IPSec", CipherSuite: str("ESP-AES-256"), SymmetricEncryption: str("AES256"), KeyExchangeAlgorithm: str("DH Group 14"), KeySize: num(256)}
	for _, issue := range d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), ipsec) {
		if issue.Category == CategoryKeySize {
			t.Errorf("AES-256 key length flagged as a weak key: %+v", issue)
		}
	}
	rsa := &models.CryptoImplementation{ID: uuid.New(), Protocol: "TLS", CipherSuite: str("TLS_RSA_WITH_AES_256_CBC_SHA"), KeyExchangeAlgorithm: str("RSA"), KeySize: num(1024)}
	found := false
	for _, issue := range d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), rsa) {
		found = found || issue.Category == CategoryKeySize
	}
	if !found {
		t.Error("RSA-1024 must still be flagged")
	}
}

// P-06, the crypto-risk judgment (Crypto Risks list and the `crypto` producer).
func TestConfigurationJudge_SymmetricKeySizeIsNotAWeakKey(t *testing.T) {
	ipsec := cryptoassess.Configuration{Suite: "ESP-AES-256", Symmetric: "AES256", KeyAlgorithm: "DH Group 14", KeyBits: 256}
	for _, r := range ipsec.Judge().Rules {
		if r.Rule == "key_size" {
			t.Errorf("AES-256 over DH group 14 judged a weak key: %+v", r)
		}
	}
	symmetricOnly := cryptoassess.Configuration{Symmetric: "AES256", KeyAlgorithm: "DH", KeyBits: 256}
	for _, r := range symmetricOnly.Judge().Rules {
		if r.Rule == "key_size" {
			t.Errorf("AES256 symmetric column: judged a weak key: %+v", r)
		}
	}
	rsa := cryptoassess.Configuration{Suite: "TLS_RSA_WITH_AES_256_CBC_SHA", KeyAlgorithm: "RSA", KeyBits: 1024}
	if !slices.ContainsFunc(rsa.Judge().Rules, func(r cryptoassess.Rule) bool { return r.Rule == "key_size" }) {
		t.Error("RSA-1024 must still fail the key-size rule")
	}
}

// B1 (review of): a cipher string the parser cannot resolve still
// exposes what it names, and reads as partially assessed — never as clean.
func TestAnalyzeCryptoRisk_UnresolvedCipherStringIsNotSafe(t *testing.T) {
	s := &AssetService{}
	for _, tc := range []struct {
		cipher  string
		weak    bool
		partial bool
	}{
		{"HIGH:MEDIUM:RC4", true, true},        // RC4 keyword addition
		{"RC4-SHA:-HIGH", true, true},          // RC4-SHA may survive -HIGH
		{"EXP-RC4-MD5:AES128-SHA", true, true}, // suite outside the table
		{"ALL:!aNULL", false, true},            // unknown, not clean
		{"DEFAULT", false, true},
		{"DEFAULT:!RC4", false, true}, // excluded never counts
		{"ECDHE-RSA-AES256-GCM-SHA384:!RC4", false, false},
	} {
		factors := s.AnalyzeCryptoRisk(implWithCipher(tc.cipher))
		if got := slices.Contains(factors, "Weak cipher suite"); got != tc.weak {
			t.Errorf("%q: weak cipher = %v, want %v (%v)", tc.cipher, got, tc.weak, factors)
		}
		partial := slices.ContainsFunc(factors, func(f string) bool { return strings.HasPrefix(f, "Partially assessed") })
		if partial != tc.partial {
			t.Errorf("%q: partially assessed = %v, want %v (%v)", tc.cipher, partial, tc.partial, factors)
		}
	}
}

func TestWeakCryptoDetector_UnresolvedCipherStringIsNotSafe(t *testing.T) {
	d := NewWeakCryptoDetector(nil)
	for cipher, want := range map[string]WeakCryptoSeverity{
		"HIGH:MEDIUM:RC4":        SeverityCritical,
		"RC4-SHA:-HIGH":          SeverityCritical,
		"EXP-RC4-MD5:AES128-SHA": SeverityCritical,
		// Weak classes, bare or inside a string (second review, B2).
		"HIGH:EXP":                        SeverityCritical,
		"ECDHE-RSA-AES256-GCM-SHA384:EXP": SeverityCritical,
		"EXP":                             SeverityCritical,
		"HIGH:LOW":                        SeverityCritical,
		"LOW":                             SeverityCritical,
	} {
		issues := d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), implWithCipher(cipher))
		if len(issues) == 0 || issues[0].Severity != want {
			t.Errorf("%q: want a %s issue, got %+v", cipher, want, issues)
		}
	}
	for _, cipher := range []string{"ALL:!aNULL", "DEFAULT:!RC4", "RC4:!RC4", "!RC4:RC4",
		"EXP:!EXP", "HIGH:!EXPORT:EXP", "HIGH:LOW:!LOW", "aNULL:!aNULL", "eNULL:!NULL"} {
		if issues := d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), implWithCipher(cipher)); len(issues) > 0 {
			t.Errorf("%q: nothing names a weak cipher in use, got %+v", cipher, issues)
		}
	}
}

func TestConfigurationJudge_PartialCipherStringIsALimitation(t *testing.T) {
	for suite, want := range map[string]bool{
		"ALL:!aNULL":                            true,
		"DEFAULT":                               true,
		"ECDHE-RSA-AES256-GCM-SHA384:!RC4":      false,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": false,
	} {
		j := cryptoassess.Configuration{Suite: suite}.Judge()
		got := slices.ContainsFunc(j.Limitations, func(l string) bool { return strings.Contains(l, "partially assessed") })
		if got != want {
			t.Errorf("%q: partial limitation = %v, want %v (%v)", suite, got, want, j.Limitations)
		}
	}
}
