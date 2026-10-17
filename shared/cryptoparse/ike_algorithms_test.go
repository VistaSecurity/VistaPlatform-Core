package cryptoparse

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCanonicalIKEEncryption(t *testing.T) {
	cases := map[string][2]string{
		"aes256":      {"aes-256-cbc", "ENCR-AES-CBC-256"},
		"AES-256-CBC": {"aes-256-cbc", "ENCR-AES-CBC-256"},
		"aes128gcm16": {"aes-128-gcm", "ENCR-AES-GCM-128"},
		"esp-3des":    {"3des-cbc", "ENCR-3DES"},
		"3des":        {"3des-cbc", "ENCR-3DES"},
		"des":         {"des-cbc", "ENCR-DES"},
		"camellia256": {"camellia256", ""},
		"":            {"", ""},
	}
	for in, want := range cases {
		n, c := CanonicalIKEEncryption(in)
		if n != want[0] || c != want[1] {
			t.Errorf("CanonicalIKEEncryption(%q) = %q,%q; want %q,%q", in, n, c, want[0], want[1])
		}
	}
}

func TestCanonicalIKEIntegrity(t *testing.T) {
	cases := map[string][2]string{
		"sha1":            {"hmac-sha1", "AUTH-HMAC-SHA1-96"},
		"esp-sha256-hmac": {"hmac-sha256", "AUTH-HMAC-SHA2-256-128"},
		"md5":             {"hmac-md5", "AUTH-HMAC-MD5-96"},
		"hmac-sha512":     {"hmac-sha512", "AUTH-HMAC-SHA2-512-256"},
		"whirlpool":       {"whirlpool", ""},
	}
	for in, want := range cases {
		n, c := CanonicalIKEIntegrity(in)
		if n != want[0] || c != want[1] {
			t.Errorf("CanonicalIKEIntegrity(%q) = %q,%q; want %q,%q", in, n, c, want[0], want[1])
		}
	}
}

func TestParseIKETransformPairs(t *testing.T) {
	got := ParseIKETransformPairs("aes256-sha256 aes128gcm-prfsha256 3des-md5 aes256-sha256 bogus-sha1 aes-256-cbc")
	want := []IKETransformPair{
		{Encryption: "aes-256-cbc", Integrity: "hmac-sha256"},
		{Encryption: "aes-128-gcm"},
		{Encryption: "3des-cbc", Integrity: "hmac-md5"},
		{Encryption: "aes-256-cbc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseIKETransformPairs = %#v\nwant %#v", got, want)
	}
}

func TestIKEGroupCode(t *testing.T) {
	if IKEGroupCode(14) != "DH-MODP-2048" || IKEGroupCode(19) != "DH-ECP-256" || IKEGroupCode(33) != "" || IKEGroupCode(999) != "" {
		t.Fatal("IKEGroupCode does not follow the IANA table")
	}
}

// TestIKEAlgorithmCodesAreCatalogued holds every code this file names to a row
// seed.sql inserts: a code with no row would leave the proposal unlinked and
// the tunnel silently unassessed.
func TestIKEAlgorithmCodesAreCatalogued(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "database", "seed.sql")) //nolint:gosec // fixed in-repo path
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, c := range ikeEncryptionCode {
		codes = append(codes, c)
	}
	for _, c := range ikeIntegrityCode {
		codes = append(codes, c)
	}
	for _, c := range codes {
		if !strings.Contains(string(body), "('"+c+"', '") {
			t.Errorf("catalogue code %q is named by ike_algorithms.go but seed.sql inserts no such row", c)
		}
	}
}
