package services

// The cloud-KMS → `keys` mapping, function by function. Every case here is a
// DECISION about what a provider's word means in inventory's vocabulary, and
// the ones that are load-bearing are the ones where the honest answer is
// "nothing": an unrecognised lifecycle state, an algorithm the catalogue has no
// row for, a spec that carries no size. Those must stay empty rather than fall
// back to something plausible.

import (
	"strings"
	"testing"
)

func TestCloudKeyCustody(t *testing.T) {
	cases := map[string]string{
		"CUSTOMER":   "customer",
		"customer":   "customer",
		" Customer ": "customer",
		"AWS":        "provider",
		"aws":        "provider",
		// Not a manager we recognise → NOT a guess. "" is written as NULL, and
		// the lens renders no custody badge at all.
		"":              "",
		"SOMETHING NEW": "",
	}
	for in, want := range cases {
		if got := CloudKeyCustody(in); got != want {
			t.Errorf("CloudKeyCustody(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCloudKeyType(t *testing.T) {
	cases := []struct{ spec, usage, want string }{
		{"SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "AES"},
		{"RSA_2048", "SIGN_VERIFY", "RSA"},
		{"ECC_NIST_P256", "SIGN_VERIFY", "ECDSA"},
		// The same curve used for key agreement is a different algorithm.
		{"ECC_NIST_P256", "KEY_AGREEMENT", "ECDH"},
		{"HMAC_384", "GENERATE_VERIFY_MAC", "HMAC"},
		{"ML_DSA_65", "SIGN_VERIFY", "ML-DSA"},
		{"", "", "unknown"},
	}
	for _, c := range cases {
		if got := cloudKeyType(c.spec, c.usage); got != c.want {
			t.Errorf("cloudKeyType(%q, %q) = %q, want %q", c.spec, c.usage, got, c.want)
		}
	}
}

func TestCloudKeySizeAndCurve(t *testing.T) {
	cases := []struct {
		spec  string
		size  int
		curve string
	}{
		{"SYMMETRIC_DEFAULT", 256, ""},
		{"RSA_2048", 2048, ""},
		{"RSA_3072", 3072, ""},
		{"RSA_4096", 4096, ""},
		{"ECC_NIST_P256", 256, "P-256"},
		{"ECC_NIST_P384", 384, "P-384"},
		{"ECC_NIST_P521", 521, "P-521"},
		{"ECC_SECG_P256K1", 256, "secp256k1"},
		{"HMAC_512", 512, ""},
		// No size in the spec → 0, written as NULL. An unknown modulus is not a
		// modulus of zero.
		{"SM2", 0, ""},
		{"", 0, ""},
	}
	for _, c := range cases {
		if got := cloudKeySize(c.spec); got != c.size {
			t.Errorf("cloudKeySize(%q) = %d, want %d", c.spec, got, c.size)
		}
		if got := cloudKeyCurve(c.spec); got != c.curve {
			t.Errorf("cloudKeyCurve(%q) = %q, want %q", c.spec, got, c.curve)
		}
	}
}

func TestCloudKeyMaterialType(t *testing.T) {
	cases := map[string]string{
		"SYMMETRIC_DEFAULT": "secret-key",
		"HMAC_256":          "secret-key",
		"RSA_4096":          "private-key",
		"ECC_NIST_P384":     "private-key",
		"":                  "key",
	}
	// Every value must be one the valid_material_type CHECK admits.
	allowed := map[string]bool{"secret-key": true, "private-key": true, "key": true}
	for spec, want := range cases {
		got := cloudKeyMaterialType(spec)
		if got != want {
			t.Errorf("cloudKeyMaterialType(%q) = %q, want %q", spec, got, want)
		}
		if !allowed[got] {
			t.Errorf("cloudKeyMaterialType(%q) = %q, which is not a CycloneDX material type the schema admits", spec, got)
		}
	}
}

func TestCloudKeyState(t *testing.T) {
	cases := map[string]string{
		"Creating":               "pre-activation",
		"PendingImport":          "pre-activation",
		"Enabled":                "active",
		"Updating":               "active",
		"Disabled":               "suspended",
		"Unavailable":            "suspended",
		"PendingDeletion":        "deactivated",
		"PendingReplicaDeletion": "deactivated",
		"DESTROY_SCHEDULED":      "deactivated",
		"PENDING_GENERATION":     "pre-activation",
		"IMPORT_FAILED":          "",
		// The honest default. An unrecognised state must NOT read as active:
		// that would be a live-key claim nobody made.
		"SomethingNew": "",
		"":             "",
	}
	valid := map[string]bool{
		"pre-activation": true, "active": true, "suspended": true,
		"deactivated": true, "compromised": true, "destroyed": true, "": true,
	}
	for in, want := range cases {
		got := cloudKeyState(in)
		if got != want {
			t.Errorf("cloudKeyState(%q) = %q, want %q", in, got, want)
		}
		if !valid[got] {
			t.Errorf("cloudKeyState(%q) = %q, which the valid_key_state CHECK would reject", in, got)
		}
	}
}

// The catalogue is the single source of crypto assessment, so algorithm_id must
// resolve to a row that is ABOUT this key — or to nothing at all.
func TestCloudKeyAlgorithmCode(t *testing.T) {
	cases := []struct{ spec, usage, want string }{
		{"SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "AES256"},
		{"RSA_2048", "ENCRYPT_DECRYPT", "RSA-2048"},
		{"RSA_3072", "SIGN_VERIFY", "RSA-3072"},
		{"RSA_4096", "SIGN_VERIFY", "RSA-4096"},
		{"ECC_NIST_P384", "SIGN_VERIFY", "ECDSA"},
		{"ECC_NIST_P384", "KEY_AGREEMENT", "ECDH"},
		{"ML_DSA_44", "SIGN_VERIFY", "ML-DSA-44"},
		// Deliberate misses. The catalogue's hmac-sha2-* rows are SSH MAC
		// negotiation algorithms, not an assessment of a standalone HMAC key,
		// and there is no SM2 row at all. An unresolved key is honestly
		// unscored; a borrowed row is a wrong answer stated confidently.
		{"HMAC_256", "GENERATE_VERIFY_MAC", ""},
		{"SM2", "SIGN_VERIFY", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := CloudKeyAlgorithmCode(c.spec, c.usage); got != c.want {
			t.Errorf("CloudKeyAlgorithmCode(%q, %q) = %q, want %q", c.spec, c.usage, got, c.want)
		}
	}
	// The bare `RSA` catalogue row is "RSA key transport (static)" — a TLS
	// key-exchange assessment, not an assessment of an RSA key. Resolving to it
	// would rate every RSA CMK at that row's risk whatever its modulus, which is
	// the same mis-resolution fixed on the certificate path.
	for _, spec := range []string{"RSA", "RSA_UNKNOWN"} {
		if got := CloudKeyAlgorithmCode(spec, "SIGN_VERIFY"); got == "RSA" {
			t.Errorf("CloudKeyAlgorithmCode(%q) resolved to the bare RSA key-transport row", spec)
		}
	}
}

func TestCloudKeyFunctions(t *testing.T) {
	cases := map[string][]string{
		"ENCRYPT_DECRYPT":     {"encrypt", "decrypt"},
		"SIGN_VERIFY":         {"sign", "verify"},
		"GENERATE_VERIFY_MAC": {"tag", "verify"},
		"KEY_AGREEMENT":       {"keyderive"},
		"ASYMMETRIC_SIGN":     {"sign", "verify"},
		"ASYMMETRIC_DECRYPT":  {"decrypt"},
		"MAC":                 {"tag", "verify"},
		"wrapKey":             {"encrypt"},
		"":                    nil,
		"something-new":       nil,
	}
	for in, want := range cases {
		got := cloudKeyFunctions(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("cloudKeyFunctions(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCloudKeyExternalRef(t *testing.T) {
	if got := cloudKeyExternalRef(CloudKeyRecord{KeyARN: "arn:x", KeyID: "k"}); got != "arn:x" {
		t.Errorf("external ref = %q, want the ARN when present", got)
	}
	if got := cloudKeyExternalRef(CloudKeyRecord{KeyID: "k"}); got != "k" {
		t.Errorf("external ref = %q, want the key id as fallback", got)
	}
	if got := cloudKeyExternalRef(CloudKeyRecord{}); got != "" {
		t.Errorf("external ref = %q, want empty when the provider named nothing", got)
	}
}

func TestCloudKeySecuredBy(t *testing.T) {
	cases := []struct{ provider, origin, want string }{
		{"aws", "AWS_CLOUDHSM", "AWS CloudHSM key store"},
		{"aws", "EXTERNAL", "Imported key material"},
		{"aws", "AWS_KMS", "AWS KMS"},
		{"azure", "", "Azure Key Vault"},
		{"gcp", "", "Google Cloud KMS"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := cloudKeySecuredBy(c.provider, c.origin); got != c.want {
			t.Errorf("cloudKeySecuredBy(%q, %q) = %q, want %q", c.provider, c.origin, got, c.want)
		}
	}
}
