package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// ADR-0008 D4.5: "Every prompt and every tool result crossing the provider
// boundary passes through the same redactor the interrogators use. Key
// material, credentials, and the fields that redactor names cannot reach a
// model. Tests for this are mutation-tested like the redactor's."
//
// This is that test, stated at the boundary rather than at the interrogator.
// The fixture is deliberately NOT a device response: it is the shape a prompt
// context actually has — a tenant integration's stored config, a webhook sink,
// an uploaded key, and the crypto posture the model is being asked about. A
// prompt is an exfiltration path, and it is one that leaves no trace on the
// device that owned the secret.
//
// To mutation-test it: delete one fragment from secretNameFragments in
// redact.go (say "psk"), run this file, and confirm the corresponding case
// fails. Restore. A guard that cannot fail is worse than no guard.
func TestProviderBoundary_SecretsRedactedPostureSurvives(t *testing.T) {
	const (
		password   = "s3rvice-acct-Pa55w0rd"
		psk        = "76cb7a67a0650c263bd78635193fc1b2"
		apiToken   = "EXAMPLE-api-token-9f8e7d6c5b4a"
		webhookURL = "https://hooks.example.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXX"
		privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----"
	)

	// The context a Narrator or Query seam would be handed about one asset.
	promptContext := map[string]any{
		// --- secrets: none of these may cross the boundary ---
		"admin_password": password,
		"ipsec": map[string]any{
			"pre_shared_key": psk,
			"psksecret":      psk, // FortiOS phase1-interface spells it this way
		},
		"integration": map[string]any{
			"api_token":   apiToken,
			"webhook_url": webhookURL,
			"auth":        "Basic YWRtaW46aHVudGVyMg==",
		},
		"ssh": []any{
			map[string]any{
				"comment":     "deploy@build01",
				"private_key": privateKey,
			},
		},

		// --- posture: all of this is the question being asked ---
		"cipher_suite":     "TLS_AES_256_GCM_SHA384",
		"key_size":         2048,
		"protocol_version": "TLSv1.2",
		"key_algorithm":    "RSA",
		"public_key":       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
		"authmethod":       "publickey",
		"host_key_type":    "ssh-ed25519",
	}

	out := Map(promptContext)

	// Nothing secret survives anywhere in the serialized payload. Checking the
	// serialization rather than individual keys is what catches a value that
	// slipped through at a nesting depth the assertions did not enumerate.
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for name, leaked := range map[string]string{
		"password":         password,
		"pre-shared key":   psk,
		"API token":        apiToken,
		"webhook URL":      webhookURL,
		"SSH private key":  privateKey,
		"basic auth value": "YWRtaW46aHVudGVyMg==",
	} {
		if strings.Contains(string(blob), leaked) {
			t.Errorf("%s crossed the provider boundary: %s", name, blob)
		}
	}

	// The inverse polarity. A boundary that redacts the posture fields has
	// destroyed the question along with the answer, and would do it silently.
	posture := map[string]any{
		"cipher_suite":     "TLS_AES_256_GCM_SHA384",
		"key_size":         2048,
		"protocol_version": "TLSv1.2",
		"key_algorithm":    "RSA",
		"public_key":       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
		"authmethod":       "publickey",
		"host_key_type":    "ssh-ed25519",
	}
	for field, want := range posture {
		if got := out[field]; got != want {
			t.Errorf("posture field %q was altered at the boundary: got %#v, want %#v", field, got, want)
		}
	}
}

// The same rule as a table, one field name per row, so a regression names the
// exact field that moved rather than "something in the fixture".
func TestProviderBoundary_FieldByField(t *testing.T) {
	cases := []struct {
		field  string
		secret bool
		why    string
	}{
		{"admin_password", true, "credential"},
		{"password", true, "credential"},
		{"pre_shared_key", true, "IPsec PSK"},
		{"psksecret", true, "FortiOS phase1-interface PSK"},
		{"x_mesh_psk", true, "UniFi controller mesh PSK"},
		{"api_token", true, "integration API token"},
		{"apiKey", true, "integration API key, camelCase"},
		{"webhook_url", true, "the credential is inside the URL"},
		{"slack_webhook", true, "the credential is inside the URL"},
		{"authorization", true, "header value: Bearer …/Basic …"},
		{"auth", true, "bare auth block, whole-name match"},
		{"community", true, "SNMP v1/v2c community string — the whole credential"},
		{"snmp_community", true, "SNMP community, vendor-prefixed"},
		{"read_community", true, "SNMP read community"},
		{"trap-community", true, "SNMP trap community, hyphenated"},
		{"community_string", true, "SNMP community, spelled out"},
		{"communityString", true, "SNMP community, camelCase"},
		{"private_key", true, "key material"},
		{"private-key", true, "key material, FortiOS spelling"},
		{"client_secret", true, "OAuth client secret"},
		{"session_key", true, "key material"},
		// The two SNMP spellings the gate-4 rows above do not name. X.5 reached
		// the same finding by a different route and proposed a bare `community`
		// FRAGMENT; the suffix rule shipped instead, because Azure returns
		// communityGalleryImageId. These rows are what is left of that finding.
		{"ro_community", true, "SNMP read-only community"},
		{"rw_community", true, "SNMP read-write community"},
		{"passcode", true, "a password by another name"},
		{"pin", true, "a device PIN, whole-name match"},

		{"cipher_suite", false, "posture: the negotiated suite"},
		{"key_size", false, "posture: SP 800-131A floors are checked on this"},
		{"key_length", false, "posture"},
		{"protocol_version", false, "posture: isWeakProtocol reads this"},
		{"key_algorithm", false, "posture"},
		{"key_exchange", false, "posture"},
		{"public_key", false, "posture: a public key is publishable by definition"},
		{"public_key_algorithm", false, "posture"},
		{"authmethod", false, "posture: SSH auth method, not a credential"},
		{"authentication_algorithm", false, "posture"},
		{"host_key_type", false, "posture"},
		{"host_key_fingerprint", false, "posture: a fingerprint is not the key"},
		{"fingerprint_sha256", false, "posture"},
		{"not_after", false, "posture: certificate validity"},
		{"serial", false, "identity"},
		// The inverse polarity for the names above. `snmp_version` is what we
		// actually inventory about SNMP — v1/v2c is the plaintext-management
		// finding — and `pinning`/`pinned_certificate` are posture whose names
		// merely contain "pin".
		{"snmp_version", false, "posture: v1/v2c is what plaintext_management reads"},
		{"pinning", false, "posture: certificate pinning, not a PIN"},
		{"pinned_certificate", false, "posture: a pinned cert is publishable"},
		{"communityGalleryImageId", false, "posture: an Azure image id, not a credential — the suffix rule must not eat it"},
		{"community_gallery_image_id", false, "posture: the same id, folded"},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			in := map[string]any{tc.field: "fixture-value"}
			got := Map(in)[tc.field]

			if tc.secret && got != Marker {
				t.Errorf("%s (%s) crossed the boundary unredacted: %v", tc.field, tc.why, got)
			}
			if !tc.secret && got != "fixture-value" {
				t.Errorf("%s (%s) was redacted; the boundary is over-strict: %v", tc.field, tc.why, got)
			}
		})
	}
}
