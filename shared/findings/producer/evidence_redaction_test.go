package producer

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// The findings evidence rail's redaction backstop (security review X.5, X5-06).
//
// `findings.evidence` is a jsonb the UI renders and the remediator seam reads,
// and Writer.Upsert used to write it verbatim. Every other rail in this
// codebase has a backstop — Registry.Get wraps each interrogator in Sanitize,
// the host-inventory intake re-sanitises, the AI boundary redacts — and this is
// the single chokepoint for six producers written by parallel agents. Nothing
// leaks through it today; a backstop is for the producer nobody has written yet.
//
// Both polarities matter here more than usual, because the obvious fix is
// WRONG: redact.Map would apply IsSecretName, whose catch-all is
// `HasSuffix(name, "key")`, and the drift producer's evidence carries
// `observation_key` — the finding's own identity, the value a re-run matches on.
// Masking it would break that producer silently.
//
// To mutation-test: (a) drop the redactEvidence call from marshalEvidence and
// the first test fails; (b) swap redact.IsExplicitSecretName for
// redact.IsSecretName and the must-survive test fails on observation_key and
// class_key.

func TestMarshalEvidence_MasksNamedCredentialsAndPEM(t *testing.T) {
	// The shapes a future producer plausibly writes by mistake. None of these
	// keys is written by any producer today, which is the point.
	evidence := map[string]any{
		"password":       "hunter2",
		"api_key":        "sk-live-000",
		"snmp_community": "public",
		"auth":           "Basic aGk6dGhlcmU=",
		"nested": map[string]any{
			"client_secret": "s3cr3t",
			"port":          443,
		},
		"list": []any{
			map[string]any{"token": "abc123"},
			"plain",
		},
		// A private key pasted into an innocently named field — the case the
		// name rules cannot catch and TextPEM can.
		"banner": "SSH-2.0-x\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\ntrailing",
	}

	raw, err := marshalEvidence(evidence)
	if err != nil {
		t.Fatalf("marshalEvidence: %v", err)
	}
	got := string(raw)

	for _, secret := range []string{"hunter2", "sk-live-000", "public", "aGk6dGhlcmU=", "s3cr3t", "abc123", "MIIabc"} {
		if strings.Contains(got, secret) {
			t.Errorf("%q reached findings.evidence: %s", secret, got)
		}
	}
	// The text AROUND a PEM block survives: TextPEM masks the block, not the
	// field, and a banner is posture.
	if !strings.Contains(got, "SSH-2.0-x") || !strings.Contains(got, "trailing") {
		t.Errorf("TextPEM ate the text around the block, which is posture: %s", got)
	}
	// A non-secret value beside a secret one is untouched.
	if !strings.Contains(got, "443") {
		t.Errorf("a port was lost: %s", got)
	}
	if !strings.Contains(got, `"plain"`) {
		t.Errorf("a plain list element was lost: %s", got)
	}
}

// The over-strict polarity, and the one this design exists for: every key the
// producers actually write must survive, byte for byte.
//
// The fixtures are the real key sets, taken from the six producers in this
// repository (crypto, configuration, hygiene, eol, vulnerability, drift) plus
// the compliance rail. `observation_key` and `class_key` are the two that end
// in "key"; they are the finding's own identity, not material.
func TestMarshalEvidence_LeavesEveryProducersOwnEvidenceAlone(t *testing.T) {
	fixtures := map[string]map[string]any{
		"drift: new_class_in_segment": {
			"observation_key":              "segment:1e9/class:printer",
			"asset_id":                     "11111111-1111-4111-8111-111111111111",
			"segment_id":                   "22222222-2222-4222-8222-222222222222",
			"segment_name":                 "Campus VLAN 20",
			"baseline":                     map[string]any{"classes_in_segment": []any{"server", "workstation"}},
			"observed":                     map[string]any{"class": "printer", "first_observed_at": "2026-09-01T00:00:00Z"},
			"assets_in_window":             3,
			"segment_assets_before_window": 41,
		},
		"drift: new_issuer": {
			"observation_key":     "issuer:CN=Some CA",
			"asset_id":            "11111111-1111-4111-8111-111111111111",
			"baseline":            map[string]any{"issuers": []any{"CN=Old CA"}},
			"observed":            map[string]any{"issuer_dn": "CN=Some CA", "fingerprint_sha256": "ab12"},
			"first_observed_at":   "2026-09-01T00:00:00Z",
			"key_algorithm":       "RSA",
			"signature_algorithm": "SHA256-RSA",
		},
		"eol": {
			"catalogue_id":          "eol-1",
			"catalogue_source_url":  "https://endoflife.date/ubuntu",
			"catalogue_product":     "ubuntu",
			"catalogue_cycle":       "20.04",
			"catalogue_vendor":      "Canonical",
			"product_kind":          "os",
			"eol_date":              "2025-05-31",
			"extended_support_date": "2030-04-30",
			"days_remaining":        -30,
			"observed_product":      "Ubuntu",
			"observed_version":      "20.04.6",
		},
		"vulnerability": {
			"cve_id":          "CVE-2026-0001",
			"cve_count":       2,
			"cves":            []any{"CVE-2026-0001", "CVE-2026-0002"},
			"matched_cpe":     "cpe:2.3:a:openssl:openssl:3.0.0",
			"matched_purl":    "pkg:generic/openssl@3.0.0",
			"matched_product": "openssl",
			"matched_version": "3.0.0",
			"install_id":      "33333333-3333-4333-8333-333333333333",
			"source_id":       "nvd",
			"fixed":           "3.0.8",
			"introduced":      "3.0.0",
			"range":           ">=3.0.0 <3.0.8",
		},
		"configuration": {
			"protocol":             "SSH",
			"protocols":            []any{"SSH", "TELNET"},
			"transport":            "tcp",
			"port":                 22,
			"ports":                []any{22, 23},
			"service":              "ssh",
			"presence":             "observed",
			"detail":               "telnet is reachable",
			"fact_keys":            []any{"mgmt.plaintext", "mgmt.protocol"},
			"matched_by":           "fact",
			"cipher_suite":         "TLS_AES_128_GCM_SHA256",
			"key_size":             2048,
			"public_key_algorithm": "ECDSA",
		},
		"hygiene": {
			"owner_email_present":   false,
			"support_group_present": false,
			"location_present":      false,
			"site_present":          false,
			"region_present":        false,
			"surviving_asset_id":    "44444444-4444-4444-8444-444444444444",
			"other_asset_ids":       []any{"55555555-5555-4555-8555-555555555555"},
			"missing_asset_id":      "66666666-6666-4666-8666-666666666666",
			"missing_asset_label":   "web01",
			"missing_reason":        "archived",
			"relationship_type":     "runs_on",
		},
		"class proposal / crypto": {
			"class_key":          "hardware.computer.server",
			"class_label":        "Server",
			"rule_id":            "rule-7",
			"proposal_id":        "77777777-7777-4777-8777-777777777777",
			"risk_factors":       []any{"weak_cipher"},
			"stored_score":       70,
			"threshold":          60,
			"certificate_id":     "88888888-8888-4888-8888-888888888888",
			"fingerprint_sha256": "cd34",
			"days_unseen":        45,
		},
	}

	// The SIZE backstop's over-strict polarity, in the same test because it is
	// the same claim: a producer's own evidence reaches the database unchanged.
	// A host presenting a full chain per endpoint is ordinary, not pathological,
	// and must pass through untouched — the cap is for the four-hundred-
	// certificate load balancer, not for this.
	// A LITERAL count, not maxEvidenceListItems: a fixture that scaled with the
	// constant would pass at any cap, including one lowered below what real
	// producers write. Forty entries is a plausible chain-per-endpoint host.
	bigCerts := make([]any, 0, 40)
	for i := 0; i < 40; i++ {
		bigCerts = append(bigCerts, map[string]any{
			"certificate_id":     fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", i),
			"fingerprint_sha256": fmt.Sprintf("%064x", i),
		})
	}
	fixtures["drift: new_issuer, a whole chain per endpoint (at the cap)"] = map[string]any{
		"observation_key": "issuer:CN=Some CA",
		"asset_id":        "11111111-1111-4111-8111-111111111111",
		"observed":        map[string]any{"certificates": bigCerts},
	}

	for name, evidence := range fixtures {
		t.Run(name, func(t *testing.T) {
			want, err := json.Marshal(evidence)
			if err != nil {
				t.Fatalf("marshalling the fixture: %v", err)
			}
			got, err := marshalEvidence(evidence)
			if err != nil {
				t.Fatalf("marshalEvidence: %v", err)
			}
			// Compare decoded, so map ordering is not what is being asserted.
			var a, b any
			if err := json.Unmarshal(want, &a); err != nil {
				t.Fatalf("decode want: %v", err)
			}
			if err := json.Unmarshal(got, &b); err != nil {
				t.Fatalf("decode got: %v", err)
			}
			wantJSON, _ := json.Marshal(a)
			gotJSON, _ := json.Marshal(b)
			if string(wantJSON) != string(gotJSON) {
				t.Errorf("the backstop changed a producer's own evidence.\n want %s\n  got %s", wantJSON, gotJSON)
			}
			if strings.Contains(string(gotJSON), redact.Marker) {
				t.Errorf("%s: something was masked that a producer writes on purpose: %s", name, gotJSON)
			}
		})
	}
}

// The empty case is unchanged: `{}` and never SQL NULL, because the upsert
// merges `evidence || EXCLUDED.evidence` and NULL on either side erases the
// whole document.
func TestMarshalEvidence_EmptyStaysAnEmptyObject(t *testing.T) {
	for name, in := range map[string]map[string]any{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := marshalEvidence(in)
			if err != nil {
				t.Fatalf("marshalEvidence: %v", err)
			}
			if string(raw) != "{}" {
				t.Fatalf("got %s, want {}", raw)
			}
		})
	}
}
