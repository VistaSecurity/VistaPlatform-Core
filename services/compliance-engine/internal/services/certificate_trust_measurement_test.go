package services

// Unit tests for the certificate-trust measurements (feature, slice 3):
// the two transforms that read certificates.trust_status, and the verdicts the
// seeded controls over them reach for every status in the vocabulary.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The predicates seeded for the Certificate Hygiene trust controls. Pinned
// against seed.sql below, so the verdict table tests what actually ships.
const (
	ch003TrustedCAPattern  = "^(untrusted|distrusted)$"
	ch004SelfSignedPattern = "^self_signed$"
)

var allTrustStatuses = []string{"public", "private_trusted", "self_signed", "untrusted", "distrusted", "incomplete"}

func nullText() scannedValue { return scannedValue{kind: scanText} }

func TestTransformTrustOK(t *testing.T) {
	want := map[string]bool{
		"public":          true,
		"private_trusted": true,
		"self_signed":     false,
		"untrusted":       false,
		"distrusted":      false,
		"incomplete":      false,
	}
	if len(want) != len(allTrustStatuses) {
		t.Fatalf("test table covers %d statuses, vocabulary has %d", len(want), len(allTrustStatuses))
	}
	for _, status := range allTrustStatuses {
		got, err := measurementTransforms["trust_ok"](textValue(status))
		if err != nil {
			t.Errorf("trust_ok(%q) error: %v", status, err)
			continue
		}
		if got != want[status] {
			t.Errorf("trust_ok(%q) = %v, want %v", status, got, want[status])
		}
	}
}

// An unevaluated certificate (NULL trust_status) must produce NO measurement —
// not true (the old chain_valid answer for a NULL), and not false either, which
// would raise a BP-007 violation for every certificate the trust pass has not
// reached yet.
func TestTrustTransforms_NullAndUnknownYieldNoMeasurement(t *testing.T) {
	for _, name := range []string{"trust_ok", "trust_status"} {
		for label, v := range map[string]scannedValue{
			"NULL":    nullText(),
			"unknown": textValue("trusted-ish"),
			"empty":   textValue(""),
			"bool":    {kind: scanBool},
		} {
			got, err := measurementTransforms[name](v)
			if !errors.Is(err, errNoMeasurement) {
				t.Errorf("%s(%s) = (%v, %v), want errNoMeasurement", name, label, got, err)
			}
		}
	}
}

func TestTransformTrustStatus_PublishesTheVocabulary(t *testing.T) {
	for _, status := range allTrustStatuses {
		got, err := measurementTransforms["trust_status"](textValue(status))
		if err != nil || got != status {
			t.Errorf("trust_status(%q) = (%v, %v), want (%q, nil)", status, got, err, status)
		}
	}
}

// TestTrustStatusVocabularyMatchesSchema keeps the transforms' vocabulary equal
// to the CHECK constraint on certificates.trust_status. A status added to the
// schema but not here would silently read as "not assessed".
func TestTrustStatusVocabularyMatchesSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "database", "schema.sql"))
	if err != nil {
		t.Fatalf("read schema.sql: %v", err)
	}
	schema := string(raw)
	i := strings.Index(schema, "certificates_trust_status_check")
	if i < 0 {
		t.Fatal("schema.sql has no certificates_trust_status_check")
	}
	check := schema[i:]
	check = check[:strings.Index(check, ";")]
	for _, status := range allTrustStatuses {
		if !strings.Contains(check, "'"+status+"'") {
			t.Errorf("status %q is not in the schema CHECK", status)
		}
	}
	if got := strings.Count(check, "::character varying"); got != len(trustStatusOK) {
		t.Errorf("schema CHECK lists %d statuses, transforms know %d", got, len(trustStatusOK))
	}
}

// TestTrustControlVerdicts runs every status through the seeded predicates:
// CH-003 (issued by a trusted CA), CH-004 (not self-signed) and BP-007 (chain
// valid, a presence rule over trust_ok).
func TestTrustControlVerdicts(t *testing.T) {
	ev := &RuleEvaluator{}
	cases := []struct {
		status                       string
		ch003, ch004, bp007Violation bool
	}{
		{"public", false, false, false},
		{"private_trusted", false, false, false},
		{"self_signed", false, true, true},
		{"untrusted", true, false, true},
		{"distrusted", true, false, true},
		// The issuer is not in inventory: neither trusted nor known to be
		// untrusted. CH-003 does not judge it; BP-007 (chain valid) does.
		{"incomplete", false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			v, err := measurementTransforms["trust_status"](textValue(tc.status))
			if err != nil {
				t.Fatalf("trust_status: %v", err)
			}
			assertPattern(t, ch003TrustedCAPattern, v.(string), tc.ch003)
			assertPattern(t, ch004SelfSignedPattern, v.(string), tc.ch004)
			// Case-insensitive, as seeded.
			assertPattern(t, ch003TrustedCAPattern, strings.ToUpper(v.(string)), tc.ch003)

			ok, err := measurementTransforms["trust_ok"](textValue(tc.status))
			if err != nil {
				t.Fatalf("trust_ok: %v", err)
			}
			passed := ev.evaluatePresence(MeasurementValue{Value: ok}, map[string]interface{}{"exists": true})
			if passed == tc.bp007Violation {
				t.Errorf("BP-007 over trust_ok(%q)=%v passed=%v, want violation=%v", tc.status, ok, passed, tc.bp007Violation)
			}
		})
	}
}

// TestTrustControlsSeeded pins that the predicates the verdict table tests are
// the ones seed.sql ships, on the measurement the controls name.
func TestTrustControlsSeeded(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "database", "seed.sql"))
	if err != nil {
		t.Fatalf("read seed.sql: %v", err)
	}
	seed := string(raw)
	for _, want := range []string{
		`'{"pattern": "` + ch003TrustedCAPattern + `", "flags": "i", "match_means_violation": true}'::jsonb`,
		`'{"pattern": "` + ch004SelfSignedPattern + `", "flags": "i", "match_means_violation": true}'::jsonb`,
		"'CH-003', 'Certificates are issued by a trusted CA'",
		"'CH-004', 'Certificates are not self-signed'",
		"code = 'certificate_trust_status'",
	} {
		if !strings.Contains(seed, want) {
			t.Errorf("seed.sql does not contain %s", want)
		}
	}
	def, ok := MeasurementTypeByCode("certificate_trust_status")
	if !ok {
		t.Fatal("certificate_trust_status is not registered")
	}
	if def.Source.Transform != "trust_status" || def.Source.Value != "trust_status" {
		t.Errorf("certificate_trust_status source = %+v", def.Source)
	}
	chain, _ := MeasurementTypeByCode("certificate_chain_valid")
	if chain.Source.Transform != "trust_ok" || chain.Source.Value != "trust_status" {
		t.Errorf("certificate_chain_valid must read the trust verdict, source = %+v", chain.Source)
	}
}
