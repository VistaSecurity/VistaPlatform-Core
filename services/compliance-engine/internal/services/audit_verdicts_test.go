package services

// Pure-logic tests for the compliance VERDICT layer — the findings of the
// Core audit, WP-A. Each of these pins a rule that produced a
// confident wrong answer: a predicate that could not match what the producers
// emit, an evaluator branch that could not distinguish compliant from
// non-compliant, or a severity that was invented rather than read.
//
// The seeded predicates are MIRRORED here as fixtures rather than re-typed from
// memory, and TestSeededPredicatesAreTheOnesInSeedSQL asserts each fixture
// string appears verbatim in scripts/database/seed.sql. Without that assertion
// these tests would happily prove things about regexes the product does not
// ship.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The predicate patterns seeded into control_measurements. Kept as raw Go
// strings in the shape the evaluator receives them (i.e. after SQL/JSON
// unescaping): seed.sql writes `\\.` inside a SQL string literal, which reaches
// jsonb as `\.`.
const (
	// BP-003 / BP-010, measurement `symmetric_encryption`.
	seedWeakCipherPattern = `^(3DES|DES|RC4)(-[A-Z0-9]+)*$`
	// BP-009, measurement `key_exchange_algorithm`.
	seedNonPFSKexPattern = `^(RSA|NULL|ECDH(_[A-Z0-9]+)*|DH(_[A-Z0-9]+)*)$`
	// BP-001 / BP-006, measurement `tls_version`.
	seedDeprecatedProtocolPattern = `^(TLS.?1\.0|TLS.?1\.1|1\.0|1\.1|SSL.?[23](\.0)?|Unknown-0x0300|Unknown-0x0002)$`
)

// patternPredicate builds the predicate map the seed stores alongside each of
// the patterns above: case-insensitive, match means violation.
func patternPredicate(pattern string) map[string]interface{} {
	return map[string]interface{}{
		"pattern":               pattern,
		"flags":                 "i",
		"match_means_violation": true,
	}
}

// assertPattern runs `value` through evaluatePattern and checks the verdict.
// wantViolation is stated from the product's point of view; evaluatePattern
// returns "passed", so the assertion inverts.
func assertPattern(t *testing.T, pattern, value string, wantViolation bool) {
	t.Helper()
	ev := &RuleEvaluator{}
	passed := ev.evaluatePattern(MeasurementValue{Value: value}, patternPredicate(pattern))
	if passed == wantViolation {
		verdict := "passed"
		if !passed {
			verdict = "flagged"
		}
		t.Errorf("value %q %s; want violation=%v", value, verdict, wantViolation)
	}
}

// ---------------------------------------------------------------------------
// CMP-1 — boolean measurements in presence rules
// ---------------------------------------------------------------------------

// A boolean measurement IS its own presence signal. Before the fix, the
// evaluator asked `v != nil && v != ""`, which is true for both `true` and
// `false`, so BP-004 (PFS) and BP-007 (chain valid) returned the same verdict
// for every asset in the inventory — the two polarities below were
// indistinguishable.
func TestEvaluatePresence_BooleanMeasurementIsItsOwnPresenceSignal(t *testing.T) {
	ev := &RuleEvaluator{}
	mustExist := map[string]interface{}{"exists": true}
	mustBeAbsent := map[string]interface{}{"exists": false}

	cases := []struct {
		name       string
		value      interface{}
		predicate  map[string]interface{}
		wantPassed bool
	}{
		// BP-004: PFS must be supported. ECDHE endpoint -> pfs_support=true.
		{"ECDHE endpoint passes BP-004", true, mustExist, true},
		// Static-RSA endpoint -> pfs_support=false.
		{"static-RSA endpoint fails BP-004", false, mustExist, false},
		// BP-007: certificate chain must be valid.
		{"valid chain passes BP-007", true, mustExist, true},
		{"self-signed / invalid chain fails BP-007", false, mustExist, false},

		// The inverse polarity still works, for predicates that genuinely want
		// a property to be absent (e.g. tls_compression_enabled).
		{"compression disabled passes an exists:false rule", false, mustBeAbsent, true},
		{"compression enabled fails an exists:false rule", true, mustBeAbsent, false},

		// Non-boolean values keep their previous meaning.
		{"non-empty string is present", "TLS 1.3", mustExist, true},
		{"empty string is absent", "", mustExist, false},
		{"nil is absent", nil, mustExist, false},
		{"zero int is still a recorded value", 0, mustExist, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ev.evaluatePresence(MeasurementValue{Value: tc.value}, tc.predicate)
			if got != tc.wantPassed {
				t.Errorf("evaluatePresence(%v, %v) = %v, want %v", tc.value, tc.predicate, got, tc.wantPassed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CMP-3 — seeded predicates vs producer vocabulary
// ---------------------------------------------------------------------------

// Weak symmetric ciphers. Values come from BOTH producer vocabularies: the
// catalogue codes every cipher-suite parser normalises to, and the suffixed
// forms that reach the column from OpenSSL-style names.
func TestSeededWeakCipherPattern(t *testing.T) {
	violating := []string{
		"3DES", "DES", "RC4", // catalogue codes
		"3des", "rc4", // resolved case-insensitively
		"3DES-EDE-CBC", "DES-CBC", "RC4-128", // suffixed forms
	}
	compliant := []string{
		"AES128", "AES256", "CHACHA20", // catalogue codes
		"aes256", "AES-256-GCM", "AES-128-CBC", "CHACHA20-POLY1305",
	}

	for _, v := range violating {
		assertPattern(t, seedWeakCipherPattern, v, true)
	}
	for _, v := range compliant {
		assertPattern(t, seedWeakCipherPattern, v, false)
	}
}

// Non-PFS key exchange. The whole point of BP-009 is the STATIC suites, and the
// old `^(RSA|ECDH|DH|NULL)$` matched none of the compound forms the passive
// sensor emits (sensor/internal/crypto/key_exchange.go) — while the ephemeral
// forms it must NOT flag differ from the static ones by a single letter.
func TestSeededNonPFSKeyExchangePattern(t *testing.T) {
	violating := []string{
		"RSA", "NULL", "ECDH", "DH", // catalogue codes
		"ECDH_RSA", "ECDH_ECDSA", "DH_RSA", "DH_DSS", "DH_ANON", // sensor compound forms
		"ecdh_rsa", "dh_dss", // case-insensitive
	}
	compliant := []string{
		"ECDHE", "DHE", // catalogue codes with forward secrecy
		"ECDHE_RSA", "ECDHE_ECDSA", "DHE_RSA", "DHE_DSS", // sensor compound forms
		"ecdhe_rsa", "dhe_rsa",
	}

	for _, v := range violating {
		assertPattern(t, seedNonPFSKexPattern, v, true)
	}
	for _, v := range compliant {
		assertPattern(t, seedNonPFSKexPattern, v, false)
	}
}

// ---------------------------------------------------------------------------
// CMP-5 — SSLv3 reaches the inventory under names the pattern never had
// ---------------------------------------------------------------------------

func TestSeededDeprecatedProtocolPattern(t *testing.T) {
	violating := []string{
		"TLS 1.0", "TLS1.0", "TLSv1.0", "1.0",
		"TLS 1.1", "TLS1.1", "TLSv1.1", "1.1",
		// SSLv3/SSLv2 — including the spelling the sensor's TLS enricher
		// produces for a version crypto/tls has no name for, which is how
		// SSLv3 actually arrives.
		"SSLv3", "SSL3", "SSL 3.0", "SSLv2", "SSL2", "SSL 2.0",
		"Unknown-0x0300", "Unknown-0x0002", "unknown-0x0300",
	}
	compliant := []string{
		"TLS 1.2", "TLS1.2", "TLSv1.2", "1.2",
		"TLS 1.3", "TLS1.3", "TLSv1.3", "1.3",
		"Unknown-0x0304", // TLS 1.3 under an unrecognised codepoint
	}

	for _, v := range violating {
		assertPattern(t, seedDeprecatedProtocolPattern, v, true)
	}
	for _, v := range compliant {
		assertPattern(t, seedDeprecatedProtocolPattern, v, false)
	}
}

// The fixtures above are only meaningful if they are the predicates the product
// actually seeds. seed.sql escapes backslashes for the SQL string literal, so
// the comparison is made against the file's escaped form.
func TestSeededPredicatesAreTheOnesInSeedSQL(t *testing.T) {
	seedPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql")
	body, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read seed.sql: %v", err)
	}
	seed := string(body)

	for _, pattern := range []string{
		seedWeakCipherPattern,
		seedNonPFSKexPattern,
		seedDeprecatedProtocolPattern,
	} {
		escaped := strings.ReplaceAll(pattern, `\`, `\\`)
		if !strings.Contains(seed, `"pattern": "`+escaped+`"`) {
			t.Errorf("scripts/database/seed.sql does not seed the pattern this test pins:\n  %s", pattern)
		}
	}

	// CMP-1: the corrected presence predicates. `exists` states the PASS
	// condition, so both boolean controls must require the property to exist.
	// The inverted literal may appear EXACTLY once — in the WHERE clause of the
	// re-runnable correction that repairs already-seeded deployments. Anywhere
	// else (i.e. an INSERT) means the inversion is still being shipped.
	const inverted = `'{"exists": false, "match_means_violation": true}'`
	if n := strings.Count(seed, inverted); n != 1 {
		t.Errorf("seed.sql mentions the inverted boolean presence predicate %d times, want exactly 1 (the corrections WHERE clause) — CMP-1", n)
	}
	if !strings.Contains(seed, `cm.predicate = `+inverted+`::jsonb`) {
		t.Error("seed.sql has no re-runnable correction repairing the inverted presence predicate on existing deployments (CMP-1)")
	}
}

// ---------------------------------------------------------------------------
// CMP-4 — key size means different things per algorithm family
// ---------------------------------------------------------------------------

func TestKeySizeFamily(t *testing.T) {
	cases := map[string]string{
		// Finite field: the 2048-bit floor applies.
		"RSA":            keyFamilyFiniteField,
		"rsaEncryption":  keyFamilyFiniteField,
		"RSASSA-PSS":     keyFamilyFiniteField,
		"DSA":            keyFamilyFiniteField,
		"DH":             keyFamilyFiniteField,
		"Diffie-Hellman": keyFamilyFiniteField,

		// Elliptic curve: 256 bits is 128-bit security, ABOVE the RSA-2048 floor.
		// ECDSA must be classified here despite containing the substring "DSA".
		"ECDSA":           keyFamilyEllipticCurve,
		"ecdsa":           keyFamilyEllipticCurve,
		"EC":              keyFamilyEllipticCurve,
		"id-ecPublicKey":  keyFamilyEllipticCurve,
		"Ed25519":         keyFamilyEllipticCurve,
		"ED448":           keyFamilyEllipticCurve,
		"EdDSA":           keyFamilyEllipticCurve,
		"X25519":          keyFamilyEllipticCurve,
		"prime256v1":      keyFamilyEllipticCurve,
		"secp384r1":       keyFamilyEllipticCurve,
		"brainpoolP256r1": keyFamilyEllipticCurve,

		// Not classifiable -> NOT ASSESSED rather than judged against a floor
		// that may not apply.
		"":            keyFamilyUnknown,
		"ML-DSA-65":   keyFamilyUnknown,
		"who-knows":   keyFamilyUnknown,
		"unspecified": keyFamilyUnknown,
	}

	for algorithm, want := range cases {
		if got := keySizeFamily(algorithm); got != want {
			t.Errorf("keySizeFamily(%q) = %q, want %q", algorithm, got, want)
		}
	}
}

// The verdict the split produces: a P-256 certificate must pass its family's
// floor, and an RSA-1024 certificate must fail its own.
func TestKeySizeThresholdsPerFamily(t *testing.T) {
	ev := &RuleEvaluator{}
	rsaFloor := map[string]interface{}{"operator": ">=", "value": float64(2048)}
	ecFloor := map[string]interface{}{"operator": ">=", "value": float64(256)}

	if !ev.evaluateThreshold(MeasurementValue{Value: 256}, ecFloor) {
		t.Error("a P-256 certificate must satisfy the elliptic-curve key-size floor")
	}
	if ev.evaluateThreshold(MeasurementValue{Value: 256}, rsaFloor) {
		t.Error("guard: 256 must NOT satisfy the RSA floor — that is why the measurements are split")
	}
	if ev.evaluateThreshold(MeasurementValue{Value: 1024}, rsaFloor) {
		t.Error("an RSA-1024 certificate must fail the finite-field key-size floor")
	}
	if !ev.evaluateThreshold(MeasurementValue{Value: 2048}, rsaFloor) {
		t.Error("an RSA-2048 certificate must satisfy the finite-field key-size floor")
	}
}

// ---------------------------------------------------------------------------
// CMP-8 — predicate flags and inversion were parsed but never read
// ---------------------------------------------------------------------------

func TestEvaluatePattern_HonoursFlagsAndMatchMeansViolation(t *testing.T) {
	ev := &RuleEvaluator{}

	t.Run("flags i makes the match case-insensitive", func(t *testing.T) {
		p := map[string]interface{}{"pattern": "^rc4$", "flags": "i", "match_means_violation": true}
		if ev.evaluatePattern(MeasurementValue{Value: "RC4"}, p) {
			t.Error("RC4 passed a case-insensitive ^rc4$ rule")
		}
	})

	t.Run("without flags the match stays case-sensitive", func(t *testing.T) {
		p := map[string]interface{}{"pattern": "^rc4$", "match_means_violation": true}
		if !ev.evaluatePattern(MeasurementValue{Value: "RC4"}, p) {
			t.Error("RC4 was flagged by a case-SENSITIVE ^rc4$ rule")
		}
	})

	t.Run("match_means_violation false inverts the rule", func(t *testing.T) {
		// The pattern now describes the REQUIRED shape.
		p := map[string]interface{}{"pattern": "^TLS ?1\\.[23]$", "match_means_violation": false}
		if !ev.evaluatePattern(MeasurementValue{Value: "TLS 1.3"}, p) {
			t.Error("TLS 1.3 should satisfy a required-shape rule")
		}
		if ev.evaluatePattern(MeasurementValue{Value: "TLS 1.0"}, p) {
			t.Error("TLS 1.0 should violate a required-shape rule")
		}
	})

	t.Run("absent match_means_violation defaults to true", func(t *testing.T) {
		p := map[string]interface{}{"pattern": "^TLS 1\\.0$"}
		if ev.evaluatePattern(MeasurementValue{Value: "TLS 1.0"}, p) {
			t.Error("a match must be a violation by default")
		}
	})
}

// ---------------------------------------------------------------------------
// CMP-9 — measurement severity fell back to a literal, not the control
// ---------------------------------------------------------------------------

func TestEvaluateMeasurement_SeverityFallsBackToControlBaseline(t *testing.T) {
	ev := &RuleEvaluator{}
	// A rule that produces a violation, so the severity is the one a finding
	// would carry.
	measurement := models.ControlMeasurement{
		RuleType:  "pattern",
		Predicate: patternPredicate("^TLS 1\\.0$"),
	}
	value := MeasurementValue{Value: "TLS 1.0"}
	mt := models.MeasurementType{Code: "tls_version"}

	t.Run("baseline is used when no override is set", func(t *testing.T) {
		passed, severity := ev.evaluateMeasurement(value, measurement, mt, "Critical")
		if passed {
			t.Fatal("fixture should produce a violation")
		}
		if severity != "Critical" {
			t.Errorf("severity = %q, want the control's baseline Critical (not the literal Med)", severity)
		}
	})

	t.Run("severity_override still wins", func(t *testing.T) {
		overridden := measurement
		overridden.SeverityOverride = "Low"
		_, severity := ev.evaluateMeasurement(value, overridden, mt, "Critical")
		if severity != "Low" {
			t.Errorf("severity = %q, want the measurement override Low", severity)
		}
	})

	t.Run("Med remains the last resort", func(t *testing.T) {
		_, severity := ev.evaluateMeasurement(value, measurement, mt, "")
		if severity != "Med" {
			t.Errorf("severity = %q, want Med when the control carries no baseline either", severity)
		}
	})
}

// ---------------------------------------------------------------------------
// CMP-7 / — the live path's status rule must BE the materialized one
// ---------------------------------------------------------------------------

// Status is decided by whether the control was VIOLATED, at every baseline
// severity. This replaces the severity-derived mapping (Critical/High → FAIL,
// Med → WARN, Low → PASS), under which a violated Low-baseline control reported
// PASS and its findings were invisible to the score.
//
// The live evaluator lowercases its Status by contract (callers ToUpper it), so
// the lowering is pinned here too.
func TestLiveControlStatusIsDrivenByViolationsNotSeverity(t *testing.T) {
	if got := strings.ToLower(statusForFindings(false)); got != "pass" {
		t.Errorf("no findings maps to %q, want pass", got)
	}
	if got := strings.ToLower(statusForFindings(true)); got != "fail" {
		t.Errorf("a violation maps to %q, want fail", got)
	}

	// The regression itself: severity no longer participates. A control whose
	// only finding is Low must FAIL exactly as a Critical one does.
	for _, severity := range []string{"Low", "Med", "High", "Critical"} {
		b := frameworkScore([]controlOutcome{{BaselineSeverity: severity, Status: statusForFindings(true)}})
		if b.Score == nil {
			t.Errorf("baseline %s: a violated control has no score; it was assessed and it failed", severity)
		} else if *b.Score != 0 {
			t.Errorf("baseline %s: a violated control scored %d, want 0 — severity is the weight, not the verdict", severity, *b.Score)
		}
		if b.Failing != 1 || b.Passing != 0 {
			t.Errorf("baseline %s: counts = {passing:%d failing:%d}, want {0 1}", severity, b.Passing, b.Failing)
		}
	}
}
