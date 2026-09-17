package services

// Proof that certificate hygiene (CT logging, chain trust) does not
// masquerade as cryptographic weakness on external_connections.
//
// The confirmed defect: a tenant's dashboard reported 24 "weak crypto"
// third-party connections. Every one was TLS 1.3 / TLS_AES_256_GCM_SHA384 to a
// trusted endpoint with a valid chain — the ONLY weak_reasons entry was a
// missing Signed Certificate Timestamp. CT logging says nothing about
// protocol version, cipher suite, key exchange, key size or signature
// algorithm (what crypto_strength must reflect — CLAUDE.md "Crypto Assessment
// Source of Truth"), so assessCrypto must not fold it (or an untrusted/pinned
// CA, or an incomplete chain) into weak_reasons/crypto_strength. Those flags
// still need to be recorded — assessCertHygiene routes them to
// hygieneFlags/CertHygieneFlags instead.
//
// This needs the real `algorithms` catalogue (the whole-cipher-suite lookup
// path in assessCrypto queries it), so it's a DB-integration test — skips
// without TEST_DATABASE_URL (nightly test-backend / make test-integration-db).
// See DB_INTEGRATION_TESTS.md.

import (
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newAssessCryptoFixture(t *testing.T) *ExternalConnectionsService {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	algorithms := NewAlgorithmService(db)
	return NewExternalConnectionsService(db, algorithms)
}

func containsSubstr(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// TestIntegration_AssessCrypto_SCTMissingIsHygieneNotWeak is the exact
// production defect: TLS 1.3 + TLS_AES_256_GCM_SHA384 (catalogue: recommended
// / current) with no SCT observed must classify "strong", with the SCT note
// living in hygieneFlags — never in weakReasons, which would drag
// crypto_strength down to "weak" for a connection with nothing cryptographically
// wrong with it.
func TestIntegration_AssessCrypto_SCTMissingIsHygieneNotWeak(t *testing.T) {
	t.Parallel()
	svc := newAssessCryptoFixture(t)

	input := models.ExternalConnectionUpsert{
		Protocol:             "TLS",
		ProtocolVersion:      strPtr("1.3"),
		CipherSuite:          strPtr("TLS_AES_256_GCM_SHA384"),
		KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(256),
		CertHasSCT: boolPtr(false),
	}

	strength, _, _, weakReasons, hygieneFlags := svc.assessCrypto(input)

	if strength != "strong" {
		t.Fatalf("crypto_strength = %q, want %q (weakReasons=%v hygieneFlags=%v)", strength, "strong", weakReasons, hygieneFlags)
	}
	if containsSubstr(weakReasons, "SCT") {
		t.Fatalf("weakReasons must not mention SCTs (that's certificate hygiene, not crypto weakness), got %v", weakReasons)
	}
	if !containsSubstr(hygieneFlags, "SCT") {
		t.Fatalf("hygieneFlags must record the missing-SCT observation, got %v", hygieneFlags)
	}
}

// TestIntegration_AssessCrypto_UntrustedCAIsHygieneNotWeak covers the second
// named example from the defect report: a service that pins its own CA (e.g.
// Signal) validates as cert_validation_status="untrusted_ca" even over a
// strong TLS 1.3 connection — that's chain-trust hygiene, not weak crypto.
func TestIntegration_AssessCrypto_UntrustedCAIsHygieneNotWeak(t *testing.T) {
	t.Parallel()
	svc := newAssessCryptoFixture(t)

	input := models.ExternalConnectionUpsert{
		Protocol:             "TLS",
		ProtocolVersion:      strPtr("1.3"),
		CipherSuite:          strPtr("TLS_AES_256_GCM_SHA384"),
		KeyExchangeAlgorithm: strPtr("ECDHE"), KeySize: intPtr(256),
		CertValidationStatus: strPtr("untrusted_ca"),
	}

	strength, _, _, weakReasons, hygieneFlags := svc.assessCrypto(input)

	if strength != "strong" {
		t.Fatalf("crypto_strength = %q, want %q (weakReasons=%v hygieneFlags=%v)", strength, "strong", weakReasons, hygieneFlags)
	}
	if containsSubstr(weakReasons, "untrusted") {
		t.Fatalf("weakReasons must not mention an untrusted/pinned CA, got %v", weakReasons)
	}
	if !containsSubstr(hygieneFlags, "untrusted") {
		t.Fatalf("hygieneFlags must record the untrusted-CA observation, got %v", hygieneFlags)
	}
}

// TestIntegration_AssessCrypto_WeakCipherSuiteStillWeak is the control: a
// genuinely weak cipher suite (RC4, catalogue: weak/obsolete) must still
// classify "weak" — the hygiene split must not have widened into a blanket
// "certs never count" bug.
func TestIntegration_AssessCrypto_WeakCipherSuiteStillWeak(t *testing.T) {
	t.Parallel()
	svc := newAssessCryptoFixture(t)

	input := models.ExternalConnectionUpsert{
		Protocol:        "TLS",
		ProtocolVersion: strPtr("1.2"),
		CipherSuite:     strPtr("TLS_RSA_WITH_RC4_128_SHA"),
	}

	strength, _, _, weakReasons, _ := svc.assessCrypto(input)

	if strength != "weak" {
		t.Fatalf("crypto_strength = %q, want %q for RC4 (weakReasons=%v)", strength, "weak", weakReasons)
	}
	if len(weakReasons) == 0 {
		t.Fatal("expected at least one weak reason for RC4")
	}
}

// TestIntegration_AssessCrypto_WeakCertKeySizeStillWeak: a "recommended"
// cipher suite paired with an undersized certificate key must still classify
// "weak" — cert key size is a real cryptographic weakness the algorithms
// catalogue rates, unlike hygiene.
func TestIntegration_AssessCrypto_WeakCertKeySizeStillWeak(t *testing.T) {
	t.Parallel()
	svc := newAssessCryptoFixture(t)

	input := models.ExternalConnectionUpsert{
		Protocol:               "TLS",
		ProtocolVersion:        strPtr("1.3"),
		CipherSuite:            strPtr("TLS_AES_256_GCM_SHA384"),
		CertPublicKeyAlgorithm: strPtr("RSA"),
		CertPublicKeySize:      intPtr(1024),
	}

	strength, _, _, weakReasons, _ := svc.assessCrypto(input)

	if strength != "weak" {
		t.Fatalf("crypto_strength = %q, want %q for an RSA-1024 certificate (weakReasons=%v)", strength, "weak", weakReasons)
	}
	if !containsSubstr(weakReasons, "1024") {
		t.Fatalf("expected a weakReason naming the undersized key, got %v", weakReasons)
	}
}
