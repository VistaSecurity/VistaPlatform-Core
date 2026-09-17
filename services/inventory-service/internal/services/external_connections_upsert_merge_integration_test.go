package services

// Proof that a partial re-observation cannot wipe a prior finding out of
// external_connections.weak_reasons / cert_hygiene_flags.
//
// assessCrypto is computed fresh from whatever fields THIS observation
// carries — it has no view of the row's existing state. A passive
// re-observation that can read the cipher suite (so crypto_strength resolves
// away from "unknown") but, say, never saw the certificate (passive capture
// can't always decrypt it) legitimately comes back with an EMPTY
// weak_reasons/cert_hygiene_flags for itself: not because the earlier finding
// stopped being true, but because this observation had nothing to say about
// it. The upsert's ON CONFLICT clause used to key entirely off
// "EXCLUDED.crypto_strength <> 'unknown'" for both columns, so that empty
// array silently overwrote a real prior finding — an active probe's
// ["missing SCT"] erased by the very next passive sighting of the same
// connection. That's the same "empty never wins" rule the discovery
// metadata envelope (CLAUDE.md) and cert_sct_source's COALESCE already
// depend on; weak_reasons/cert_hygiene_flags just hadn't caught up.
//
// Needs the real `algorithms` catalogue — DB-integration test, skips without
// TEST_DATABASE_URL (nightly test-backend / make test-integration-db).

import (
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_ExternalConnectionUpsert_HygieneFlagsSurviveAPartialReobservation
// is the reviewer's exact reported scenario: an active probe records a
// missing-SCT hygiene observation; a later passive re-observation of the SAME
// connection carries a resolvable cipher suite (so crypto_strength updates)
// but no CertHasSCT at all (nil, not false) — it simply didn't see the cert.
// cert_hygiene_flags must still hold the missing-SCT observation afterward.
func TestIntegration_ExternalConnectionUpsert_HygieneFlagsSurviveAPartialReobservation(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	// Observation 1: an active TLS probe. Good cipher suite, but it directly
	// observed the certificate and found no SCT.
	conn1, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:    "192.0.2.70",
		DestIP:      "198.51.100.70",
		DestPort:    443,
		Protocol:    "TLS",
		CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"),
		CertHasSCT:  boolPtr(false),
	})
	if err != nil {
		t.Fatalf("first Upsert (active probe): %v", err)
	}
	if !containsSubstr(conn1.CertHygieneFlags, "SCT") {
		t.Fatalf("first observation: expected cert_hygiene_flags to record the missing SCT, got %v", conn1.CertHygieneFlags)
	}

	// Observation 2: a passive re-observation of the SAME connection. It can
	// read the cipher suite off the wire, but this pass never decrypted far
	// enough to see the certificate — CertHasSCT is nil, not false. This must
	// NOT be read as "SCT now present": it's "unobserved this time".
	conn2, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:    "192.0.2.70",
		DestIP:      "198.51.100.70",
		DestPort:    443,
		Protocol:    "TLS",
		CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"),
		// CertHasSCT intentionally omitted (nil).
	})
	if err != nil {
		t.Fatalf("second Upsert (passive re-observation): %v", err)
	}
	if !containsSubstr(conn2.CertHygieneFlags, "SCT") {
		t.Fatalf("second observation wiped cert_hygiene_flags instead of preserving it: got %v", conn2.CertHygieneFlags)
	}
}

// TestIntegration_ExternalConnectionUpsert_WeakReasonsSurviveAPartialReobservation
// is the same shape for weak_reasons: an undersized certificate key is the
// ONLY thing making the connection "weak" (the cipher suite itself is
// catalogue-good), then a later observation resolves the same good cipher
// suite but never re-read the certificate's key size. weak_reasons must still
// name the undersized key afterward — it was never re-measured as fixed, just
// not re-measured at all.
//
// The persisted rating and reasons must agree after merging incomplete facts.
func TestIntegration_ExternalConnectionUpsert_WeakReasonsSurviveAPartialReobservation(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	// Observation 1: good cipher suite, but an undersized (RSA-1024)
	// certificate key makes the connection weak.
	conn1, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:               "192.0.2.71",
		DestIP:                 "198.51.100.71",
		DestPort:               443,
		Protocol:               "TLS",
		CipherSuite:            strPtr("TLS_AES_256_GCM_SHA384"),
		CertPublicKeyAlgorithm: strPtr("RSA"),
		CertPublicKeySize:      intPtr(1024),
	})
	if err != nil {
		t.Fatalf("first Upsert (with cert key size): %v", err)
	}
	if stringValue(conn1.Strength) != "weak" {
		t.Fatalf("first observation: crypto_strength = %q, want %q (weakReasons=%v)", stringValue(conn1.Strength), "weak", conn1.WeakReasons)
	}
	if !containsSubstr(conn1.WeakReasons, "1024") {
		t.Fatalf("first observation: expected weak_reasons to name the undersized key, got %v", conn1.WeakReasons)
	}

	// Observation 2: same connection, same good cipher suite, but this
	// observation never re-read the certificate's key size at all.
	conn2, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:    "192.0.2.71",
		DestIP:      "198.51.100.71",
		DestPort:    443,
		Protocol:    "TLS",
		CipherSuite: strPtr("TLS_AES_256_GCM_SHA384"),
		// CertPublicKeyAlgorithm/CertPublicKeySize intentionally omitted.
	})
	if err != nil {
		t.Fatalf("second Upsert (cert key size unobserved): %v", err)
	}
	if stringValue(conn2.Strength) != "weak" {
		t.Fatalf("partial observation lost weak strength: %v", conn2.Strength)
	}
	if !containsSubstr(conn2.WeakReasons, "1024") {
		t.Fatalf("second observation wiped weak_reasons instead of preserving it: got %v", conn2.WeakReasons)
	}
}
