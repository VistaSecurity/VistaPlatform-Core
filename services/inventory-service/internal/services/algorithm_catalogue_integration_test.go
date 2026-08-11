package services

// Guard for the cryptographic algorithm catalogue (the `algorithms` seed).
//
// The catalogue is the assessment engine's source of truth: strength, PQC
// status, risk scores and the CycloneDX identity fields all come from here, and
// it is the first thing a cryptographer evaluating the product will check. A
// wrong classification is not a crash — it is a confidently incorrect finding,
// the worst failure mode for an inventory tool. These invariants make the next
// such error fail CI instead of shipping.
//
// Runs against the real schema + seed via the testdb harness (nightly
// test-backend and `make test-integration-db`); skips when TEST_DATABASE_URL is
// unset, so the plain unit path stays green.

import (
	"database/sql"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// mustClassify lists algorithm codes the platform WILL encounter on the wire or
// in a certificate and therefore must be able to classify. A miss here means a
// scanned asset using that algorithm gets no assessment. Keep this list honest:
// add a code when the discovery pipeline learns to emit it.
var mustClassify = []string{
	// Symmetric
	"AES128", "AES256", "3DES", "DES", "RC4", "ChaCha20", "NULL",
	// Hashes (SHA-2, SHA-3, legacy)
	"SHA256", "SHA384", "SHA512", "SHA1", "MD5", "SHA3-256", "SHA3-512",
	// Classical signatures
	"RSA-SHA256", "RSA-SHA512", "ECDSA-SHA256", "ECDSA-SHA384", "ED25519", "DSA", "RSA-MD5",
	// Classical key exchange
	"RSA-2048", "RSA-4096", "DH-2048", "ECDHE", "X25519", "X448", "CURVE25519",
	// The key-exchange vocabulary the cipher-suite parsers emit. The static
	// forms are the population the no-forward-secrecy controls exist to find,
	// and without a row they resolved to nothing at all.
	"DHE", "ECDH", "DH", "RSA",
	// Post-quantum (standardized + hybrid — the whole point of the product)
	"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
	"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
	"SLH-DSA-128s", "SLH-DSA-256f",
	"X25519MLKEM768", "SecP256r1MLKEM768",
	// Protocol versions
	"TLS1.2", "TLS1.3", "SSLv3",
}

func TestIntegration_AlgorithmCatalogue_ClassifiesEverythingItMust(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	for _, code := range mustClassify {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM algorithms WHERE code = $1`, code).Scan(&n); err != nil {
			t.Fatalf("query %s: %v", code, err)
		}
		if n != 1 {
			t.Errorf("algorithm %q is not in the catalogue (found %d rows) — a scanned asset using it gets NO assessment", code, n)
		}
	}
}

// Internal consistency. These are relationships that must hold for the ratings
// to be trustworthy; a violation means two columns disagree about the same
// algorithm.
func TestIntegration_AlgorithmCatalogue_IsInternallyConsistent(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	type check struct {
		name  string
		query string // must return zero rows; %s of offending codes on failure
	}
	checks := []check{
		{"weak algorithm with a low risk score (<50)",
			`SELECT code||' ('||risk_score||')' FROM algorithms WHERE strength='weak' AND risk_score < 50`},
		{"recommended algorithm with a high risk score (>30)",
			`SELECT code||' ('||risk_score||')' FROM algorithms WHERE strength='recommended' AND risk_score > 30`},
		{"PQC algorithm without a NIST quantum security level",
			`SELECT code FROM algorithms WHERE is_pqc AND nist_quantum_security_level IS NULL`},
		{"obsolete algorithm not rated weak",
			`SELECT code||' ('||strength||')' FROM algorithms WHERE deprecation_status='obsolete' AND strength <> 'weak'`},
		{"is_pqc row not marked quantum-resistant in metadata",
			`SELECT code FROM algorithms WHERE is_pqc AND COALESCE(metadata->>'quantum_resistance','') <> 'true'`},
	}

	for _, c := range checks {
		offenders := queryStrings(t, db, c.query)
		if len(offenders) > 0 {
			t.Errorf("%s: %v", c.name, offenders)
		}
	}
}

// Regression guards for the specific errors corrected in this catalogue pass.
// If any recurs, this fails with the exact reason.
func TestIntegration_AlgorithmCatalogue_KnownErrorsStayFixed(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	// 1. ML-KEM OIDs belong on the NIST KEM arc (2.16.840.1.101.3.4.4.x), not
	//    the AES arc (…3.4.1.x) they were mistakenly seeded on.
	if bad := queryStrings(t, db,
		`SELECT code||'='||oid FROM algorithms WHERE code LIKE 'ML-KEM-%' AND oid IS NOT NULL AND oid NOT LIKE '2.16.840.1.101.3.4.4.%'`); len(bad) > 0 {
		t.Errorf("ML-KEM OID(s) not on the KEM arc: %v", bad)
	}

	// 2. CBC is confidentiality-only; no CBC-mode row may claim the 'ae'
	//    (authenticated encryption) primitive.
	if bad := queryStrings(t, db,
		`SELECT code FROM algorithms WHERE primitive='ae' AND (code ILIKE '%CBC%' OR name ILIKE '%CBC%')`); len(bad) > 0 {
		t.Errorf("CBC-mode row(s) mislabelled as authenticated encryption: %v", bad)
	}

	// 3. A TLS/SSL protocol version is not an algorithm and must carry no OID
	//    (it previously held the id-kp-serverAuth EKU OID).
	if bad := queryStrings(t, db,
		`SELECT code FROM algorithms WHERE category='protocol_version' AND oid='1.3.6.1.5.5.7.3.1'`); len(bad) > 0 {
		t.Errorf("protocol-version row(s) carrying the serverAuth EKU OID: %v", bad)
	}

	// 4. Every standardized PQC algorithm must report the correct NIST category.
	for code, want := range map[string]int{
		"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5,
		"ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5,
	} {
		var got sql.NullInt64
		if err := db.QueryRow(`SELECT nist_quantum_security_level FROM algorithms WHERE code=$1`, code).Scan(&got); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if !got.Valid || int(got.Int64) != want {
			t.Errorf("%s NIST quantum level = %v, want %d", code, got, want)
		}
	}

	// 5. Symmetric primitives and SHA-2 hashes are NOT Shor-breakable. Level 0
	//    in this table means "classically breakable or already broken", which is
	//    what ChaCha20 and the SHA-2 family were left at — so a ChaCha20
	//    endpoint looked no better than an RSA one on the quantum axis.
	for code, want := range map[string]int{
		"ChaCha20": 5, "AES128": 1, "AES256": 5,
		"SHA256": 2, "SHA384": 4, "SHA512": 5, "BLAKE2S": 2,
	} {
		var got sql.NullInt64
		if err := db.QueryRow(`SELECT nist_quantum_security_level FROM algorithms WHERE code=$1`, code).Scan(&got); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if !got.Valid || int(got.Int64) != want {
			t.Errorf("%s NIST quantum level = %v, want %d", code, got, want)
		}
	}

	// 6. Finite-field DH and RSA of the same modulus size have the same
	//    security strength (SP 800-57 Part 1 Rev 5, Table 2). DH-1024 claimed
	//    56 — the RSA-512 figure.
	for code, want := range map[string]int{
		"DH-1024": 80, "DH-768": 64, "DH-512": 56, "DH-2048": 112,
	} {
		var got sql.NullInt64
		if err := db.QueryRow(`SELECT classical_security_level FROM algorithms WHERE code=$1`, code).Scan(&got); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if !got.Valid || int(got.Int64) != want {
			t.Errorf("%s classical security level = %v, want %d", code, got, want)
		}
	}
	var rsa1024, dh1024 sql.NullInt64
	_ = db.QueryRow(`SELECT classical_security_level FROM algorithms WHERE code='RSA-1024'`).Scan(&rsa1024)
	_ = db.QueryRow(`SELECT classical_security_level FROM algorithms WHERE code='DH-1024'`).Scan(&dh1024)
	if rsa1024.Valid && dh1024.Valid && rsa1024.Int64 != dh1024.Int64 {
		t.Errorf("RSA-1024 (%d) and DH-1024 (%d) must carry the same security strength", rsa1024.Int64, dh1024.Int64)
	}

	// 7. The bare 'CBC' pseudo-algorithm is a MODE, not an algorithm. If it
	//    survives (because a row still references it) it must at least be
	//    unassessed, so it can never become the worst component of a score.
	var cbcRisk sql.NullInt64
	switch err := db.QueryRow(`SELECT risk_score FROM algorithms WHERE code='CBC'`).Scan(&cbcRisk); err {
	case sql.ErrNoRows: // deleted — the intended outcome
	case nil:
		if !cbcRisk.Valid || cbcRisk.Int64 != 0 {
			t.Errorf("the 'CBC' pseudo-algorithm still carries risk %v — a mode must not be scored as an algorithm", cbcRisk)
		}
	default:
		t.Errorf("CBC lookup: %v", err)
	}

	// 8. The static key-exchange rows must record the absence of forward
	//    secrecy, not read as ordinary healthy key agreement.
	for _, code := range []string{"RSA", "ECDH", "DH"} {
		var strength string
		var risk int
		var category string
		if err := db.QueryRow(`SELECT strength, risk_score, category FROM algorithms WHERE code=$1`, code).Scan(&strength, &risk, &category); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if category != "key_exchange" {
			t.Errorf("%s must be a key_exchange row, got %q", code, category)
		}
		if strength != "weak" || risk < 50 {
			t.Errorf("%s (static, no forward secrecy) is rated %s/%d — too benign", code, strength, risk)
		}
	}
}

func queryStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, s)
	}
	return out
}
