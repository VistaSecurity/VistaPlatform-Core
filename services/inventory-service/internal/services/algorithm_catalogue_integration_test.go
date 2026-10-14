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
//
// Every test here reads a database of its own (shippedCatalogue), never the
// shared one. `algorithms` is a GLOBAL table, and the other packages running
// concurrently against the shared database write to it: they insert fixture
// rows (READ-<uuid> weak at score 40/1/0, a NULL-score row) and temporarily
// rewrite seeded ones (AES256 to weak/NULL, then restore). Every one of those is
// a legitimate fixture and a violation of an invariant below, so a whole-table
// scan on the shared database failed whenever it happened to overlap them.
// Excluding fixture code prefixes would not fix that. The seeded-row rewrites
// carry real codes, and the next fixture would bring a prefix nobody listed.
// The subject of these tests is what schema.sql + seed.sql SHIP, and a fresh
// database holding exactly that is the only place nothing else can write.

import (
	"database/sql"
	"fmt"
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
	// Kerberos: the RFC 8009 SHA-2 encryption types are what the SHA-1 ones
	// are told to migrate to, so they must resolve.
	"AES256-CTS-HMAC-SHA1-96", "AES256-CTS-HMAC-SHA384-192", "AES128-CTS-HMAC-SHA256-128",
	// Hashes (SHA-2, SHA-3, legacy). The 224-bit and 512/t variants are FIPS
	// 180-4 / 202 outputs the Rev. 3 transition names individually.
	"SHA256", "SHA384", "SHA512", "SHA1", "MD5", "SHA3-256", "SHA3-512",
	"SHA224", "SHA-512/256", "SHA-512/224", "SHA3-224",
	// Classical signatures. The bare family rows — ECDSA, Ed25519, DSA — are
	// what a certificate's public_key_algorithm resolves to (crypto/x509
	// spelling) and what the key producer looks up; without one an EC
	// certificate is unclassified and raises no pqc_vulnerable finding.
	// 'Ed25519' is the one spelling of that row: a second, 'ED25519', once
	// coexisted with it (the code UNIQUE is case-sensitive, every lookup is
	// not) and seed.sql Part 5 merges it away.
	"RSA-SHA256", "RSA-SHA512", "ECDSA-SHA256", "ECDSA-SHA384", "ECDSA", "Ed25519", "DSA", "RSA-MD5",
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
	// Stateful hash-based signatures (SP 800-208): approved, quantum-safe,
	// and what a firmware image is signed with.
	"LMS", "XMSS",
	// Protocol versions
	"TLS1.2", "TLS1.3", "SSLv3",
}

func TestIntegration_AlgorithmCatalogue_ClassifiesEverythingItMust(t *testing.T) {
	db := shippedCatalogue(t)

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

// Every row shipped by this repository has a deliberate score. This is the
// evidence audit for the committed catalogue sources; it does not authorize a
// backfill of operator-created NULL rows, whose intended assessment is unknown.
func TestIntegration_AlgorithmCatalogue_ShippedRowsHaveExplicitRiskScores(t *testing.T) {
	db := shippedCatalogue(t)

	missing := queryStrings(t, db, `SELECT code FROM algorithms WHERE risk_score IS NULL ORDER BY code`)
	if len(missing) > 0 {
		t.Fatalf("shipped algorithm rows without an explicit risk score: %v", missing)
	}
}

// Internal consistency. These are relationships that must hold for the ratings
// to be trustworthy; a violation means two columns disagree about the same
// algorithm.
func TestIntegration_AlgorithmCatalogue_IsInternallyConsistent(t *testing.T) {
	db := shippedCatalogue(t)

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
		// `algorithms.code` is UNIQUE case-sensitively and every reader is
		// case-insensitive: the crypto producer keys its lookup by UPPER(code),
		// this service's classifier by lower(code), the key producer uses ILIKE.
		// Two codes that fold to one string are two verdicts for one algorithm,
		// and which one answers is whichever row the scan returned last.
		// 'Ed25519' / 'ED25519' were exactly that until seed.sql Part 5.
		{"codes that collide under case folding (two rows, one lookup key)",
			`SELECT string_agg(code, ' / ' ORDER BY code) FROM algorithms GROUP BY UPPER(code) HAVING count(*) > 1`},
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
	db := shippedCatalogue(t)

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

// shippedCatalogue returns a database holding nothing but schema.sql + seed.sql,
// which is what these guards are about. See the file comment for why it cannot
// be the shared database.
func shippedCatalogue(t *testing.T) *sql.DB {
	t.Helper()
	return testdb.ScratchDatabase(t)
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

// Marking an algorithm obsolete means it grades Critical: the Catalog ->
// Ratings dialog says so, and algorithm_obsolete_floor.go makes it true on the
// admin write path. Seed INSERTs bypass that path, and five shipped rows were
// 'obsolete' at 76-82 — the dialog's promise was false for the rows the
// product itself ships. The floor is read from the same function the write
// path uses, so this moves with the band ladder.
func TestIntegration_AlgorithmCatalogue_ObsoleteRowsGradeCritical(t *testing.T) {
	db := shippedCatalogue(t)

	floor := ObsoleteRiskFloor()
	offenders := queryStrings(t, db, fmt.Sprintf(
		`SELECT code||' ('||risk_score||')' FROM algorithms WHERE deprecation_status='obsolete' AND risk_score < %d ORDER BY code`, floor))
	if len(offenders) > 0 {
		t.Errorf("obsolete rows scored below the Critical floor (%d): %v", floor, offenders)
	}
}

// Guards for the NIST alignment pass (seed.sql "Algorithm catalogue: NIST
// alignment pass"). Each one pins a row the review found contradicting the
// guidance in force, so the next edit to the seed cannot quietly undo it.
func TestIntegration_AlgorithmCatalogue_NISTAlignmentStaysFixed(t *testing.T) {
	db := shippedCatalogue(t)

	// 1. Disallowed is not deprecated. 80-bit public keys (SP 800-131A, since
	//    2013), DSA (FIPS 186-5 withdrew it) and RC4 in Kerberos (RFC 8429)
	//    sat at 'deprecated' while their siblings of the same strength were
	//    'obsolete'. One primitive, one verdict.
	for _, code := range []string{"RSA-1024", "DH-1024", "DH-768", "DH-ECP-192", "DH-RFC5114-1024-160", "DSA", "RC4-HMAC-KRB"} {
		var status string
		if err := db.QueryRow(`SELECT deprecation_status FROM algorithms WHERE code=$1`, code).Scan(&status); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if status != DeprecationObsolete {
			t.Errorf("%s is %q; NIST disallows it, so it must be %q", code, status, DeprecationObsolete)
		}
	}

	// 2. A classical public-key algorithm is Shor-breakable: NIST quantum
	//    category 0, never a positive category. curve25519-sha256 carried the
	//    3 that belongs to its ML-KEM hybrid.
	if bad := queryStrings(t, db, `
		SELECT code||' ('||nist_quantum_security_level||')' FROM algorithms
		WHERE NOT is_pqc AND primitive IN ('key-agree','signature','pke')
		  AND COALESCE(nist_quantum_security_level, 0) > 0 ORDER BY code`); len(bad) > 0 {
		t.Errorf("classical public-key row(s) claiming a positive NIST quantum category: %v", bad)
	}

	// 3. Every quantum-vulnerable public-key row that is not already
	//    disallowed carries the IR 8547 (draft) date, so the Catalog page and
	//    the CBOM export show what is ahead of a 2048-bit RSA key.
	if bad := queryStrings(t, db, `
		SELECT code FROM algorithms
		WHERE NOT is_pqc AND primitive IN ('key-agree','signature','pke')
		  AND deprecation_status <> 'obsolete' AND deprecation_date IS NULL ORDER BY code`); len(bad) > 0 {
		t.Errorf("quantum-vulnerable public-key row(s) without a deprecation date: %v", bad)
	}
	if bad := queryStrings(t, db, `
		SELECT code FROM algorithms
		WHERE NOT is_pqc AND primitive IN ('key-agree','signature','pke')
		  AND deprecation_status = 'current'
		  AND (migration_guidance IS NULL OR migration_guidance NOT LIKE '%8547%') ORDER BY code`); len(bad) > 0 {
		t.Errorf("current quantum-vulnerable public-key row(s) whose guidance does not name IR 8547: %v", bad)
	}

	// 4. The PQ/T hybrid key exchanges follow one convention, whichever
	//    protocol names them: the ML-KEM half is standardized and the row
	//    carries a classical strength.
	for _, code := range []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "mlkem768x25519-sha256", "mlkem768nistp256-sha256"} {
		var status string
		var csl sql.NullInt64
		if err := db.QueryRow(`SELECT pqc_standardization_status, classical_security_level FROM algorithms WHERE code=$1`, code).Scan(&status, &csl); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if status != "standardized" || !csl.Valid {
			t.Errorf("%s: pqc_standardization_status=%q classical_security_level=%v; hybrids share one convention (standardized, strength set)", code, status, csl)
		}
	}

	// 5. The NIST mapping must not claim approval NIST has not given. X25519
	//    and X448 are not SP 800-56A Rev. 3 schemes (NIST declined to add them
	//    in July 2025); ChaCha20-Poly1305 is not an approved cipher.
	for _, code := range []string{"X25519", "X448", "CURVE25519", "curve25519-sha256", "ChaCha20", "TLS_CHACHA20_POLY1305_SHA256", "chacha20-poly1305@openssh.com"} {
		var nist sql.NullString
		if err := db.QueryRow(`SELECT compliance_mappings->>'NIST' FROM algorithms WHERE code=$1`, code).Scan(&nist); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if nist.String != "not-approved" {
			t.Errorf("%s: compliance_mappings.NIST = %q, want not-approved", code, nist.String)
		}
	}

	// 6. Triple DES: encryption disallowed after 2023 (SP 800-131A Rev. 2).
	//    The row stays deprecated by owner decision; the date must say when.
	for _, code := range []string{"3DES", "3des-cbc", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"} {
		var date sql.NullString
		if err := db.QueryRow(`SELECT deprecation_date::text FROM algorithms WHERE code=$1`, code).Scan(&date); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if date.String != "2023-12-31" {
			t.Errorf("%s: deprecation_date = %q, want 2023-12-31", code, date.String)
		}
	}

	// 7. The signature hash does not set the key's strength, and 4096-bit RSA
	//    and DH share one estimate.
	for code, want := range map[string]int{"RSA-SHA256": 112, "RSA-SHA512": 112, "RSA-4096": 152, "DH-MODP-4096": 152} {
		var got sql.NullInt64
		if err := db.QueryRow(`SELECT classical_security_level FROM algorithms WHERE code=$1`, code).Scan(&got); err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if !got.Valid || int(got.Int64) != want {
			t.Errorf("%s classical security level = %v, want %d", code, got, want)
		}
	}
}

// The seed re-applies on every helm upgrade. Every UPDATE in the NIST
// alignment pass names the shipped value it replaces, so a row a platform
// admin has edited in Catalog -> Ratings keeps the admin's value. This drives
// the real file over edited rows: a predicate widened to "anything but the new
// value" rewrites the admin's choice on the next upgrade and nothing in the
// shipped-catalogue guards above would notice, because the shipped rows are
// unchanged.
func TestIntegration_AlgorithmCatalogue_ReseedKeepsAdminEdits(t *testing.T) {
	db := shippedCatalogue(t)

	edits := []struct {
		code, stmt, probe, want string
	}{
		{"ChaCha20",
			`UPDATE algorithms SET compliance_mappings = compliance_mappings || '{"NIST": "admin: validated module"}' WHERE code = 'ChaCha20'`,
			`SELECT compliance_mappings->>'NIST' FROM algorithms WHERE code = 'ChaCha20'`, "admin: validated module"},
		{"hmac-sha1",
			`UPDATE algorithms SET compliance_mappings = compliance_mappings || '{"FIPS": "admin: CMVP cert"}' WHERE code = 'hmac-sha1'`,
			`SELECT compliance_mappings->>'FIPS' FROM algorithms WHERE code = 'hmac-sha1'`, "admin: CMVP cert"},
		// An admin took DSA back out of obsolete and re-scored it.
		{"DSA",
			`UPDATE algorithms SET deprecation_status = 'deprecated', risk_score = 60, pre_obsolete_risk_score = NULL, obsolete_risk_floor_at = NULL WHERE code = 'DSA'`,
			`SELECT deprecation_status || '/' || risk_score FROM algorithms WHERE code = 'DSA'`, "deprecated/60"},
		{"AES256-CTS-HMAC-SHA1-96",
			`UPDATE algorithms SET strength = 'strong', risk_score = 12 WHERE code = 'AES256-CTS-HMAC-SHA1-96'`,
			`SELECT strength || '/' || risk_score FROM algorithms WHERE code = 'AES256-CTS-HMAC-SHA1-96'`, "strong/12"},
		{"X25519",
			`UPDATE algorithms SET compliance_mappings = compliance_mappings || '{"NIST": "admin"}' WHERE code = 'X25519'`,
			`SELECT compliance_mappings->>'NIST' FROM algorithms WHERE code = 'X25519'`, "admin"},
	}
	for _, e := range edits {
		if _, err := db.Exec(e.stmt); err != nil {
			t.Fatalf("edit %s: %v", e.code, err)
		}
	}

	testdb.ForceApplySeed(t, db)

	for _, e := range edits {
		var got string
		if err := db.QueryRow(e.probe).Scan(&got); err != nil {
			t.Errorf("%s: %v", e.code, err)
			continue
		}
		if got != e.want {
			t.Errorf("%s: re-seed rewrote the admin's edit: got %q, want %q", e.code, got, e.want)
		}
	}
}
