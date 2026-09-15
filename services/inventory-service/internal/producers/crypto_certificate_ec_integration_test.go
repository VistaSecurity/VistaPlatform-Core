package producers

// The elliptic-curve certificate families, against the SEEDED catalogue.
//
// crypto_certificate_lookup_integration_test.go and its sibling pin how a
// finite-field key (RSA, DSA) resolves; they create the catalogue rows they
// need when the database has no seed. These tests deliberately do not: the
// defect they pin was a MISSING SEED ROW. An ECDSA certificate's
// public_key_algorithm is the bare family name "ECDSA", the catalogue carried
// only ECDSA-SHA256/384/512, ECDSA-SHA1 and the SSH host-key names — none of
// which assesses an EC public key as such — and the resolver's bare lookup
// landed on nothing. Unclassified, never assumed safe, so no pqc_vulnerable
// finding: on the RC-verification tenant, 16 RSA certificates raised 16 and
// 6 ECDSA certificates raised 0, while NIST IR 8547 puts both on the same
// deprecation clock. A test that seeded the row itself could not catch that
// regressing, so these run against scripts/database/seed.sql and fail if the
// row is not there.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seededCryptoFixture is newCryptoFixture over a database that carries
// seed.sql, plus the risk score of one seeded catalogue row the test is about,
// read back rather than written as a literal (editing the row must MOVE the
// score, not fail the test).
func seededCryptoFixture(t *testing.T, code string) (*cryptoFixture, int) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	f := newCryptoFixture(t)

	var risk int
	err := f.owner.QueryRow(`SELECT COALESCE(risk_score, 0) FROM algorithms WHERE code = $1`, code).Scan(&risk)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		t.Fatalf("the seeded catalogue has no %q row; seed.sql is what puts it there, and without it a certificate of that family resolves to nothing", code)
	case err != nil:
		t.Fatalf("probe catalogue row %s: %v", code, err)
	}
	return f, risk
}

// An ECDSA P-256 certificate resolves to the bare `ECDSA` catalogue row, raises
// crypto/pqc_vulnerable citing it, and covers its asset.
//
// Mutation-checked, both ways:
//   - remove the `ECDSA` INSERT from seed.sql Part 5 → seededCryptoFixture
//     fails on the missing row;
//   - make resolveCertificateAlgorithms skip the bare lookup for an
//     elliptic-curve family (return early when sizedPublicKeyCode is "") →
//     no catalogue match, no pqc_vulnerable finding, and every assertion below
//     fails.
func TestIntegration_CryptoProducer_ECDSACertificateIsPQCVulnerable(t *testing.T) {
	f, risk := seededCryptoFixture(t, "ECDSA")
	ctx := context.Background()

	cfg := f.configuration(t, "TLS 1.3", 0)
	certID := uuid.New()
	// P-256, signed with SHA-256: the shape crypto/x509 reports for the
	// commonest EC leaf (public_key_algorithm "ECDSA", signature "ECDSAWithSHA256").
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=ec.example.test', 'CN=Test CA', 'ec.example.test',
		        'ECDSA', 256, 'ECDSAWithSHA256', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfg, certID)

	run := f.mustRun(t, ctx)

	if codes := pqcCodes(t, f, certID); len(codes) != 1 || codes[0] != "ECDSA" {
		t.Errorf("ECDSA certificate's pqc_vulnerable finding cites %v, want [ECDSA] — an EC key is Shor-breakable on every curve (NIST IR 8547)", codes)
	}
	if run.PQCVulnerable < 1 {
		t.Errorf("run counted %d PQC-vulnerable subjects, want at least the certificate", run.PQCVulnerable)
	}

	// The same resolution scores it: the row's own risk, and the evidence names
	// the row. A row rated 0 raises nothing, which is also fine.
	var score int
	var evidence []byte
	err := f.owner.QueryRow(`
		SELECT score, evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&score, &evidence)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if risk > 0 {
			t.Fatalf("no weak_certificate finding for an ECDSA certificate whose catalogue row scores %d", risk)
		}
	case err != nil:
		t.Fatalf("read the weak_certificate finding: %v", err)
	default:
		if score != risk {
			t.Errorf("weak_certificate score = %d, want the ECDSA row's %d", score, risk)
		}
		if got := keyCatalogueCodes(t, evidence); len(got) != 1 || got[0] != "ECDSA" {
			t.Errorf("public_key_algorithm resolved to %v, want exactly [ECDSA]", got)
		}
	}

	var covered bool
	if err := f.owner.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM producer_assessments
		               WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto')`,
		f.tenant, f.assetID).Scan(&covered); err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	if !covered {
		t.Errorf("the asset serving the ECDSA certificate is not marked assessed by crypto")
	}
}

// An Ed25519 certificate resolves to ONE catalogue row, spelled 'Ed25519', and
// its pqc_vulnerable finding cites it once.
//
// The catalogue used to hold 'Ed25519' AND 'ED25519' — different risk scores —
// and the resolver keys its map by UPPER(code), so which row answered was
// whichever the scan returned last. Both of this certificate's algorithm
// strings resolve to the row (crypto/x509 spells the PureEd25519 signature
// "Ed25519" too), which is why the finding must name it once, not twice.
//
// Mutation-checked: re-adding an 'ED25519' row to seed.sql fails the
// row-count assertion here and the case-folding check in
// TestIntegration_AlgorithmCatalogue_IsInternallyConsistent; dropping the
// dedupe in certSubject.pqcVulnerableCodes makes the finding cite
// [Ed25519 Ed25519].
func TestIntegration_CryptoProducer_Ed25519CertificateResolvesToOneRow(t *testing.T) {
	f, _ := seededCryptoFixture(t, "Ed25519")
	ctx := context.Background()

	var spellings int
	if err := f.owner.QueryRow(`SELECT count(*) FROM algorithms WHERE UPPER(code) = 'ED25519'`).Scan(&spellings); err != nil {
		t.Fatalf("count Ed25519 rows: %v", err)
	}
	if spellings != 1 {
		t.Fatalf("the catalogue carries %d rows spelling ED25519, want exactly 1 ('Ed25519'); with two, the resolver's verdict depends on scan order", spellings)
	}

	cfg := f.configuration(t, "TLS 1.3", 0)
	certID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=ed.example.test', 'CN=Test CA', 'ed.example.test',
		        'Ed25519', 256, 'Ed25519', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfg, certID)

	f.mustRun(t, ctx)

	if codes := pqcCodes(t, f, certID); len(codes) != 1 || codes[0] != "Ed25519" {
		t.Errorf("Ed25519 certificate's pqc_vulnerable finding cites %v, want exactly [Ed25519]", codes)
	}
}

// The seed's Ed25519 merge, run verbatim against a database in the PRE-FIX
// state: both spellings present, with rows pointing at the one being retired.
//
// A fresh install never sees this; every existing install does, on its next
// `helm upgrade`, and the seed Job runs WITHOUT ON_ERROR_STOP — a merge that
// tripped a foreign key would print an error nobody reads and leave the
// duplicate in place. So the block is executed here exactly as seed.sql spells
// it (read from the file between its BEGIN/END markers), against a key and a
// junction row that reference the retired row, plus a junction row that would
// collide with the kept row on the (implementation, algorithm, role) UNIQUE.
//
// Mutation-checked: dropping the `UPDATE keys SET algorithm_id = keep` line
// makes the DELETE fail the keys FK and the row survives; dropping the
// collision DELETE before the crypto_implementation_algorithms UPDATE makes
// that UPDATE violate unique_impl_algorithm. Either way the block aborts and
// the "retired row is gone" assertion fails.
func TestIntegration_Seed_Ed25519MergeRepointsReferencesBeforeDeleting(t *testing.T) {
	f, _ := seededCryptoFixture(t, "Ed25519")
	block := seedBlock(t, "ed25519-dedupe")

	var keep uuid.UUID
	if err := f.owner.QueryRow(`SELECT id FROM algorithms WHERE code = 'Ed25519'`).Scan(&keep); err != nil {
		t.Fatalf("read the kept row: %v", err)
	}

	// Recreate the retired row as the pre-fix seed had it. Its cleanup is
	// registered first (LIFO → runs last), after the rows that reference it.
	retire := uuid.New()
	exec(t, f.owner, `
		INSERT INTO algorithms (id, code, category, name, strength, deprecation_status, risk_score, primitive)
		VALUES ($1, 'ED25519', 'signature', 'Ed25519', 'strong', 'current', 15, 'signature')`, retire)
	t.Cleanup(func() { _, _ = f.owner.Exec(`DELETE FROM algorithms WHERE id = $1`, retire) })

	cfg := f.configuration(t, "TLS 1.3", 0)
	// A key that points at the retired row: the plain FK a bare DELETE trips.
	keyID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO keys (id, tenant_id, key_type, public_fingerprint, size_bits, material_type, state, algorithm_id, provenance)
		VALUES ($1, $2, 'Ed25519', $3, 256, 'public-key', 'active', $4, 'certificate')`,
		keyID, f.tenant, fingerprint(), retire)
	t.Cleanup(func() { _, _ = f.owner.Exec(`DELETE FROM keys WHERE id = $1`, keyID) })
	// The configuration links BOTH spellings in the signature role: moving the
	// retired link naively collides with the kept one.
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type)
		VALUES ($1, $2, 'signature'), ($1, $3, 'signature')`, cfg, keep, retire)

	if _, err := f.owner.Exec(block); err != nil {
		t.Fatalf("the seed's ed25519-dedupe block failed against a pre-fix database: %v", err)
	}

	var survivors int
	if err := f.owner.QueryRow(`SELECT count(*) FROM algorithms WHERE code = 'ED25519'`).Scan(&survivors); err != nil {
		t.Fatalf("count retired rows: %v", err)
	}
	if survivors != 0 {
		t.Errorf("the 'ED25519' row survived the merge")
	}
	var keyAlg uuid.UUID
	if err := f.owner.QueryRow(`SELECT algorithm_id FROM keys WHERE id = $1`, keyID).Scan(&keyAlg); err != nil {
		t.Fatalf("read the key's algorithm: %v", err)
	}
	if keyAlg != keep {
		t.Errorf("the key points at %s after the merge, want the kept 'Ed25519' row %s", keyAlg, keep)
	}
	var links int
	if err := f.owner.QueryRow(`
		SELECT count(*) FROM crypto_implementation_algorithms
		 WHERE crypto_implementation_id = $1 AND algorithm_type = 'signature'`, cfg).Scan(&links); err != nil {
		t.Fatalf("count signature links: %v", err)
	}
	if links != 1 {
		t.Errorf("the configuration has %d signature links after the merge, want 1 (the kept row, once)", links)
	}
}

// seedBlock returns the SQL between `-- BEGIN: <name>` and `-- END: <name>`
// in scripts/database/seed.sql — the statement bytes the seed Job will run, not
// a copy of them.
func seedBlock(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := string(raw)
	begin := "-- BEGIN: " + name
	end := "-- END: " + name
	i := strings.Index(s, begin)
	if i < 0 {
		t.Fatalf("%s has no %q marker", path, begin)
	}
	j := strings.Index(s[i:], end)
	if j < 0 {
		t.Fatalf("%s has no %q marker after its BEGIN", path, end)
	}
	block := s[i : i+j]
	// Drop the marker line itself (it carries a parenthetical), keep the SQL.
	if nl := strings.Index(block, "\n"); nl >= 0 {
		block = block[nl+1:]
	}
	return block
}
