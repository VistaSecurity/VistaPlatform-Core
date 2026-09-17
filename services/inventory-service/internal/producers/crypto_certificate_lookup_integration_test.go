package producers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// An RSA certificate is judged by the catalogue row for ITS KEY SIZE, never by
// the bare `RSA` row.
//
// The bare row is `RSA key transport (static)` — the TLS key-exchange
// assessment, risk 70 — and until this test existed every RSA certificate was
// scored by it: an RSA-4096 root CA read as High, and since every host chains
// to its CA, every host in the RC-verification estate reported High with
// nothing above Low in its own configurations (20/20). The sized rows the
// catalogue already carries (RSA-1024 … RSA-4096) are the assessment of a
// public key; this pins that they are the ones consulted.
//
// Mutation-checked: restoring the bare lookup for a sized key
// (`lookup("public_key_algorithm", keyAlg)` unconditionally in
// resolveCertificateAlgorithms) fails every assertion below — the match names
// "RSA", the score is the bare row's 70, and the PQC finding cites "RSA".
func TestIntegration_CryptoProducer_RSACertificateResolvesThroughItsSizedRow(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	// Both rows must exist for the test to mean anything: the trap AND the
	// answer. seed.sql carries both; a database without the seed gets them
	// here, scoped to this test, so the assertion can never pass vacuously.
	bareRisk := f.ensureCatalogueRow(t, "RSA", "key_exchange", "weak", "deprecated", 70, "pke")
	sizedRisk := f.ensureCatalogueRow(t, "RSA-4096", "key_exchange", "strong", "current", 25, "pke")
	if sizedRisk >= bareRisk {
		t.Fatalf("catalogue: RSA-4096 risk %d is not below bare RSA risk %d; the test cannot tell the rows apart", sizedRisk, bareRisk)
	}

	cfg := f.configuration(t, "TLS 1.3", 0)
	certID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=Strong Root CA', 'CN=Strong Root CA', 'Strong Root CA',
		        'RSA', 4096, 'sha256WithRSAEncryption', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'root')`, cfg, certID)

	f.mustRun(t, ctx)

	// A strong sized row contributes a numeric assessment but no weak finding.
	var count int
	if err := f.owner.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id=$1 AND kind='weak_certificate' AND subject_id=$2`, f.tenant, certID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("strong RSA-4096 raised %d weak findings", count)
	}

	// The PQC classification comes from the same resolution, so it names the
	// sized row too — and it is still raised: sizing the lookup must not cost
	// the certificate its Shor-vulnerability finding.
	var pqcEvidence []byte
	if err := f.owner.QueryRow(`
		SELECT evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'pqc_vulnerable'
		  AND subject_type = 'certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&pqcEvidence); err != nil {
		t.Fatalf("read the pqc_vulnerable finding for the RSA-4096 certificate: %v", err)
	}
	var pqc struct {
		Vulnerable []string `json:"vulnerable_algorithms"`
	}
	if err := json.Unmarshal(pqcEvidence, &pqc); err != nil {
		t.Fatalf("pqc evidence is not the expected shape: %v\n%s", err, pqcEvidence)
	}
	if len(pqc.Vulnerable) != 1 || pqc.Vulnerable[0] != "RSA-4096" {
		t.Errorf("pqc_vulnerable cites %v, want [RSA-4096]", pqc.Vulnerable)
	}

	// And the asset is covered: a sized resolution is a measurement.
	var covered bool
	if err := f.owner.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM producer_assessments
		               WHERE tenant_id = $1 AND asset_id = $2 AND producer = 'crypto')`,
		f.tenant, f.assetID).Scan(&covered); err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	if !covered {
		t.Errorf("the asset serving the certificate is not marked assessed by crypto")
	}
}

// An RSA key of a size the catalogue does not carry resolves to NO catalogue
// row — not to the bare `RSA` row. The key-size floor still judges it, so a
// below-floor modulus is reported (RSA-1536 here scores at least the floor's
// High), but the score comes from the floor, not from a row about key
// transport, and the evidence names no catalogue match for the key.
func TestIntegration_CryptoProducer_UncataloguedRSASizeDoesNotBorrowTheBareRow(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	f.ensureCatalogueRow(t, "RSA", "key_exchange", "weak", "deprecated", 70, "pke")
	var sizedExists bool
	if err := f.owner.QueryRow(`SELECT EXISTS (SELECT 1 FROM algorithms WHERE UPPER(code) = 'RSA-1536')`).Scan(&sizedExists); err != nil {
		t.Fatalf("probe catalogue: %v", err)
	}
	if sizedExists {
		t.Skip("the catalogue now carries RSA-1536; pick another uncatalogued size")
	}

	cfg := f.configuration(t, "TLS 1.2", 0)
	certID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=odd.example.test', 'CN=Test CA', 'odd.example.test',
		        'RSA', 1536, 'sha256WithRSAEncryption', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfg, certID)

	f.mustRun(t, ctx)

	var evidence []byte
	if err := f.owner.QueryRow(`
		SELECT evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&evidence); err != nil {
		t.Fatalf("read the weak_certificate finding (the SP 800-131A floor must still fire on 1536 bits): %v", err)
	}
	var ev struct {
		Factors []string `json:"risk_factors"`
		Matches []struct {
			Field string `json:"field"`
			Code  string `json:"code"`
		} `json:"catalogue_matches"`
	}
	if err := json.Unmarshal(evidence, &ev); err != nil {
		t.Fatalf("evidence is not the expected shape: %v\n%s", err, evidence)
	}
	for _, m := range ev.Matches {
		if m.Field == "public_key_algorithm" {
			t.Errorf("an uncatalogued RSA size resolved to catalogue row %q; it must resolve to nothing", m.Code)
		}
	}
	if !contains(string(evidence), "SP 800-131A") {
		t.Errorf("the key-size floor did not fire on a 1536-bit RSA key: %v", ev.Factors)
	}
}

// ensureCatalogueRow returns the risk score of the catalogue row with this
// code, creating it — scoped to the test — when the database has no seed.
//
// The catalogue is platform-scoped (no tenant_id), so a row created here is
// removed on cleanup; a row that already exists (seed.sql's) is left exactly as
// it is, and its live risk score is what the caller asserts against.
func (f *cryptoFixture) ensureCatalogueRow(t *testing.T, code, category, strength, deprecation string, risk int, primitive string) int {
	t.Helper()
	var existing int
	err := f.owner.QueryRow(`SELECT COALESCE(risk_score, 0) FROM algorithms WHERE UPPER(code) = UPPER($1)`, code).Scan(&existing)
	switch {
	case err == nil:
		return existing
	case errors.Is(err, sql.ErrNoRows):
	default:
		t.Fatalf("probe catalogue row %s: %v", code, err)
	}
	id := uuid.New()
	exec(t, f.owner, `
		INSERT INTO algorithms (id, name, code, category, strength, deprecation_status, risk_score, is_pqc, primitive)
		VALUES ($1, $2, $2, $3, $4, $5, $6, false, $7)`,
		id, code, category, strength, deprecation, risk, primitive)
	t.Cleanup(func() { _, _ = f.owner.Exec(`DELETE FROM algorithms WHERE id = $1`, id) })
	return risk
}
