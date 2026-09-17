package producers

// Which catalogue row a certificate's PUBLIC KEY resolves to, per family and
// per size, against a real Postgres.
//
// crypto_certificate_lookup_integration_test.go pins the headline rule: an RSA
// certificate is scored by the row for its modulus, never by the bare `RSA`
// row, which is the TLS key-transport assessment. This file pins the two edges
// of that rule, which are the two places it can go wrong in opposite
// directions:
//
//   - the selection is by SIZE, not merely "not the bare row" — three sizes,
//     three rows, three scores;
//   - a family the catalogue does NOT size keeps its bare row (DSA), while a
//     family it DOES size gets nothing at a size it lacks (RSA-8192). Getting
//     that backwards either scores a 2048-bit DSA key clean or puts an
//     8192-bit RSA key back at High.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// The RSA sizes the catalogue carries, end to end: each certificate is scored
// by the row for ITS size and by no other row.
//
// The single-certificate test in the sibling file proves the sized row is
// preferred; this one proves the SELECTION is by size rather than "any row that
// is not the bare one" — three certificates, three different catalogue rows,
// three different scores, in one pass over one tenant. The expected numbers are
// read back from the catalogue rows themselves rather than written here as
// literals, which is the discipline catalogue_risk_integration_test.go uses:
// editing a row must MOVE the score, so a literal would turn that into a
// failure.
//
// Mutation-checked: resolving the bare `RSA` row instead gives all three the
// same score (70) and the same code, and every sub-case fails.
func TestIntegration_CryptoProducer_RSACertificatesScoreByTheirOwnSize(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	bare := f.ensureCatalogueRow(t, "RSA", "key_exchange", "weak", "deprecated", 70, "pke")

	type sizeCase struct {
		bits int
		code string
		risk int
	}
	cases := []sizeCase{
		{1024, "RSA-1024", f.ensureCatalogueRow(t, "RSA-1024", "key_exchange", "weak", "deprecated", 80, "pke")},
		{2048, "RSA-2048", f.ensureCatalogueRow(t, "RSA-2048", "key_exchange", "acceptable", "current", 40, "pke")},
		{4096, "RSA-4096", f.ensureCatalogueRow(t, "RSA-4096", "key_exchange", "strong", "current", 25, "pke")},
	}
	// Four DISTINCT scores, or the assertions below cannot tell the rows apart.
	seen := map[int]bool{bare: true}
	for _, c := range cases {
		if seen[c.risk] {
			t.Fatalf("catalogue: %s scores %d, which is not distinct from the rows already in this test; the assertions could not tell them apart", c.code, c.risk)
		}
		seen[c.risk] = true
	}

	cfg := f.configuration(t, "TLS 1.2", 0)
	certIDs := make([]uuid.UUID, len(cases))
	for i, c := range cases {
		certIDs[i] = uuid.New()
		exec(t, f.owner, `
			INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
			                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
			VALUES ($1, $2, $3, 'CN=Test CA', $4, 'RSA', $5, 'sha256WithRSAEncryption', $6)`,
			certIDs[i], f.tenant,
			fmt.Sprintf("CN=rsa-%d.example.test", c.bits), fmt.Sprintf("rsa-%d.example.test", c.bits),
			c.bits, fingerprint())
		exec(t, f.owner, `
			INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
			VALUES ($1, $2, 'leaf')`, cfg, certIDs[i])
	}

	f.mustRun(t, ctx)

	for i, c := range cases {
		if c.bits == 4096 {
			var count int
			if err := f.owner.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id=$1 AND kind='weak_certificate' AND subject_id=$2`, f.tenant, certIDs[i]).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("strong RSA-4096 raised %d weak findings", count)
			}
			if codes := pqcCodes(t, f, certIDs[i]); len(codes) != 1 || codes[0] != c.code {
				t.Fatalf("PQC codes=%v", codes)
			}
			continue
		}
		var score int
		var evidence []byte
		if err := f.owner.QueryRow(`
			SELECT score, evidence FROM findings
			WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
			f.tenant, certIDs[i]).Scan(&score, &evidence); err != nil {
			t.Fatalf("read the weak_certificate finding for the %d-bit certificate: %v", c.bits, err)
		}
		if score != c.risk {
			t.Errorf("%d-bit RSA certificate scored %d, want the %s row's %d (the bare RSA row scores %d)",
				c.bits, score, c.code, c.risk, bare)
		}
		if got := keyCatalogueCodes(t, evidence); len(got) != 1 || got[0] != c.code {
			t.Errorf("%d-bit RSA certificate resolved its key to %v, want exactly [%s]", c.bits, got, c.code)
		}
		if codes := pqcCodes(t, f, certIDs[i]); len(codes) != 1 || codes[0] != c.code {
			t.Errorf("%d-bit RSA certificate's pqc_vulnerable finding cites %v, want [%s]", c.bits, codes, c.code)
		}
	}
}

// A DSA certificate keeps the bare `DSA` catalogue row, at every size.
//
// The bare-row rule the sibling file enforces is about the bare `RSA` row,
// which is `key_exchange` — the TLS key-transport mechanism, not a statement
// about a certified key. The bare `DSA` row is a `signature` row, and what it
// says (signature generation withdrawn in FIPS 186-5; weak, deprecated) is true
// of a DSA public key of any size. The catalogue carries no `DSA-<bits>` rows
// at all, so dropping the bare row for EVERY finite-field family took a
// DSA-2048 certificate from High to no finding and no pqc_vulnerable at all:
// scored clean and out of the quantum-migration queue, on the strength of a row
// the catalogue does not have.
//
// Mutation-checked: removing the `h.Category != catalogueCategoryKeyExchange`
// fallback in resolveCertificateAlgorithms leaves this certificate with no
// weak_certificate finding and no pqc_vulnerable finding, and both assertions
// fail. Widening that fallback to accept ANY bare row instead fails
// TestIntegration_CryptoProducer_ASizedFamilyDoesNotBorrowItsKeyExchangeRow.
func TestIntegration_CryptoProducer_DSACertificateKeepsItsSignatureRow(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	bareDSA := f.ensureCatalogueRow(t, "DSA", "signature", "weak", "deprecated", 70, "signature")
	var sizedExists bool
	if err := f.owner.QueryRow(`SELECT EXISTS (SELECT 1 FROM algorithms WHERE UPPER(code) = 'DSA-2048')`).Scan(&sizedExists); err != nil {
		t.Fatalf("probe catalogue: %v", err)
	}
	if sizedExists {
		t.Skip("the catalogue now sizes DSA; this test's subject is the UNSIZED fallback")
	}

	cfg := f.configuration(t, "TLS 1.2", 0)
	certID := uuid.New()
	// 2048 bits: at the SP 800-131A floor, so the floor contributes nothing and
	// the catalogue row is the only thing that can score this certificate.
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=dsa.example.test', 'CN=Test CA', 'dsa.example.test',
		        'DSA', 2048, 'dsaWithSHA256', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfg, certID)

	f.mustRun(t, ctx)

	var score int
	var evidence []byte
	if err := f.owner.QueryRow(`
		SELECT score, evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&score, &evidence); err != nil {
		t.Fatalf("read the weak_certificate finding for a DSA-2048 certificate (the bare DSA row scores %d): %v", bareDSA, err)
	}
	if score != bareDSA {
		t.Errorf("DSA-2048 certificate scored %d, want the bare DSA row's %d", score, bareDSA)
	}
	if got := keyCatalogueCodes(t, evidence); len(got) != 1 || got[0] != "DSA" {
		t.Errorf("DSA-2048 certificate resolved its key to %v, want exactly [DSA]", got)
	}
	if codes := pqcCodes(t, f, certID); len(codes) != 1 || codes[0] != "DSA" {
		t.Errorf("DSA-2048 certificate's pqc_vulnerable finding cites %v, want [DSA] — a DSA key is Shor-breakable whatever its size", codes)
	}
}

// An RSA key at a size the catalogue does not carry does NOT fall back to the
// bare `RSA` row, even though a DSA key falls back to the bare `DSA` one.
//
// 8192 bits is the case that separates the two rules: it is above every floor,
// so nothing else can score it, and borrowing the key-transport row would put a
// stronger-than-recommended key back at High — the original bug, surviving at
// one size. The RSA-1536 test in the sibling file shows the same resolution
// with the floor firing; this one shows it with nothing else in the way.
//
// Mutation-checked: dropping the `h.Category != catalogueCategoryKeyExchange`
// condition raises a weak_certificate finding scoring the bare row's 70 and
// this test fails.
func TestIntegration_CryptoProducer_ASizedFamilyDoesNotBorrowItsKeyExchangeRow(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	bare := f.ensureCatalogueRow(t, "RSA", "key_exchange", "weak", "deprecated", 70, "pke")
	if bare == 0 {
		t.Fatalf("the bare RSA row scores 0; this test cannot tell a borrowed verdict from no verdict")
	}
	var sizedExists bool
	if err := f.owner.QueryRow(`SELECT EXISTS (SELECT 1 FROM algorithms WHERE UPPER(code) = 'RSA-8192')`).Scan(&sizedExists); err != nil {
		t.Fatalf("probe catalogue: %v", err)
	}
	if sizedExists {
		t.Skip("the catalogue now carries RSA-8192; pick another uncatalogued size above the floor")
	}

	cfg := f.configuration(t, "TLS 1.3", 0)
	certID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=huge.example.test', 'CN=Test CA', 'huge.example.test',
		        'RSA', 8192, 'sha256WithRSAEncryption', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfg, certID)

	f.mustRun(t, ctx)

	var score int
	var evidence []byte
	err := f.owner.QueryRow(`
		SELECT score, evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&score, &evidence)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Correct: no sized row, no borrowable row, nothing above a floor.
	case err != nil:
		t.Fatalf("read the weak_certificate finding: %v", err)
	default:
		t.Errorf("an 8192-bit RSA certificate raised a weak_certificate finding scoring %d (the bare RSA key-transport row scores %d); it must resolve to no catalogue row at all: %s",
			score, bare, evidence)
	}
}

// keyCatalogueCodes is the catalogue codes a finding's evidence says the
// certificate's PUBLIC KEY resolved to.
func keyCatalogueCodes(t *testing.T, evidence []byte) []string {
	t.Helper()
	var ev struct {
		Matches []struct {
			Field string `json:"field"`
			Code  string `json:"code"`
		} `json:"catalogue_matches"`
	}
	if err := json.Unmarshal(evidence, &ev); err != nil {
		t.Fatalf("evidence is not the expected shape: %v\n%s", err, evidence)
	}
	var out []string
	for _, m := range ev.Matches {
		if m.Field == "public_key_algorithm" {
			out = append(out, m.Code)
		}
	}
	return out
}

// pqcCodes is the algorithms the certificate's pqc_vulnerable finding cites, or
// nil when there is no such finding.
func pqcCodes(t *testing.T, f *cryptoFixture, certID uuid.UUID) []string {
	t.Helper()
	var evidence []byte
	err := f.owner.QueryRow(`
		SELECT evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'pqc_vulnerable'
		  AND subject_type = 'certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&evidence)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatalf("read the pqc_vulnerable finding: %v", err)
	}
	var pqc struct {
		Vulnerable []string `json:"vulnerable_algorithms"`
	}
	if err := json.Unmarshal(evidence, &pqc); err != nil {
		t.Fatalf("pqc evidence is not the expected shape: %v\n%s", err, evidence)
	}
	return pqc.Vulnerable
}
