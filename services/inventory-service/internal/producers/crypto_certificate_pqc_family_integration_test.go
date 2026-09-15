package producers

// Whether a certificate is quantum-vulnerable is a question about its key's
// FAMILY, and it must survive the catalogue having no row for that key.
//
// The sibling files pin the SCORING rule: a certificate's public key is judged
// by the row for its modulus and never by the bare `RSA` row, which is the TLS
// key-transport assessment. That rule is right and these tests keep it.
// What it took with it was the PQC classification, because both were derived
// from the same row:
//
//   - an RSA key at a size the catalogue does not carry (RSA-1536, RSA-8192)
//     resolves to nothing, and so raised no pqc_vulnerable finding — it had
//     raised one before the sizing fix;
//   - an ECDSA certificate never raised one at all. `public_key_algorithm` is
//     the bare string "ECDSA" and the catalogue spells ECDSA only in
//     hash-named variants (ECDSA-SHA256 …), so the bare string resolves to
// nothing. This one long predates and was called out in it.
//
// Both are unambiguously Shor-breakable and both silently left the migration
// queue for want of a catalogue row. `algorithms.algorithm_family` and
// `primitive` already carry that taxonomy on every sized row, so the producer
// resolves the family separately from the row it scores by — which is what
// these tests drive, end to end, against a real catalogue.
//
// Score 0 stays NOT ASSESSED throughout: a family verdict says nothing about
// what a modulus is worth and must not invent a number. Each test asserts the
// weak_certificate side is exactly what the floor and the catalogue say, which
// for two of the three is no finding at all.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// An RSA certificate whose modulus the catalogue does not carry is unscored and
// still quantum-vulnerable.
//
// Two sizes, one pass, because they fail the SAME way for opposite reasons and
// only both together pin the rule:
//
//   - 8192 bits is above every floor, so nothing can score it — the finding
//     side is "no weak_certificate row at all", and the pqc side must be raised
//     anyway. Getting this wrong by borrowing the bare row is the original
//     key-transport bug; getting it wrong by staying silent is the regression
//     this test exists for.
//   - 1536 bits is below the SP 800-131A floor, so the floor scores it — the
//     number must be the FLOOR's, with no catalogue match for the key, which is
//     what tells a borrowed 70 from a floor 70 (they collide numerically, so
//     the evidence is the only witness).
//
// Mutation-checked, five ways, each against the assertion it is named for.
// Dropping the family fallback from certSubject.pqcVulnerableCodes (or never
// assigning certSubject.keyFamily) leaves both certificates with no
// pqc_vulnerable finding and both sub-cases fail. Letting the bare `RSA` row
// answer again — removing the `h.Category != catalogueCategoryKeyExchange`
// guard — puts a catalogue match on the key and scores the 8192-bit
// certificate 70, failing the evidence and the no-finding assertions. Letting a
// family verdict SCORE the certificate fails the same two, plus
// TestIntegration_CryptoProducer_ECDSACertificateIsQuantumVulnerable; letting it
// set `measurable` fails TestCertificateFamilyVerdictIsNotAMeasurement. Citing
// the family unconditionally rather than only when the key did not resolve
// fails TestIntegration_CryptoProducer_RSACertificatesScoreByTheirOwnSize and
// TestIntegration_CryptoProducer_DSACertificateKeepsItsSignatureRow, which want
// exactly one code.
func TestIntegration_CryptoProducer_UncataloguedRSASizesStayQuantumVulnerable(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	// The trap must exist, or "it did not borrow the bare row" is vacuous.
	bare := f.ensureCatalogueRow(t, "RSA", "key_exchange", "weak", "deprecated", 70, "pke")
	if bare == 0 {
		t.Fatal("the bare RSA row scores 0; this test cannot tell a borrowed verdict from no verdict")
	}
	f.requireVulnerableFamily(t, "RSA")

	type sizeCase struct {
		bits int
		// wantScore is the weak_certificate score, or 0 for "no finding".
		wantScore int
		why       string
	}
	cases := []sizeCase{
		{
			bits:      8192,
			wantScore: 0,
			why:       "above every floor and matching no catalogue row, so nothing can score it",
		},
		{
			bits:      1536,
			wantScore: cryptoparse.WeakCryptoSeverityScore(cryptoparse.WeakKeySizeSeverity("RSA", 1536)),
			why:       "below the SP 800-131A floor, which is the only thing that scores it",
		},
	}

	cfg := f.configuration(t, "TLS 1.2", 0)
	certIDs := make([]uuid.UUID, len(cases))
	for i, c := range cases {
		f.requireNoCatalogueCode(t, fmt.Sprintf("RSA-%d", c.bits))
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
	// The signature string these certificates carry must resolve to nothing, or
	// the pqc finding could be citing the SIGNATURE rather than the key and the
	// whole test would pass without the family ever being consulted.
	f.requireNoCatalogueCode(t, "sha256WithRSAEncryption")

	f.mustRun(t, ctx)

	for i, c := range cases {
		t.Run(fmt.Sprintf("RSA-%d", c.bits), func(t *testing.T) {
			if codes := pqcCodes(t, f, certIDs[i]); len(codes) != 1 || codes[0] != "RSA" {
				t.Errorf("a %d-bit RSA certificate's pqc_vulnerable finding cites %v, want [RSA] — "+
					"an RSA key is Shor-breakable at every modulus, including one the catalogue does not carry",
					c.bits, codes)
			}

			var score int
			var evidence []byte
			err := f.owner.QueryRow(`
				SELECT score, evidence FROM findings
				WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
				f.tenant, certIDs[i]).Scan(&score, &evidence)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if c.wantScore != 0 {
					t.Fatalf("no weak_certificate finding for a %d-bit RSA certificate, want score %d (%s)",
						c.bits, c.wantScore, c.why)
				}
				return
			case err != nil:
				t.Fatalf("read the weak_certificate finding: %v", err)
			}
			if c.wantScore == 0 {
				t.Fatalf("a %d-bit RSA certificate raised a weak_certificate finding scoring %d, want none "+
					"(%s; the bare RSA key-transport row scores %d): %s", c.bits, score, c.why, bare, evidence)
			}
			if score != c.wantScore {
				t.Errorf("a %d-bit RSA certificate scored %d, want %d — %s", c.bits, score, c.wantScore, c.why)
			}
			// The score and the bare row's 70 are numerically equal at 1536
			// bits, so this is what separates the floor from a borrowed row.
			if got := keyCatalogueCodes(t, evidence); len(got) != 0 {
				t.Errorf("a %d-bit RSA certificate resolved its key to %v, want no catalogue match at all — "+
					"a score of %d is only honest if it came from the floor", c.bits, got, score)
			}
		})
	}
}

// An ECDSA certificate is quantum-vulnerable, and scored by nothing.
//
// This one was never right: the catalogue has no bare `ECDSA` code — only
// ECDSA-SHA256 and its hash-named siblings, which are SIGNATURE-scheme rows —
// while `certificates.public_key_algorithm` is the bare family name crypto/x509
// prints. So every EC certificate in the estate resolved to no row and dropped
// out of the PQC classification, on a spelling mismatch rather than a
// judgement. NIST IR 8547 names ECDSA outright.
//
// P-256 is chosen deliberately: it is at the elliptic-curve floor
// (cryptoparse.MinECCKeySizeBits), so nothing scores it and the weak_certificate
// side must stay silent. "Quantum-vulnerable" and "weak today" are different
// statements and this certificate is the first but not the second.
//
// Mutation-checked: dropping the family fallback from
// certSubject.pqcVulnerableCodes leaves no pqc_vulnerable finding and the first
// assertion fails; letting a family verdict score the certificate raises a
// weak_certificate finding and the second fails.
func TestIntegration_CryptoProducer_ECDSACertificateIsQuantumVulnerable(t *testing.T) {
	f := newCryptoFixture(t)
	ctx := context.Background()

	f.requireVulnerableFamily(t, "ECDSA")
	// The premise: neither the key's spelling nor the signature's resolves to a
	// catalogue row. If either did, the finding could come from the row and the
	// family would never be consulted.
	f.requireNoCatalogueCode(t, "ECDSA")
	f.requireNoCatalogueCode(t, "ecdsa-with-SHA256")

	cfg := f.configuration(t, "TLS 1.3", 0)
	certID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, common_name,
		                          public_key_algorithm, public_key_size, signature_algorithm, fingerprint_sha256)
		VALUES ($1, $2, 'CN=ec.example.test', 'CN=Test CA', 'ec.example.test',
		        'ECDSA', 256, 'ecdsa-with-SHA256', $3)`,
		certID, f.tenant, fingerprint())
	exec(t, f.owner, `
		INSERT INTO crypto_implementation_certificates (crypto_implementation_id, certificate_id, certificate_role)
		VALUES ($1, $2, 'leaf')`, cfg, certID)

	f.mustRun(t, ctx)

	if codes := pqcCodes(t, f, certID); len(codes) != 1 || codes[0] != "ECDSA" {
		t.Errorf("an ECDSA P-256 certificate's pqc_vulnerable finding cites %v, want [ECDSA] — "+
			"NIST IR 8547 names ECDSA, and the catalogue carrying no bare `ECDSA` code is a spelling, not a verdict",
			codes)
	}

	var score int
	var evidence []byte
	err := f.owner.QueryRow(`
		SELECT score, evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_certificate' AND subject_id = $2`,
		f.tenant, certID).Scan(&score, &evidence)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Correct: a P-256 key is at the floor and matched no catalogue row, so
		// there is nothing to score it with. Score 0 is NOT ASSESSED.
	case err != nil:
		t.Fatalf("read the weak_certificate finding: %v", err)
	default:
		t.Errorf("an ECDSA P-256 certificate raised a weak_certificate finding scoring %d; knowing a key's "+
			"family is Shor-breakable is not a risk assessment of the key: %s", score, evidence)
	}
}

// A key in the inventory whose size could not be read is unscored and still
// quantum-vulnerable.
//
// The certificate half of this bug had a twin on the key path:
// key_producer.go's algorithmCodeForKey returned the bare `RSA` code for a key
// with no size, linking the Keys lens's Algorithm column to `RSA key transport
// (static)` — the very row stopped the certificate path borrowing. Fixing
// that alone would have taken the key's pqc_vulnerable finding with it, for
// exactly the reason the certificates above lost theirs, so the key path
// resolves its family too.
//
// The row here carries a NULL algorithm_id, which is what
// `algorithmCodeForKey("RSA", 0)` now produces (its `code ILIKE ”` matches
// nothing) and what every RSA key whose PEM could not be parsed will have.
//
// Mutation-checked: dropping the family fallback from
// keySubject.pqcVulnerableCode leaves no finding and the first assertion fails;
// making a family verdict `measurable` is invisible here (coverage is claimed
// either way) and is pinned by TestCertificateFamilyVerdictIsNotAMeasurement.
func TestIntegration_CryptoProducer_UnsizedRSAKeyStaysQuantumVulnerable(t *testing.T) {
	f := newCryptoFixture(t)

	f.requireVulnerableFamily(t, "RSA")
	cfg := f.configuration(t, "TLS 1.2", 0)

	keyID := uuid.New()
	exec(t, f.owner, `
		INSERT INTO keys (id, tenant_id, key_type, public_fingerprint,
		                  material_type, state, provenance)
		VALUES ($1, $2, 'RSA', $3, 'public-key', 'active', 'certificate')`,
		keyID, f.tenant, fingerprint())
	t.Cleanup(func() {
		_, _ = f.owner.Exec(`DELETE FROM implementation_keys WHERE key_id = $1`, keyID)
		_, _ = f.owner.Exec(`DELETE FROM keys WHERE id = $1`, keyID)
	})
	exec(t, f.owner, `INSERT INTO implementation_keys (implementation_id, key_id) VALUES ($1, $2)`,
		cfg, keyID)

	f.mustRun(t, context.Background())

	codes := f.pqcKeyCodes(t, keyID)
	if len(codes) != 1 || codes[0] != "RSA" {
		t.Errorf("an unsized RSA key's pqc_vulnerable finding cites %v, want [RSA] — an RSA key is "+
			"Shor-breakable whether or not anything could read its modulus", codes)
	}

	// And the key is NOT scored: the row it would have borrowed rates static
	// RSA key transport 70, which is a statement about forward secrecy in a
	// TLS handshake, not about this key.
	var algoCode sql.NullString
	if err := f.owner.QueryRow(`
		SELECT alg.code FROM keys k LEFT JOIN algorithms alg ON alg.id = k.algorithm_id
		 WHERE k.id = $1`, keyID).Scan(&algoCode); err != nil {
		t.Fatalf("read the key's catalogue row: %v", err)
	}
	if algoCode.Valid {
		t.Errorf("the unsized key resolved to catalogue row %q, want none", algoCode.String)
	}
}

// The family taxonomy is the same DENYLIST, applied to a family instead of a
// row — so it stays silent about everything Shor does not break.
//
// This is the half that makes the fallback safe to have at all. A family-level
// answer widens what can be classified, and the way that goes wrong is an
// allowlist in disguise: the previous {ae, hash, mac} allowlist in
// pqc_readiness.go misclassified 11 catalogue algorithms, plain AES128 and
// AES256 among them. The verdict here is the same expression
// cryptoassess.PQCClassCTE uses — `NOT is_pqc AND primitive = ANY(denylist)` —
// with the grouping moved to `algorithm_family`, so both halves of it have to
// hold.
//
// Key rows rather than certificates, because a key's `key_type` is free text
// and can name a family directly; a certificate cannot carry an AES public key.
// The RSA key is the CONTROL: without it, a run in which the family lookup
// never executed at all would pass every negative assertion.
//
// Mutation-checked: dropping `NOT COALESCE(is_pqc, false)` from
// resolveFamilyTaxonomy's verdict raises a finding on the ML-DSA key, and
// dropping the `primitive = ANY(...)` filter (which is what inverting the
// denylist into an allowlist of "safe" primitives amounts to) raises one on the
// AES key.
func TestIntegration_CryptoProducer_FamilyTaxonomyKeepsTheDenylist(t *testing.T) {
	f := newCryptoFixture(t)

	cfg := f.configuration(t, "TLS 1.2", 0)
	// Every key here is inserted with NO algorithm_id, which is the premise:
	// the row lookup has nothing to say and the family is the only thing that
	// can answer. (Unlike a certificate, a key resolves through a stored
	// foreign key rather than a string, so an existing catalogue code with the
	// same spelling is irrelevant.)
	insert := func(keyType string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		exec(t, f.owner, `
			INSERT INTO keys (id, tenant_id, key_type, public_fingerprint,
			                  material_type, state, provenance)
			VALUES ($1, $2, $3, $4, 'public-key', 'active', 'certificate')`,
			id, f.tenant, keyType, fingerprint())
		t.Cleanup(func() {
			_, _ = f.owner.Exec(`DELETE FROM implementation_keys WHERE key_id = $1`, id)
			_, _ = f.owner.Exec(`DELETE FROM keys WHERE id = $1`, id)
		})
		exec(t, f.owner, `INSERT INTO implementation_keys (implementation_id, key_id) VALUES ($1, $2)`, cfg, id)
		return id
	}

	f.requireVulnerableFamily(t, "RSA")
	classical := insert("RSA")
	symmetric := f.familyKey(t, insert, "AES", "ae")
	postQuantum := f.familyKey(t, insert, "ML-DSA", "signature")

	var resolved int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM keys WHERE tenant_id = $1 AND id = ANY($2) AND algorithm_id IS NOT NULL`,
		f.tenant, pq.Array([]uuid.UUID{classical, symmetric, postQuantum})).Scan(&resolved); err != nil {
		t.Fatalf("check the keys resolved to no catalogue row: %v", err)
	}
	if resolved != 0 {
		t.Fatalf("%d of the keys point at a catalogue row; this test is about what the FAMILY says when "+
			"the row says nothing", resolved)
	}

	f.mustRun(t, context.Background())

	got := f.pqcSubjects(t, "key")
	if !got[classical] {
		t.Fatal("the RSA control raised no pqc_vulnerable finding — the family lookup did not run, " +
			"so the two negative cases below prove nothing")
	}
	if got[symmetric] {
		t.Error("a key whose family is symmetric raised pqc_vulnerable — the family verdict has stopped " +
			"being a denylist of Shor-breakable primitives, which is how plain AES gets reported as needing migration")
	}
	if got[postQuantum] {
		t.Error("a key whose family is already post-quantum raised pqc_vulnerable")
	}
}

// familyKey guards a family-negative case: the family must exist in the
// catalogue with the shape the case is about, or the "raised nothing" assertion
// passes for the wrong reason — a family the catalogue has never heard of also
// raises nothing.
func (f *cryptoFixture) familyKey(t *testing.T, insert func(string) uuid.UUID, family, wantPrimitive string) uuid.UUID {
	t.Helper()
	var rows int
	if err := f.owner.QueryRow(`
		SELECT COUNT(*) FROM algorithms
		 WHERE UPPER(algorithm_family) = UPPER($1) AND primitive = $2`, family, wantPrimitive).Scan(&rows); err != nil {
		t.Fatalf("probe the %s family: %v", family, err)
	}
	if rows == 0 {
		t.Skipf("the catalogue carries no %s row with primitive %q; this case needs one to be a real negative",
			family, wantPrimitive)
	}
	return insert(family)
}

// A family verdict is not a measurement.
//
// [certSubject.assess] answers "what is this certificate worth", and the family
// taxonomy must contribute nothing to it — not to the score, not to the risk
// factors, and above all not to `measurable`, which is the producer's claim to
// have assessed the asset. "We know this key is RSA" is not "we know what this
// modulus is worth", and recording the first as the second is precisely the
// score-0-means-not-assessed confusion this producer is built around.
//
// A unit test rather than an integration one because `measurable` is not
// separately observable through the database: where a family verdict fires, the
// pqc_vulnerable finding it raises claims coverage on its own (that finding
// feeds risk, so the asset must not be scored by a producer whose coverage
// record says it never looked). This is the only place the two can be told
// apart.
//
// Mutation-checked: setting `measurable = true` from c.keyFamily.Vulnerable in
// assess, or adding the family to c.catalogue in resolveFamilyTaxonomy, fails
// this test.
func TestCertificateFamilyVerdictIsNotAMeasurement(t *testing.T) {
	c := certSubject{
		label:     "family-only.example.test",
		keyAlg:    "RSA",
		keyFamily: familyTaxonomy{Family: "RSA", Vulnerable: true},
	}

	score, factors, measurable := c.assess()
	if measurable {
		t.Error("a certificate known only by its family reports measurable=true — its asset is now " +
			"recorded as assessed by crypto on the strength of a taxonomy lookup")
	}
	if score != 0 {
		t.Errorf("assess scored a family-only certificate %d, want 0 (NOT ASSESSED)", score)
	}
	if len(factors) != 0 {
		t.Errorf("assess cited %v as risk factors for a family-only certificate, want none", factors)
	}

	// And the classification is made regardless: unscored, still in the queue.
	if codes := c.pqcVulnerableCodes(); len(codes) != 1 || codes[0] != "RSA" {
		t.Errorf("pqcVulnerableCodes = %v, want [RSA]", codes)
	}
}

// The family verdict yields to a row that actually resolved.
//
// A certificate whose public key resolved to its own catalogue row cites that
// row and nothing else, so an RSA-4096 certificate keeps reporting exactly
// `RSA-4096` rather than `RSA-4096, RSA`. The gate is on the KEY having
// resolved rather than on the code list being empty, because a certificate's
// signature algorithm is the ISSUER's — a signature row that resolved has said
// nothing about this certificate's key, and the family must still answer for it.
func TestCertificateFamilyVerdictYieldsToAResolvedKeyRow(t *testing.T) {
	family := familyTaxonomy{Family: "RSA", Vulnerable: true}
	keyRow := catalogueHit{Field: certFieldPublicKey, Code: "RSA-4096", Primitive: "pke"}
	sigRow := catalogueHit{Field: "signature_algorithm", Code: "RSA-SHA256", Primitive: "signature"}
	pqcKeyRow := catalogueHit{Field: certFieldPublicKey, Code: "ML-DSA-65", Primitive: "signature", IsPQC: true}

	for _, tc := range []struct {
		name  string
		cert  certSubject
		codes []string
	}{
		{
			name:  "the key resolved, so the family stays silent",
			cert:  certSubject{keyAlg: "RSA", catalogue: []catalogueHit{keyRow}, keyFamily: family},
			codes: []string{"RSA-4096"},
		},
		{
			name: "only the signature resolved, so the family still answers for the key",
			cert: certSubject{keyAlg: "RSA", catalogue: []catalogueHit{sigRow},
				keyFamily: family},
			codes: []string{"RSA-SHA256", "RSA"},
		},
		{
			name: "a post-quantum key row silences the family without citing anything",
			cert: certSubject{keyAlg: "ML-DSA-65", catalogue: []catalogueHit{pqcKeyRow},
				keyFamily: familyTaxonomy{Family: "ML-DSA", Vulnerable: false}},
			codes: nil,
		},
		{
			name:  "nothing resolved and the family is not classical: unclassified",
			cert:  certSubject{keyAlg: "AES", keyFamily: familyTaxonomy{Family: "AES", Vulnerable: false}},
			codes: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cert.pqcVulnerableCodes()
			if len(got) != len(tc.codes) {
				t.Fatalf("pqcVulnerableCodes = %v, want %v", got, tc.codes)
			}
			for i := range got {
				if got[i] != tc.codes[i] {
					t.Fatalf("pqcVulnerableCodes = %v, want %v", got, tc.codes)
				}
			}
		})
	}
}

// pqcKeyCodes is the algorithms a KEY's pqc_vulnerable finding cites, or nil
// when there is no such finding. The certificate-subject counterpart is
// pqcCodes, in the sibling family file.
func (f *cryptoFixture) pqcKeyCodes(t *testing.T, keyID uuid.UUID) []string {
	t.Helper()
	var evidence []byte
	err := f.owner.QueryRow(`
		SELECT evidence FROM findings
		WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'pqc_vulnerable'
		  AND subject_type = 'key' AND subject_id = $2 AND detection_state = 'ACTIVE'`,
		f.tenant, keyID).Scan(&evidence)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatalf("read the key's pqc_vulnerable finding: %v", err)
	}
	var pqc struct {
		Vulnerable []string `json:"vulnerable_algorithms"`
	}
	if err := json.Unmarshal(evidence, &pqc); err != nil {
		t.Fatalf("pqc evidence is not the expected shape: %v\n%s", err, evidence)
	}
	return pqc.Vulnerable
}

// requireVulnerableFamily guarantees the catalogue states somewhere that this
// family is classically asymmetric, creating a test-scoped row when the
// database carries no seed.
//
// The row it creates is deliberately useless for anything else: a unique code
// nothing will look up and a risk score of 0, so it can supply taxonomy without
// supplying a verdict. On a seeded database (what nightly and
// `make test-integration-db` run) it creates nothing and the real rows answer.
func (f *cryptoFixture) requireVulnerableFamily(t *testing.T, family string) {
	t.Helper()
	var vulnerable bool
	if err := f.owner.QueryRow(`
		SELECT COALESCE(bool_or(NOT COALESCE(is_pqc, false) AND primitive = ANY($2::text[])), false)
		  FROM algorithms WHERE UPPER(algorithm_family) = UPPER($1)`,
		family, pq.Array(cryptoassess.QuantumVulnerablePrimitives)).Scan(&vulnerable); err != nil {
		t.Fatalf("probe the %s family: %v", family, err)
	}
	if vulnerable {
		return
	}
	id := uuid.New()
	code := family + "-TAXONOMY-" + uuid.New().String()[:8]
	exec(t, f.owner, `
		INSERT INTO algorithms (id, name, code, category, strength, deprecation_status, risk_score,
		                        is_pqc, primitive, algorithm_family)
		VALUES ($1, $2, $2, 'signature', 'acceptable', 'current', 0, false, 'signature', $3)`,
		id, code, family)
	t.Cleanup(func() { _, _ = f.owner.Exec(`DELETE FROM algorithms WHERE id = $1`, id) })
}

// requireNoCatalogueCode skips the test when the catalogue has grown a row for
// this spelling.
//
// Every test here is about what happens when a string resolves to NO row. If
// the catalogue later carries one, the test is no longer exercising that and
// must say so rather than pass on a different path — the same guard the sibling
// files put in front of RSA-1536 and RSA-8192. Both spellings the resolver
// tries are probed, exactly as it tries them.
func (f *cryptoFixture) requireNoCatalogueCode(t *testing.T, observed string) {
	t.Helper()
	var exists bool
	if err := f.owner.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM algorithms WHERE UPPER(code) = UPPER($1) OR UPPER(code) = UPPER($2))`,
		observed, cryptoparse.NormalizeComponentCode(observed)).Scan(&exists); err != nil {
		t.Fatalf("probe catalogue for %q: %v", observed, err)
	}
	if exists {
		t.Skipf("the catalogue now carries a row for %q; this test's subject is a spelling that resolves to NOTHING", observed)
	}
}
