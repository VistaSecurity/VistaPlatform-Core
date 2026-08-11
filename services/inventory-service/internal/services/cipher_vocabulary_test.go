package services

// Guards for the cipher-suite parser vocabulary and its resolution against the
// algorithm catalogue.
//
// The parsers are the only producer of the component values that (a) become
// crypto_implementation_algorithms links, (b) fill the component columns of
// crypto_implementations, and (c) are matched literally by the compliance
// engine's seeded measurement predicates. If a parser emits a string that is
// not a catalogue code, every one of those three consumers silently degrades:
// links land on whatever row happened to contain the substring, columns hold a
// vocabulary nothing matches, and controls evaluate against nothing.
//
// These tests need no database — the catalogue is injected.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// cryptoImplWithSuite builds the minimal implementation the detector needs.
func cryptoImplWithSuite(cipherSuite string) *models.CryptoImplementation {
	return &models.CryptoImplementation{ID: uuid.New(), CipherSuite: &cipherSuite}
}

// fakeCatalogue mirrors the shape of the seeded `algorithms` table closely
// enough to reproduce the mis-resolutions this work package fixes: the SMB and
// IPSec rows are here precisely because "AES-256-GCM" and "CHACHA20-POLY1305"
// used to land on them.
func fakeCatalogue() []Algorithm {
	mk := func(code, category string, risk int) Algorithm {
		return Algorithm{ID: uuid.New(), Code: code, Category: category, RiskScore: risk, Strength: "strong"}
	}
	return []Algorithm{
		// symmetric
		mk("AES128", "symmetric", 25),
		mk("AES256", "symmetric", 15),
		mk("ChaCha20", "symmetric", 20), // NB: mixed case in the real seed
		mk("3DES", "symmetric", 70),
		mk("DES", "symmetric", 95),
		mk("RC4", "symmetric", 90),
		mk("NULL", "symmetric", 99),
		mk("SMB-AES-256-GCM", "symmetric", 15),
		mk("SMB-AES-128-GCM", "symmetric", 20),
		mk("ENCR-CHACHA20-POLY1305-IPSEC", "symmetric", 15),
		// hash
		mk("SHA1", "hash", 75),
		mk("SHA256", "hash", 20),
		mk("SHA384", "hash", 15),
		mk("SHA512", "hash", 15),
		mk("MD5", "hash", 90),
		// key exchange
		mk("ECDHE", "key_exchange", 15),
		mk("DHE", "key_exchange", 35),
		mk("ECDH", "key_exchange", 65),
		mk("DH", "key_exchange", 70),
		mk("RSA", "key_exchange", 70),
		mk("RSA-1024", "key_exchange", 80),
		mk("RSA-2048", "key_exchange", 40),
		mk("X25519", "key_exchange", 15),
		// signature (deliberately several RSA-* rows: "RSA" must stay ambiguous here)
		mk("RSA-SHA256", "signature", 20),
		mk("RSA-SHA384", "signature", 20),
		mk("RSA-MD5", "signature", 90),
		mk("ECDSA-SHA256", "signature", 15),
		// protocol / suite containers
		mk("TLS1.2", "protocol_version", 25),
		mk("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "cipher_suite", 10),
	}
}

func catalogueService(t *testing.T) *AlgorithmService {
	t.Helper()
	s := &AlgorithmService{}
	s.setCatalogueForTest(fakeCatalogue())
	return s
}

// TestParseCipherSuite_EmitsCatalogueVocabulary pins the producer half of the
// contract: what the parsers emit for real, on-the-wire suite names.
func TestParseCipherSuite_EmitsCatalogueVocabulary(t *testing.T) {
	s := &AlgorithmService{}

	cases := []struct {
		suite                        string
		kex, sig, symmetric, hashAlg string
	}{
		// TLS 1.2 and earlier, IANA spelling
		{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "AES256", "SHA384"},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AES256", "SHA384"},
		{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AES128", "SHA256"},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", "SHA1"},
		{"TLS_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", "DES", "SHA1"},
		{"TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4", "SHA1"},
		{"TLS_RSA_WITH_NULL_MD5", "RSA", "RSA", "NULL", "MD5"},
		{"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE", "DSA", "AES256", "SHA256"},
		// static (non-forward-secret) forms must NOT be reported as plain RSA
		{"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDH", "RSA", "AES128", "SHA256"},
		{"TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "DH", "RSA", "AES256", "SHA256"},
		// TLS 1.3
		{"TLS_AES_256_GCM_SHA384", "ECDHE", "", "AES256", "SHA384"},
		{"TLS_AES_128_GCM_SHA256", "ECDHE", "", "AES128", "SHA256"},
		{"TLS_CHACHA20_POLY1305_SHA256", "ECDHE", "", "CHACHA20", "SHA256"},
		// abbreviated / OpenSSL spellings
		{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", "RSA", "AES256", "SHA384"},
		{"DES-CBC3-SHA", "", "", "3DES", "SHA1"}, // OpenSSL's name for triple DES
		{"RC4-MD5", "", "", "RC4", "MD5"},
		{"AES128-SHA", "", "", "AES128", "SHA1"},
	}

	for _, tc := range cases {
		t.Run(tc.suite, func(t *testing.T) {
			got, err := s.ParseCipherSuite(tc.suite)
			if err != nil || got == nil {
				t.Fatalf("ParseCipherSuite(%q) failed: %v", tc.suite, err)
			}
			if got.KeyExchange != tc.kex {
				t.Errorf("key exchange = %q, want %q", got.KeyExchange, tc.kex)
			}
			if got.Signature != tc.sig {
				t.Errorf("signature = %q, want %q", got.Signature, tc.sig)
			}
			if got.Symmetric != tc.symmetric {
				t.Errorf("symmetric = %q, want %q", got.Symmetric, tc.symmetric)
			}
			if got.Hash != tc.hashAlg {
				t.Errorf("hash = %q, want %q", got.Hash, tc.hashAlg)
			}
		})
	}
}

// TestParseCipherSuite_NeverEmitsModeDecoratedNames is the mutation guard for
// the specific regression: any code containing a mode suffix is not a catalogue
// code and will resolve by accident or not at all.
func TestParseCipherSuite_NeverEmitsModeDecoratedNames(t *testing.T) {
	s := &AlgorithmService{}
	suites := []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_CHACHA20_POLY1305_SHA256",
		"ECDHE-RSA-CHACHA20-POLY1305",
		"AES256-GCM-SHA384",
	}
	allowed := map[string]bool{
		"AES128": true, "AES256": true, "CHACHA20": true,
		"3DES": true, "DES": true, "RC4": true, "NULL": true, "": true,
	}
	for _, suite := range suites {
		got, err := s.ParseCipherSuite(suite)
		if err != nil || got == nil {
			t.Fatalf("ParseCipherSuite(%q) failed: %v", suite, err)
		}
		if !allowed[got.Symmetric] {
			t.Errorf("%s: symmetric %q is outside the agreed vocabulary", suite, got.Symmetric)
		}
	}
}

// TestClassifyAlgorithm_ResolvesToTheRightCatalogueRow is the consumer half:
// every component of a representative suite must land on the row a
// cryptographer would name, and specifically NOT on the SMB or IPSec rows that
// merely share a substring.
func TestClassifyAlgorithm_ResolvesToTheRightCatalogueRow(t *testing.T) {
	s := catalogueService(t)

	type want struct{ code, category string }
	cases := []struct {
		suite      string
		components map[string]want // algorithm_type -> expected row ("" = must not resolve)
	}{
		{
			suite: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
			components: map[string]want{
				"key_exchange": {"ECDHE", "key_exchange"},
				"symmetric":    {"AES256", "symmetric"},
				"hash":         {"SHA384", "hash"},
				"signature":    {"", "signature"}, // bare "RSA" is ambiguous among RSA-* signature rows
			},
		},
		{
			suite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			components: map[string]want{
				"key_exchange": {"RSA", "key_exchange"},
				"symmetric":    {"3DES", "symmetric"},
				"hash":         {"SHA1", "hash"},
			},
		},
		{
			suite: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
			components: map[string]want{
				"key_exchange": {"ECDH", "key_exchange"},
				"symmetric":    {"AES128", "symmetric"},
				"hash":         {"SHA256", "hash"},
			},
		},
		{
			suite: "TLS_CHACHA20_POLY1305_SHA256",
			components: map[string]want{
				"key_exchange": {"ECDHE", "key_exchange"},
				"symmetric":    {"ChaCha20", "symmetric"}, // case-insensitive match on the mixed-case code
				"hash":         {"SHA256", "hash"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.suite, func(t *testing.T) {
			parsed, err := s.ParseCipherSuite(tc.suite)
			if err != nil || parsed == nil {
				t.Fatalf("ParseCipherSuite failed: %v", err)
			}
			value := map[string]string{
				"key_exchange": parsed.KeyExchange,
				"signature":    parsed.Signature,
				"symmetric":    parsed.Symmetric,
				"hash":         parsed.Hash,
			}
			for role, w := range tc.components {
				alg, err := s.ClassifyAlgorithm(value[role], role)
				if err != nil {
					t.Fatalf("%s: ClassifyAlgorithm(%q) errored: %v", role, value[role], err)
				}
				if w.code == "" {
					if alg != nil {
						t.Errorf("%s: %q resolved to %q — it is ambiguous and must stay unlinked",
							role, value[role], alg.Code)
					}
					continue
				}
				if alg == nil {
					t.Fatalf("%s: %q resolved to nothing, want %q", role, value[role], w.code)
				}
				if alg.Code != w.code {
					t.Errorf("%s: %q resolved to %q, want %q", role, value[role], alg.Code, w.code)
				}
				if alg.Category != w.category {
					t.Errorf("%s: %q resolved into category %q, want %q", role, value[role], alg.Category, w.category)
				}
			}
		})
	}
}

// TestClassifyAlgorithm_UnknownStaysUnassessed pins the no-fabrication rule:
// an algorithm nobody has assessed must produce no link, not a fresh catalogue
// row rated "acceptable" with risk 50.
func TestClassifyAlgorithm_UnknownStaysUnassessed(t *testing.T) {
	s := catalogueService(t)
	for _, unknown := range []string{"CAMELLIA256", "SEED-CBC", "SOME-VENDOR-CIPHER"} {
		alg, err := s.ClassifyAlgorithm(unknown, "symmetric")
		if err != nil {
			t.Fatalf("ClassifyAlgorithm(%q) errored: %v", unknown, err)
		}
		if alg != nil {
			t.Errorf("%q was resolved to %q (risk %d) — unknown algorithms must stay unassessed",
				unknown, alg.Code, alg.RiskScore)
		}
	}
}

// TestClassifyAlgorithm_CaseInsensitiveExactMatch is the mutation guard for the
// case-sensitivity half of the finding.
func TestClassifyAlgorithm_CaseInsensitiveExactMatch(t *testing.T) {
	s := catalogueService(t)
	for _, spelling := range []string{"CHACHA20", "chacha20", "ChaCha20"} {
		alg, err := s.ClassifyAlgorithm(spelling, "symmetric")
		if err != nil {
			t.Fatalf("ClassifyAlgorithm(%q) errored: %v", spelling, err)
		}
		if alg == nil || alg.Code != "ChaCha20" {
			t.Fatalf("ClassifyAlgorithm(%q) = %v, want the ChaCha20 row", spelling, alg)
		}
	}
}

// TestClassifyAlgorithm_CategoryScoped: "RSA" names a key-exchange row AND the
// authentication half of every ECDHE_RSA suite. Resolving the signature against
// the key-exchange row would attach a no-forward-secrecy verdict to a suite
// that has forward secrecy.
func TestClassifyAlgorithm_CategoryScoped(t *testing.T) {
	s := catalogueService(t)

	kex, err := s.ClassifyAlgorithm("RSA", "key_exchange")
	if err != nil || kex == nil || kex.Code != "RSA" || kex.Category != "key_exchange" {
		t.Fatalf(`ClassifyAlgorithm("RSA","key_exchange") = %v (err %v), want the key_exchange RSA row`, kex, err)
	}
	sig, err := s.ClassifyAlgorithm("RSA", "signature")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig != nil {
		t.Fatalf(`ClassifyAlgorithm("RSA","signature") resolved to %q/%q — must stay unlinked`, sig.Code, sig.Category)
	}
}

// TestDeriveCipherComponents_FillsTheColumns is the CMP-2 guard: the component
// columns of crypto_implementations must be populated from the negotiated
// suite, because four seeded compliance controls read them.
func TestDeriveCipherComponents_FillsTheColumns(t *testing.T) {
	s := &AssetService{algorithmService: &AlgorithmService{}}

	suite := "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	got := s.deriveCipherComponents(IngestFinding{CipherSuite: &suite})

	assertPtr := func(name string, got *string, want string) {
		t.Helper()
		if got == nil {
			t.Fatalf("%s was not populated, want %q", name, want)
		}
		if *got != want {
			t.Fatalf("%s = %q, want %q", name, *got, want)
		}
	}
	assertPtr("symmetric_encryption", got.Symmetric, "AES256")
	assertPtr("hash_algorithm", got.Hash, "SHA384")
	assertPtr("key_exchange_algorithm", got.KeyExchange, "ECDHE")
	assertPtr("signature_algorithm", got.Signature, "RSA")
}

// TestDeriveCipherComponents_ExplicitValuesWin: the sensor reports the real key
// exchange for TLS 1.3 and for post-quantum/hybrid groups, neither of which the
// suite name carries. Derivation may only fill a gap.
func TestDeriveCipherComponents_ExplicitValuesWin(t *testing.T) {
	s := &AssetService{algorithmService: &AlgorithmService{}}

	suite := "TLS_AES_256_GCM_SHA384"
	kex := "X25519MLKEM768"
	hash := "BLAKE2S"
	got := s.deriveCipherComponents(IngestFinding{
		CipherSuite:          &suite,
		KeyExchangeAlgorithm: &kex,
		HashAlgorithm:        &hash,
	})

	if got.KeyExchange == nil || *got.KeyExchange != "X25519MLKEM768" {
		t.Fatalf("key exchange = %v, want the reported X25519MLKEM768 (not the suite-inferred ECDHE)", got.KeyExchange)
	}
	if got.Hash == nil || *got.Hash != "BLAKE2S" {
		t.Fatalf("hash = %v, want the reported BLAKE2S", got.Hash)
	}
	if got.Symmetric == nil || *got.Symmetric != "AES256" {
		t.Fatalf("symmetric = %v, want the derived AES256", got.Symmetric)
	}
}

// TestDeriveCipherComponents_BlankStaysNull keeps an empty string out of the
// columns: "" would read as "measured, and it is nothing".
func TestDeriveCipherComponents_BlankStaysNull(t *testing.T) {
	s := &AssetService{algorithmService: &AlgorithmService{}}
	blank := "   "
	got := s.deriveCipherComponents(IngestFinding{CipherSuite: &blank, HashAlgorithm: &blank})
	if got.Hash != nil || got.Symmetric != nil || got.Signature != nil || got.KeyExchange != nil {
		t.Fatalf("blank inputs produced non-NULL columns: %+v", got)
	}
}

// TestCryptoImplementationInsert_BindsEveryComponentColumn is the structural
// half of the CMP-2 guard: deriving the components is worthless if the INSERT
// throws them away, which is exactly what it did — signature_algorithm and
// symmetric_encryption were written as literal NULL on every row ever ingested.
func TestCryptoImplementationInsert_BindsEveryComponentColumn(t *testing.T) {
	sql := insertCryptoImplementationSQL

	open := strings.Index(sql, "(")
	closeIdx := strings.Index(sql, ")")
	valuesIdx := strings.Index(sql, "VALUES")
	if open < 0 || closeIdx < 0 || valuesIdx < 0 {
		t.Fatalf("could not parse the INSERT statement: %s", sql)
	}
	columns := splitTrim(sql[open+1 : closeIdx])

	vOpen := strings.Index(sql[valuesIdx:], "(") + valuesIdx
	vClose := strings.LastIndex(sql, ")")
	values := splitTrim(sql[vOpen+1 : vClose])

	if len(columns) != len(values) {
		t.Fatalf("INSERT has %d columns but %d values", len(columns), len(values))
	}

	bound := map[string]string{}
	for i, c := range columns {
		bound[c] = values[i]
	}
	for _, col := range []string{"key_exchange_algorithm", "signature_algorithm", "symmetric_encryption", "hash_algorithm"} {
		v, ok := bound[col]
		if !ok {
			t.Fatalf("%s is not in the INSERT column list", col)
		}
		if !strings.HasPrefix(v, "$") {
			t.Errorf("%s is written as %q — it must be bound to a parameter, not hardcoded", col, v)
		}
	}
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(p, "\n", ""), "\t", "")))
	}
	return out
}

// TestWeakCryptoDetector_TripleDESIsNotBrokenDES: "DES" is a substring of
// "3DES", so every triple-DES suite was reported Critical/90 — overriding the
// catalogue's curated 70 under worse-of-two-wins.
func TestWeakCryptoDetector_TripleDESIsNotBrokenDES(t *testing.T) {
	d := NewWeakCryptoDetector(nil)
	tenantID, assetID := uuid.New(), uuid.New()

	for _, suite := range []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA"} {
		t.Run(suite, func(t *testing.T) {
			issues := d.AnalyzeCryptoImplementation(tenantID, assetID, cryptoImplWithSuite(suite))
			for _, i := range issues {
				if i.Severity == SeverityCritical {
					t.Fatalf("3DES suite %q reported Critical (%s): %s", suite, i.IssueType, i.Description)
				}
			}
			if score := d.CalculateRiskScore(issues); score > 70 {
				t.Fatalf("3DES suite %q scored %d; the catalogue rates 3DES 70 and the detector must not exceed it", suite, score)
			}
		})
	}
}

// TestWeakCryptoDetector_SingleDESStillCritical is the other polarity: the
// exclusion must not blind the detector to real DES.
func TestWeakCryptoDetector_SingleDESStillCritical(t *testing.T) {
	d := NewWeakCryptoDetector(nil)
	cs := "TLS_RSA_WITH_DES_CBC_SHA"
	issues := d.AnalyzeCryptoImplementation(uuid.New(), uuid.New(), cryptoImplWithSuite(cs))
	found := false
	for _, i := range issues {
		if i.Severity == SeverityCritical && i.IssueType == "weak_cipher" {
			found = true
		}
	}
	if !found {
		t.Fatalf("single-DES suite %q was not reported Critical: %+v", cs, issues)
	}
}

// TestClassifyRisk_ECKeyIsNotAWeakRSAKey: a 256-bit key on an EC key exchange
// is healthy. Judging it against the 2048-bit RSA floor reported every modern
// endpoint as critically weak.
func TestClassifyRisk_ECKeyIsNotAWeakRSAKey(t *testing.T) {
	s := &CryptoRisksService{}
	v := "TLSv1.3"
	cipher := "TLS_AES_256_GCM_SHA384"
	hash := "SHA384"
	ks := 256

	for _, kex := range []string{"ECDHE", "X25519", "ECDH", "Ed25519", "X25519MLKEM768"} {
		t.Run(kex, func(t *testing.T) {
			k := kex
			r := &CryptoRisk{ID: uuid.New()}
			s.classifyRisk(r, &v, &cipher, &hash, &k, &ks, nil)
			if r.Category == "key_size" {
				t.Fatalf("%s with a 256-bit key was flagged %s/%s: %s", kex, r.Severity, r.IssueType, r.Description)
			}
		})
	}
}

// TestClassifyRisk_WeakRSAStillFlagged is the other polarity.
func TestClassifyRisk_WeakRSAStillFlagged(t *testing.T) {
	s := &CryptoRisksService{}
	v := "TLSv1.2"
	cipher := "TLS_RSA_WITH_AES_256_GCM_SHA384"
	hash := "SHA384"
	kex := "RSA"

	cases := []struct {
		keySize  int
		severity string
	}{
		{512, "critical"},
		{1024, "high"},
		{2048, ""},
	}
	for _, tc := range cases {
		ks := tc.keySize
		k := kex
		r := &CryptoRisk{ID: uuid.New()}
		s.classifyRisk(r, &v, &cipher, &hash, &k, &ks, nil)
		if tc.severity == "" {
			if r.Category == "key_size" {
				t.Fatalf("RSA-%d was flagged as a weak key: %+v", tc.keySize, r)
			}
			continue
		}
		if r.Category != "key_size" || r.Severity != tc.severity {
			t.Fatalf("RSA-%d: got %s/%s, want key_size/%s", tc.keySize, r.Severity, r.Category, tc.severity)
		}
	}
}

// TestKeySizeSQL_AgreesWithGoClassifier checks the generated predicates against
// the Go classifier for every family, because the list view, the summary
// counters and the classifier used to hold three different opinions about what
// "weak key" meant.
func TestKeySizeSQL_AgreesWithGoClassifier(t *testing.T) {
	sql := anyWeakKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm")

	// Every token the Go classifier consults must appear in the SQL, or a family
	// the classifier recognises would be invisible to the query.
	for _, tokens := range [][]string{kexPostQuantumTokens, kexEllipticCurveTokens, kexFiniteFieldTokens} {
		for _, tok := range tokens {
			if !strings.Contains(sql, tok) {
				t.Errorf("generated SQL does not mention family token %q", tok)
			}
		}
	}
	// The EC floor and the RSA floor must both appear, and the naked "< 2048"
	// (which is what flagged EC keys) must be family-qualified.
	if !strings.Contains(sql, "< 2048") || !strings.Contains(sql, "< 256") {
		t.Fatalf("generated SQL is missing a floor: %s", sql)
	}
	if !strings.Contains(kexFamilySQL("c", kexFamilyEllipticCurve), "NOT ") {
		t.Fatal("elliptic-curve SQL must exclude post-quantum first, mirroring keyExchangeFamily precedence")
	}
}

// TestCatalogueCache_ServesRepeatLookups: ingest resolves 15-25 components per
// finding; each one used to be its own query.
func TestCatalogueCache_ServesRepeatLookups(t *testing.T) {
	s := catalogueService(t)
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if _, err := s.ClassifyAlgorithm("AES256", "symmetric"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cached classification is implausibly slow — is it still hitting the database?")
	}
}
