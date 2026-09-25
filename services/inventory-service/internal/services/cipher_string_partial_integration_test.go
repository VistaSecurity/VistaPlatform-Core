package services

// Review of, B1: unresolved must never read as safe.
//
// The reviewer ran these strings through IngestFindings with the detector and
// the seeded catalogue. On the first cut of the parser every one of them read
// as an assessed Low (25): RC4 named by a keyword the parser declined to
// expand, an RC4 suite an unexpanded "-HIGH" may or may not have removed, an
// RC4 suite outside the parser's table — and "ALL:!aNULL", whose honest answer
// is "unknown". Here every row goes through the same production entry point.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
)

func (f leafLinkFixture) cipherAssessment(t *testing.T, implID uuid.UUID) (string, []interface{}) {
	t.Helper()
	var assessment *string
	var unexpanded []byte
	if err := f.db.QueryRow(`
		SELECT raw_data->>'cipher_assessment', COALESCE(raw_data->'cipher_string_unexpanded', '[]'::jsonb)
		  FROM crypto_implementations WHERE id = $1`, implID).Scan(&assessment, &unexpanded); err != nil {
		t.Fatalf("read cipher assessment: %v", err)
	}
	if assessment == nil {
		return "", nil
	}
	return *assessment, []interface{}{string(unexpanded)}
}

func (f leafLinkFixture) catalogueRisk(t *testing.T, code, category string) int {
	t.Helper()
	var risk int
	if err := f.db.QueryRow(`SELECT risk_score FROM algorithms WHERE code = $1 AND category = $2`, code, category).Scan(&risk); err != nil {
		t.Fatalf("catalogue %s/%s: %v", code, category, err)
	}
	return risk
}

func TestIntegration_Ingest_UnresolvedCipherStringsAreNotSafe(t *testing.T) {
	f := newScoringFixture(t)
	rc4 := f.catalogueRisk(t, "RC4", "symmetric")

	// Rows that name RC4 without resolving it: flagged as before (main scored
	// each 90), AND recorded as partially assessed.
	for i, tc := range []struct {
		cipher string
		links  map[string]string // code → role that must be linked
	}{
		{"HIGH:MEDIUM:RC4", map[string]string{"RC4": "symmetric"}},
		{"RC4-SHA:-HIGH", map[string]string{"RC4": "symmetric", "TLS_RSA_WITH_RC4_128_SHA": "cipher_suite"}},
		{"EXP-RC4-MD5:AES128-SHA", map[string]string{"RC4": "symmetric", "MD5": "hash", "AES128": "symmetric"}},
	} {
		host := []string{"unres-rc4-kw.example.com", "unres-rc4-minus.example.com", "unres-exp.example.com"}[i]
		ip := []string{"198.51.100.60", "198.51.100.61", "198.51.100.62"}[i]
		impl, risk, codes := f.ingestOne(t, cipherStringFinding(host, ip, tc.cipher))
		for code, role := range tc.links {
			if codes[code] != role {
				t.Errorf("%q: %s not linked as %s: %v", tc.cipher, code, role, codes)
			}
		}
		if risk == nil || *risk < rc4 {
			t.Errorf("%q: risk = %v, want at least the catalogue's RC4 %d (main scored it 90)", tc.cipher, risk, rc4)
		}
		if a, _ := f.cipherAssessment(t, impl); a != "partial" {
			t.Errorf("%q: cipher_assessment = %q, want partial", tc.cipher, a)
		}
	}

	// Rows whose honest answer is "unknown": partially assessed and UNSCORED —
	// not an assessed Low from their protocol version.
	for i, cipher := range []string{"ALL:!aNULL", "DEFAULT", "HIGH:!RC4"} {
		host := []string{"unres-all.example.com", "unres-default.example.com", "unres-high.example.com"}[i]
		ip := []string{"198.51.100.63", "198.51.100.64", "198.51.100.65"}[i]
		impl, risk, codes := f.ingestOne(t, cipherStringFinding(host, ip, cipher))
		if risk != nil {
			t.Errorf("%q: stored risk %d reads as an assessed verdict; want unassessed (NULL). links: %v", cipher, *risk, codes)
		}
		if a, un := f.cipherAssessment(t, impl); a != "partial" || len(un) == 0 {
			t.Errorf("%q: cipher_assessment = %q (%v), want partial with what could not be expanded", cipher, a, un)
		}
		if _, ok := codes["RC4"]; ok {
			t.Errorf("%q: RC4 linked from an exclusion: %v", cipher, codes)
		}

		// A stale verdict from an earlier pass is cleared on re-observation,
		// not left standing beside the partial flag.
		if _, err := f.db.Exec(`UPDATE crypto_implementations SET risk_score = 25 WHERE id = $1`, impl); err != nil {
			t.Fatal(err)
		}
		_, risk, _ = f.ingestOne(t, cipherStringFinding(host, ip, cipher))
		if risk != nil {
			t.Errorf("%q: re-observation left the stale score %d in place", cipher, *risk)
		}
	}

	// An excluded token still produces nothing, and a fully resolved string
	// is an ordinary, complete, scored assessment.
	impl, risk, codes := f.ingestOne(t, cipherStringFinding("resolved.example.com", "198.51.100.66",
		"ECDHE-RSA-AES256-GCM-SHA384:!RC4"))
	if _, ok := codes["RC4"]; ok {
		t.Errorf("!RC4 linked RC4: %v", codes)
	}
	if risk == nil {
		t.Errorf("a fully resolved string must be scored; links: %v", codes)
	}
	if a, _ := f.cipherAssessment(t, impl); a != "complete" {
		t.Errorf("cipher_assessment = %q, want complete", a)
	}
}
