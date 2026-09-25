package cryptoparse

import (
	"reflect"
	"strings"
	"testing"
)

func names(suites []TLSCipherSuite) []string {
	out := make([]string, 0, len(suites))
	for _, s := range suites {
		out = append(out, s.OpenSSLName)
	}
	return out
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// TestParseCipherString_RealWorldStrings pins the parser against strings real
// devices carry. Each case states all four outputs: what is enabled, what is
// uncertain, what was excluded, and what could not be expanded.
func TestParseCipherString_RealWorldStrings(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		dialect    CipherStringDialect
		enabled    []string
		uncertain  []string
		excluded   []string
		unexpanded []string
		complete   bool
	}{
		{
			// The hardened F5 profile from the finding (P-05). "AES-GCM" is F5's
			// keyword (OpenSSL spells it AESGCM) and ECDHE is a vendor-defined
			// class, so nothing is enabled — and crucially none of the excluded
			// algorithms is either.
			name:       "F5 hardened profile",
			raw:        "ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5",
			dialect:    CipherStringVendor,
			excluded:   []string{"aNULL", "RC4", "3DES", "MD5"},
			unexpanded: []string{"ECDHE+AES-GCM"},
		},
		{
			// The same intent in OpenSSL's own spelling resolves completely.
			name:    "OpenSSL ECDHE+AESGCM with exclusions",
			raw:     "ECDHE+AESGCM:!aNULL:!RC4:!3DES:!MD5",
			dialect: CipherStringOpenSSL,
			enabled: []string{
				"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
				"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
			},
			excluded: []string{"aNULL", "RC4", "3DES", "MD5"},
			complete: true,
		},
		{
			name:       "bare DEFAULT",
			raw:        "DEFAULT",
			dialect:    CipherStringVendor,
			unexpanded: []string{"DEFAULT"},
		},
		{
			name:       "DEFAULT with exclusions",
			raw:        "DEFAULT:!SSLv3:!RC4",
			dialect:    CipherStringVendor,
			excluded:   []string{"SSLv3", "RC4"},
			unexpanded: []string{"DEFAULT", "!SSLv3"},
		},
		{
			// Only exclusions: the string adds nothing, so it is being applied on
			// top of a list from elsewhere — never complete.
			name:       "exclusions only",
			raw:        "!SSLv3:!RC4:!EXP:!DES",
			dialect:    CipherStringVendor,
			excluded:   []string{"SSLv3", "RC4", "EXP", "DES"},
			unexpanded: []string{"!SSLv3"},
		},
		{
			name:     "explicit suite list",
			raw:      "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
			dialect:  CipherStringVendor,
			enabled:  []string{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"},
			complete: true,
		},
		{
			// F5's built-in f5-secure rule, as F5 documents it.
			name:       "F5 f5-secure rule",
			raw:        "ECDHE:RSA:!SSLV3:!RC4:!EXP:!DES",
			dialect:    CipherStringVendor,
			excluded:   []string{"SSLV3", "RC4", "EXP", "DES"},
			unexpanded: []string{"ECDHE", "RSA", "!SSLV3"},
		},
		{
			// A Cisco ASA `ssl cipher tlsv1.2 custom "…"` list, quoted as the
			// running-config shows it.
			name:     "ASA custom list, quoted",
			raw:      `"AES256-SHA:AES128-SHA:DES-CBC3-SHA"`,
			dialect:  CipherStringVendor,
			enabled:  []string{"AES256-SHA", "AES128-SHA", "DES-CBC3-SHA"},
			complete: true,
		},
		{
			// "+" moves an existing entry to the end and adds nothing.
			name:     "plus moves to the end",
			raw:      "AES128-SHA:AES256-SHA:DES-CBC3-SHA:+AES128-SHA",
			dialect:  CipherStringVendor,
			enabled:  []string{"AES256-SHA", "DES-CBC3-SHA", "AES128-SHA"},
			complete: true,
		},
		{
			// "-" removes, and a later mention brings it back (at the end).
			name:     "minus then re-add",
			raw:      "AES128-SHA:DES-CBC3-SHA:AES256-SHA:-3DES:DES-CBC3-SHA",
			dialect:  CipherStringVendor,
			enabled:  []string{"AES128-SHA", "AES256-SHA", "DES-CBC3-SHA"},
			excluded: []string{"3DES"},
			complete: true,
		},
		{
			// "!" is permanent: naming the suite again does not bring it back.
			name:     "bang is permanent",
			raw:      "AES128-SHA:!3DES:DES-CBC3-SHA",
			dialect:  CipherStringVendor,
			enabled:  []string{"AES128-SHA"},
			excluded: []string{"3DES"},
			complete: true,
		},
		{
			// ciphers(1) EXAMPLES: "Include only 3DES ciphers and then place RSA
			// ciphers last".
			name:    "OpenSSL man example 3DES:+RSA",
			raw:     "3DES:+RSA",
			dialect: CipherStringOpenSSL,
			enabled: []string{
				"DHE-DSS-DES-CBC3-SHA", "DHE-RSA-DES-CBC3-SHA", "ADH-DES-CBC3-SHA",
				"ECDHE-RSA-DES-CBC3-SHA", "ECDHE-ECDSA-DES-CBC3-SHA", "AECDH-DES-CBC3-SHA",
				"DES-CBC3-SHA",
			},
			complete: true,
		},
		{
			name:     "@STRENGTH sorts by key strength, stably",
			raw:      "AES128-SHA:DES-CBC3-SHA:AES256-SHA:RC4-SHA:@STRENGTH",
			dialect:  CipherStringVendor,
			enabled:  []string{"AES256-SHA", "AES128-SHA", "RC4-SHA", "DES-CBC3-SHA"},
			complete: true,
		},
		{
			// A version-dependent removal puts only what it could reach in doubt:
			// MEDIUM may hold 3DES (it does from OpenSSL 1.1.0), never AES.
			name:       "unexpanded removal makes reachable suites uncertain",
			raw:        "DES-CBC3-SHA:AES128-SHA:-MEDIUM",
			dialect:    CipherStringVendor,
			enabled:    []string{"AES128-SHA"},
			uncertain:  []string{"DES-CBC3-SHA"},
			excluded:   []string{"MEDIUM"},
			unexpanded: []string{"-MEDIUM"},
		},
		{
			// ... and an unexpanded "!" does the same to later additions.
			name:       "unexpanded bang taints later additions it could reach",
			raw:        "!MEDIUM:DES-CBC3-SHA:AES128-SHA",
			dialect:    CipherStringVendor,
			enabled:    []string{"AES128-SHA"},
			uncertain:  []string{"DES-CBC3-SHA"},
			excluded:   []string{"MEDIUM"},
			unexpanded: []string{"!MEDIUM"},
		},
		{
			// A "-" that may have removed a suite is settled by naming it again.
			name:       "re-naming after an unexpanded minus settles it",
			raw:        "DES-CBC3-SHA:-MEDIUM:DES-CBC3-SHA",
			dialect:    CipherStringVendor,
			enabled:    []string{"DES-CBC3-SHA"},
			excluded:   []string{"MEDIUM"},
			unexpanded: []string{"-MEDIUM"},
			complete:   true,
		},
		{
			// An SSLv3/TLSv1.0 keyword cannot reach a TLS-1.2-only suite under
			// either reading (suite class or protocol).
			name:       "!SSLv3 leaves TLS 1.2 suites enabled",
			raw:        "ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA:!SSLv3",
			dialect:    CipherStringVendor,
			enabled:    []string{"ECDHE-RSA-AES256-GCM-SHA384"},
			uncertain:  []string{"AES128-SHA"},
			excluded:   []string{"SSLv3"},
			unexpanded: []string{"!SSLv3"},
		},
		{
			name:       "@SECLEVEL above 0 puts everything in doubt",
			raw:        "ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=2",
			dialect:    CipherStringVendor,
			uncertain:  []string{"ECDHE-RSA-AES256-GCM-SHA384"},
			unexpanded: []string{"@SECLEVEL=2"},
		},
		{
			name:     "@SECLEVEL=0 filters nothing",
			raw:      "ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0",
			dialect:  CipherStringVendor,
			enabled:  []string{"ECDHE-RSA-AES256-GCM-SHA384"},
			complete: true,
		},
		{
			// Class keywords are vendor-defined: in the vendor dialect a removal
			// of one only puts its reach in doubt.
			name:       "vendor class-keyword removal",
			raw:        "ECDHE-ECDSA-AES128-GCM-SHA256:AES128-GCM-SHA256:!ECDHE",
			dialect:    CipherStringVendor,
			enabled:    []string{"AES128-GCM-SHA256"},
			uncertain:  []string{"ECDHE-ECDSA-AES128-GCM-SHA256"},
			excluded:   []string{"ECDHE"},
			unexpanded: []string{"!ECDHE"},
		},
		{
			// ... while OpenSSL's own ECDHE is exact.
			name:     "OpenSSL class-keyword removal",
			raw:      "ECDHE-ECDSA-AES128-GCM-SHA256:AES128-GCM-SHA256:!ECDHE",
			dialect:  CipherStringOpenSSL,
			enabled:  []string{"AES128-GCM-SHA256"},
			excluded: []string{"ECDHE"},
			complete: true,
		},
		{
			// F5's f5-aes rule. A vendor keyword ADDITION is never expanded —
			// "AES" against the table would claim the anonymous ADH-AES suites.
			name:       "vendor keyword additions are never expanded",
			raw:        "AES:!aNULL",
			dialect:    CipherStringVendor,
			excluded:   []string{"aNULL"},
			unexpanded: []string{"AES"},
		},
		{
			// A cipher-group reference and F5 stack keywords are opaque.
			name:       "F5 cipher group and NATIVE",
			raw:        "/Common/f5-secure NATIVE",
			dialect:    CipherStringVendor,
			unexpanded: []string{"/Common/f5-secure", "NATIVE"},
		},
		{
			// Separators: comma and space are accepted, and FortiOS's hyphenated
			// IANA spelling resolves.
			name:     "comma, space and FortiOS spelling",
			raw:      "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384, AES128-SHA TLS_RSA_WITH_AES_256_CBC_SHA",
			dialect:  CipherStringVendor,
			enabled:  []string{"ECDHE-RSA-AES256-GCM-SHA384", "AES128-SHA", "AES256-SHA"},
			complete: true,
		},
		{
			// A keyword that selects only suites outside the table is unresolved.
			name:       "positive keyword with no table coverage",
			raw:        "AES128-SHA:CAMELLIA",
			dialect:    CipherStringOpenSSL,
			enabled:    []string{"AES128-SHA"},
			unexpanded: []string{"CAMELLIA"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCipherString(tc.raw, tc.dialect)
			if g := nilIfEmpty(names(got.Enabled)); !reflect.DeepEqual(g, nilIfEmpty(tc.enabled)) {
				t.Errorf("enabled = %v, want %v", g, tc.enabled)
			}
			if g := nilIfEmpty(names(got.Uncertain)); !reflect.DeepEqual(g, nilIfEmpty(tc.uncertain)) {
				t.Errorf("uncertain = %v, want %v", g, tc.uncertain)
			}
			if g := nilIfEmpty(got.Excluded); !reflect.DeepEqual(g, nilIfEmpty(tc.excluded)) {
				t.Errorf("excluded = %v, want %v", g, tc.excluded)
			}
			if g := nilIfEmpty(got.Unexpanded); !reflect.DeepEqual(g, nilIfEmpty(tc.unexpanded)) {
				t.Errorf("unexpanded = %v, want %v", g, tc.unexpanded)
			}
			if got.Complete != tc.complete {
				t.Errorf("complete = %v, want %v", got.Complete, tc.complete)
			}
		})
	}
}

// TestParseCipherString_ExcludedNeverEnabled is the property the finding is
// about, over OpenSSL's own dialect where every class keyword expands: F5's
// f5-secure rule in OpenSSL spelling. Nothing RC4 or single-DES may appear in
// either list, and nothing below TLS 1.2 may be reported as definitely enabled
// once SSLv3's (unexpanded) removal has had its chance to reach it.
func TestParseCipherString_ExcludedNeverEnabled(t *testing.T) {
	got := ParseCipherString("ECDHE:RSA:!SSLV3:!RC4:!EXP:!DES", CipherStringOpenSSL)
	if len(got.Enabled) == 0 || len(got.Uncertain) == 0 {
		t.Fatalf("expected both enabled and uncertain suites, got %d / %d", len(got.Enabled), len(got.Uncertain))
	}
	for _, s := range append(append([]TLSCipherSuite{}, got.Enabled...), got.Uncertain...) {
		if s.Symmetric == SymRC4 || s.Symmetric == SymDES {
			t.Errorf("%s survived an explicit exclusion of its cipher", s.OpenSSLName)
		}
	}
	for _, s := range got.Enabled {
		if !s.tls12Only() {
			t.Errorf("%s reported enabled although !SSLV3 may have removed it", s.OpenSSLName)
		}
		if s.KeyExchange != KexECDHE && s.KeyExchange != KexRSA {
			t.Errorf("%s is neither ECDHE nor RSA key exchange", s.OpenSSLName)
		}
	}
	if got.Complete {
		t.Error("a result with uncertain suites cannot be complete")
	}
}

// Every table row must derive a full set of attributes; a row the component
// parser cannot read would be silently unselectable by every keyword.
func TestCipherStringSuiteTable_Derives(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range cipherStringSuites {
		if seen[s.OpenSSLName] {
			t.Errorf("duplicate table row %s", s.OpenSSLName)
		}
		seen[s.OpenSSLName] = true
		if s.KeyExchange == "" || s.Authentication == "" || s.Symmetric == "" || s.MAC == "" {
			t.Errorf("%s (%s) derived incompletely: %+v", s.OpenSSLName, s.IANAName, s)
		}
		if s.Symmetric != SymNULL && s.StrengthBits == 0 {
			t.Errorf("%s has no strength", s.OpenSSLName)
		}
		for _, n := range []string{s.OpenSSLName, s.IANAName, strings.ReplaceAll(s.IANAName, "_", "-"), strings.ToLower(s.OpenSSLName)} {
			if got, ok := LookupTLSCipherSuite(n); !ok || got.OpenSSLName != s.OpenSSLName {
				t.Errorf("lookup %q did not resolve to %s", n, s.OpenSSLName)
			}
		}
	}
}

// Case folding must not merge OpenSSL keywords that differ only by case.
func TestCipherKeywords_AmbiguousCaseDoesNotFold(t *testing.T) {
	// "aECDH" (1.0.2 fixed-ECDH authentication) is not "AECDH" (anonymous).
	got := ParseCipherString("AECDH-AES128-SHA:!aECDH", CipherStringOpenSSL)
	if len(got.Enabled) != 0 || len(got.Uncertain) != 1 {
		t.Fatalf("an unknown-case keyword must put its reach in doubt, not remove definitively: %+v", got)
	}
	// Uniquely-foldable keywords do fold: F5 writes SSLV3.
	got = ParseCipherString("ECDHE-RSA-AES256-GCM-SHA384:!SSLV3", CipherStringVendor)
	if len(got.Enabled) != 1 {
		t.Fatalf("SSLV3 should fold to SSLv3 and leave the TLS 1.2 suite enabled: %+v", got)
	}
}

func TestLooksLikeCipherString(t *testing.T) {
	for v, want := range map[string]bool{
		"ECDHE+AES-GCM:!aNULL":                  true,
		"DEFAULT":                               true,
		"native":                                true,
		"AES128-SHA,AES256-SHA":                 true,
		"-RC4":                                  true,
		"@STRENGTH":                             true,
		"@SECLEVEL=2":                           true,
		"fips":                                  true,  // Cisco ASA level
		"chacha20-poly1305@openssh.com":         false, // an SSH name, not a directive
		"aes256-gcm@openssh.com":                false,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": false,
		"ECDHE-RSA-AES256-GCM-SHA384":           false,
		"RC4-MD5":                               false,
		"aes256-sha256 aes128-sha1":             false, // FortiOS proposal, not a cipher string
		"ChaCha20-Poly1305":                     false,
		"":                                      false,
	} {
		if got := LooksLikeCipherString(v); got != want {
			t.Errorf("LooksLikeCipherString(%q) = %v, want %v", v, got, want)
		}
	}
}

// A cipher STRING handed to ParseCipherSuite yields only the components every
// definitely-enabled suite shares, and an error when nothing is enabled —
// never a component read out of an exclusion.
func TestParseCipherSuite_CipherStringInput(t *testing.T) {
	if c, err := ParseCipherSuite("ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5"); err == nil {
		t.Fatalf("expected an error for a string that enables nothing, got %+v", c)
	}
	c, err := ParseCipherSuite("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:!3DES")
	if err != nil {
		t.Fatal(err)
	}
	want := CipherSuiteComponents{KeyExchange: KexECDHE, Signature: SigRSA, IsInferred: true, Confidence: 0.7}
	if *c != want {
		t.Fatalf("components = %+v, want %+v", *c, want)
	}
	// One enabled suite: its full components.
	c, err = ParseCipherSuite("DES-CBC3-SHA:!RC4")
	if err != nil {
		t.Fatal(err)
	}
	if c.Symmetric != Sym3DES || c.Hash != HashSHA1 || c.KeyExchange != KexRSA {
		t.Fatalf("single-suite string components = %+v", *c)
	}
}
