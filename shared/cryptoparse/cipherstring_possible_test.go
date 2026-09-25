package cryptoparse

import (
	"reflect"
	"testing"
)

// Unresolved must never read as safe (review of, B1). What a string may
// enable and could not be resolved either way is reported for risk; what an
// exact exclusion removes never is.
func TestParseCipherString_PossiblyEnabled(t *testing.T) {
	cases := []struct {
		raw      string
		possible []string
		complete bool
	}{
		// The reviewer's rows.
		{"HIGH:MEDIUM:RC4", []string{"RC4"}, false},                    // keyword addition
		{"RC4-SHA:-HIGH", []string{"TLS_RSA_WITH_RC4_128_SHA"}, false}, // uncertain suite
		{"EXP-RC4-MD5:AES128-SHA", []string{"EXP-RC4-MD5"}, false},     // suite outside the table
		{"ALL:!aNULL", nil, false},                                     // unknown, nothing named
		{"DEFAULT", nil, false},
		// Exclusions retire possibilities, by keyword and by component.
		{"RC4:!RC4", nil, false},
		{"!RC4:RC4", nil, false},             // "!" is permanent
		{"RC4:-RC4", nil, false},             // "-" removes what came before
		{"-RC4:RC4", []string{"RC4"}, false}, // ... not what comes after
		{"EXP-RC4-MD5:!RC4", nil, false},     // its cipher is excluded
		{"EXP-RC4-MD5:!MD5", nil, false},     // its MAC is excluded
		{"EXP-RC4-MD5:!SHA1", []string{"EXP-RC4-MD5"}, false},
		{"rc4:!RC4", nil, false}, // case folds as the parser folds it
		// Retired only because the SAME keyword (or a ciphers(1) synonym) is
		// excluded — nothing else about the entry could match.
		{"aNULL:!aNULL", nil, false},
		{"eNULL:!NULL", nil, false},
		{"aNULL:!eNULL", []string{"aNULL"}, false}, // not a synonym
		// Weak CLASSES expose their members (ciphers(1) 1.0.2), so every
		// weak-cipher rule recognises them; EXP and EXPORT are synonyms.
		{"LOW:!EXP", lowSuites, false},
		{"LOW", lowSuites, false},
		{"HIGH:LOW", lowSuites, false},
		{"HIGH:EXP", append(append([]string{}, export40Suites...), export56Suites...), false},
		{"ECDHE-RSA-AES256-GCM-SHA384:EXP", append(append([]string{}, export40Suites...), export56Suites...), false},
		{"EXPORT40", export40Suites, false},
		{"EXP:!EXPORT40", export56Suites, false},
		{"EXP:!EXP", nil, false},
		{"EXP:!EXPORT", nil, false},
		{"HIGH:!EXPORT:EXP", nil, false},
		{"HIGH:LOW:!LOW", nil, false},
		{"LOW:!DES", nil, false}, // every LOW member is single DES
		{"EXP:!RC4:!DES", []string{"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"}, false},
		{"3DES+SHA1:!aNULL", []string{"3DES", "SHA1"}, false},
		// Class/version keywords and cipher groups name no algorithm.
		{"ECDHE:RSA:!SSLV3:!RC4:!EXP:!DES", nil, false},
		{"ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5", nil, false},
		{"/Common/legacy-rc4", nil, false},
		// A fully resolved string has nothing possible.
		{"ECDHE-RSA-AES256-GCM-SHA384:!RC4", nil, true},
	}
	for _, tc := range cases {
		got := ParseCipherString(tc.raw, CipherStringVendor)
		if !reflect.DeepEqual(nilIfEmpty(got.PossiblyEnabled), nilIfEmpty(tc.possible)) {
			t.Errorf("%q: possibly enabled = %v, want %v", tc.raw, got.PossiblyEnabled, tc.possible)
		}
		if got.Complete != tc.complete {
			t.Errorf("%q: complete = %v, want %v", tc.raw, got.Complete, tc.complete)
		}
	}
}

func TestSuitesPossiblyInUse(t *testing.T) {
	cases := map[string][]string{
		"TLS_RSA_WITH_RC4_128_SHA":             {"TLS_RSA_WITH_RC4_128_SHA"},
		"HIGH:MEDIUM:RC4":                      {"RC4"},
		"EXP-RC4-MD5:AES128-SHA":               {"TLS_RSA_WITH_AES_128_CBC_SHA", "EXP-RC4-MD5"},
		"ECDHE+AES-GCM:!aNULL:!RC4:!3DES:!MD5": nil,
		"AES256-SHA:!3DES:DES-CBC3-SHA":        {"TLS_RSA_WITH_AES_256_CBC_SHA"},
	}
	for in, want := range cases {
		if got := SuitesPossiblyInUse(in); !reflect.DeepEqual(nilIfEmpty(got), nilIfEmpty(want)) {
			t.Errorf("SuitesPossiblyInUse(%q) = %v, want %v", in, got, want)
		}
	}
}

// A partially resolved string yields no single-valued component: AES128 from
// the one suite the parser knows would be claimed for a set that may also hold
// RC4.
func TestParseCipherSuite_PartialStringClaimsNoComponent(t *testing.T) {
	for _, s := range []string{"EXP-RC4-MD5:AES128-SHA", "AES128-SHA:-MEDIUM:DES-CBC3-SHA:!RC4:HIGH"} {
		if c, err := ParseCipherSuite(s); err == nil {
			t.Errorf("%q: partial string produced components %+v", s, *c)
		}
	}
}

// A bare keyword naming a SET of suites is a cipher string; a keyword naming
// one algorithm (a catalogue component code too) stays a name.
func TestLooksLikeCipherString_BareKeywords(t *testing.T) {
	for v, want := range map[string]bool{
		"EXP": true, "export": true, "EXPORT40": true, "LOW": true, "low": true,
		"RSA": true, "HIGH": true, "SSLv3": true, "aNULL": false,
		"RC4": false, "3DES": false, "DES": false, "AES256": false, "MD5": false,
	} {
		if got := LooksLikeCipherString(v); got != want {
			t.Errorf("LooksLikeCipherString(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestCipherStringAssessment(t *testing.T) {
	for in, want := range map[string]bool{
		"ALL:!aNULL":                       true,
		"DEFAULT":                          true,
		"low":                              true,
		"!RC4:!MD5":                        true, // adds nothing: base list is elsewhere
		"RC4-SHA:-HIGH":                    true,
		"ECDHE-RSA-AES256-GCM-SHA384:!RC4": false,
		"TLS_RSA_WITH_RC4_128_SHA":         false, // a suite name, not a string
		"":                                 false,
	} {
		partial, unexpanded := CipherStringAssessment(in)
		if partial != want {
			t.Errorf("CipherStringAssessment(%q) partial = %v, want %v", in, partial, want)
		}
		if partial && len(unexpanded) == 0 {
			t.Errorf("CipherStringAssessment(%q): partial without saying why", in)
		}
	}
}
