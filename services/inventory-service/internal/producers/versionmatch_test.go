package producers

// Version-range matching — the part of the vulnerability producer where a bug
// does not produce an error, it produces a clean bill of health for a
// vulnerable host.
//
// Every case here is written as a triple (no / yes / unknown), because the
// third value is the one this codebase keeps losing: a comparison that could
// not run rendered as a comparison that passed.

import (
	"testing"
)

func TestWithinBounds_ComparesComponentWiseNotLexically(t *testing.T) {
	// The case the whole file exists for. Lexically "1.10" < "1.9", so a plain
	// string comparison puts 1.10 BELOW 1.9 and a rule bounded at "< 1.9"
	// declares a 1.10 install unaffected.
	if got := withinBounds("1.10", "", "", "", "1.9"); got != matchNo {
		t.Errorf("1.10 against `< 1.9` = %v, want no — 1.10 is above 1.9", got)
	}
	if got := withinBounds("1.9", "", "", "", "1.10"); got != matchYes {
		t.Errorf("1.9 against `< 1.10` = %v, want yes", got)
	}
	if got := withinBounds("1.9", "", "", "", "1.9"); got != matchNo {
		t.Errorf("1.9 against `< 1.9` = %v, want no — the exclusive end is not affected", got)
	}
}

func TestWithinBounds_Inclusivity(t *testing.T) {
	cases := []struct {
		name                                string
		version, startI, startE, endI, endE string
		want                                matchOutcome
	}{
		{"inside an inclusive range", "2.5", "2.0", "", "3.0", "", matchYes},
		{"at the inclusive start", "2.0", "2.0", "", "3.0", "", matchYes},
		{"at the inclusive end", "3.0", "2.0", "", "3.0", "", matchYes},
		{"below the inclusive start", "1.9", "2.0", "", "3.0", "", matchNo},
		{"above the inclusive end", "3.1", "2.0", "", "3.0", "", matchNo},
		{"at the exclusive start", "2.0", "", "2.0", "3.0", "", matchNo},
		{"just past the exclusive start", "2.0.1", "", "2.0", "3.0", "", matchYes},
		{"at the exclusive end", "3.0", "2.0", "", "", "3.0", matchNo},
		{"just below the exclusive end", "2.9.9", "2.0", "", "", "3.0", matchYes},
		{"unbounded below", "0.1", "", "", "3.0", "", matchYes},
		{"unbounded above", "99.0", "2.0", "", "", "", matchYes},

		// A shorter version compares component-wise against a longer one:
		// 3.0 is BELOW 3.0.2, which is what the six zero-filled slots are for.
		{"3.0 is below 3.0.2", "3.0", "", "", "", "3.0.2", matchYes},
		{"3.0.2 is not below itself", "3.0.2", "", "", "", "3.0.2", matchNo},

		// OpenSSL's letter suffixes are patch releases and sort just after the
		// numeric version they hang off.
		{"1.1.1w is above 1.1.1", "1.1.1w", "1.1.1", "", "", "3.0", matchYes},
		{"1.1.1w is below 3.0.2", "1.1.1w", "", "", "", "3.0.2", matchYes},

		// A hyphenated tag is a PRE-release and sorts BELOW the release.
		{"1.0.0-rc1 is below 1.0.0", "1.0.0-rc1", "", "", "", "1.0.0", matchYes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := withinBounds(tc.version, tc.startI, tc.startE, tc.endI, tc.endE); got != tc.want {
				t.Errorf("withinBounds(%q, %q,%q,%q,%q) = %v, want %v",
					tc.version, tc.startI, tc.startE, tc.endI, tc.endE, got, tc.want)
			}
		})
	}
}

func TestWithinBounds_UnparseableIsUnknownNotClean(t *testing.T) {
	// An unparseable version and an unparseable BOUND both make the comparison
	// undecidable. Reporting either as "no match" would turn "we could not
	// check" into "this host is fine", which is the shape that keeps costing
	// this codebase real time.
	if got := withinBounds("stable", "", "", "", "3.0"); got != matchUnknown {
		t.Errorf("an unparseable version = %v, want unknown", got)
	}
	if got := withinBounds("2.0", "", "", "", "latest"); got != matchUnknown {
		t.Errorf("an unparseable bound = %v, want unknown", got)
	}
}

func TestCPEMatches(t *testing.T) {
	rule := cpeMatchRule{
		CPE:                 "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
		VersionEndExcluding: "3.0.7",
	}
	const installed = "cpe:2.3:a:openssl:openssl:3.0.6:*:*:*:*:*:*:*"

	if got := cpeMatches(rule, installed, "3.0.6"); got != matchYes {
		t.Errorf("3.0.6 against `< 3.0.7` = %v, want yes", got)
	}
	if got := cpeMatches(rule, installed, "3.0.7"); got != matchNo {
		t.Errorf("3.0.7 against `< 3.0.7` = %v, want no", got)
	}

	// CPE attribute values are case-INSENSITIVE (2.3 §5.3.2). The SBOM writer
	// stores the column lowercase while a feed publishes its criteria verbatim,
	// so a case-sensitive comparison would miss every advisory whose feed
	// happened to publish a capital.
	upper := "CPE:2.3:A:OpenSSL:OpenSSL:3.0.6:*:*:*:*:*:*:*"
	if got := cpeMatches(rule, upper, "3.0.6"); got != matchYes {
		t.Errorf("a mixed-case CPE = %v, want yes — CPE values are case-insensitive", got)
	}
	upperRule := cpeMatchRule{CPE: "cpe:2.3:a:OpenSSL:OpenSSL:*:*:*:*:*:*:*:*", VersionEndExcluding: "3.0.7"}
	if got := cpeMatches(upperRule, installed, "3.0.6"); got != matchYes {
		t.Errorf("a mixed-case RULE = %v, want yes", got)
	}

	// A different product is a clean no, not an unknown.
	other := "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
	if got := cpeMatches(rule, other, "1.24.0"); got != matchNo {
		t.Errorf("a different product = %v, want no", got)
	}

	// A rule with no bounds and a `*` version means every version.
	all := cpeMatchRule{CPE: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}
	if got := cpeMatches(all, installed, "0.9.8"); got != matchYes {
		t.Errorf("an unbounded product-level rule = %v, want yes", got)
	}

	// A rule pinned to one version is an equality, and it compares through the
	// sort key: 1.0 and 1.0.0 are one version.
	pinned := cpeMatchRule{CPE: "cpe:2.3:a:openssl:openssl:1.0:*:*:*:*:*:*:*"}
	if got := cpeMatches(pinned, "cpe:2.3:a:openssl:openssl:1.0.0:*:*:*:*:*:*:*", "1.0.0"); got != matchYes {
		t.Errorf("1.0.0 against a rule pinned to 1.0 = %v, want yes", got)
	}
	if got := cpeMatches(pinned, "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*", "1.0.1"); got != matchNo {
		t.Errorf("1.0.1 against a rule pinned to 1.0 = %v, want no", got)
	}

	// A bounded rule against an install whose version we do not know is
	// undecidable, never a match.
	if got := cpeMatches(rule, installed, ""); got != matchUnknown {
		t.Errorf("a bounded rule with no installed version = %v, want unknown", got)
	}

	// Malformed input on either side is unknown.
	if got := cpeMatches(cpeMatchRule{CPE: "nonsense"}, installed, "3.0.6"); got != matchUnknown {
		t.Errorf("a malformed rule CPE = %v, want unknown", got)
	}
	if got := cpeMatches(rule, "nonsense", "3.0.6"); got != matchUnknown {
		t.Errorf("a malformed installed CPE = %v, want unknown", got)
	}
}

func TestPURLMatches_OSVRangesAreHalfOpen(t *testing.T) {
	// `fixed` is EXCLUSIVE: it is the first SAFE version. Treating it as
	// inclusive raises a finding on precisely the version somebody upgraded to
	// in order to clear it.
	rule := purlRangeRule{Purl: "pkg:npm/left-pad", Introduced: "1.0.0", Fixed: "1.3.0"}
	cases := map[string]matchOutcome{
		"0.9.9": matchNo,
		"1.0.0": matchYes,
		"1.2.9": matchYes,
		"1.3.0": matchNo, // the fix
		"1.4.0": matchNo,
	}
	for version, want := range cases {
		if got := purlMatches(rule, "pkg:npm/left-pad@"+version, version); got != want {
			t.Errorf("left-pad %s against [1.0.0, 1.3.0) = %v, want %v", version, got, want)
		}
	}

	// `last_affected` is INCLUSIVE — the other half of the same asymmetry.
	lastAff := purlRangeRule{Purl: "pkg:npm/left-pad", Introduced: "1.0.0", LastAffected: "1.3.0"}
	if got := purlMatches(lastAff, "pkg:npm/left-pad@1.3.0", "1.3.0"); got != matchYes {
		t.Errorf("last_affected 1.3.0 against 1.3.0 = %v, want yes — last_affected is inclusive", got)
	}
	if got := purlMatches(lastAff, "pkg:npm/left-pad@1.3.1", "1.3.1"); got != matchNo {
		t.Errorf("last_affected 1.3.0 against 1.3.1 = %v, want no", got)
	}
}

func TestPURLMatches_Identity(t *testing.T) {
	rule := purlRangeRule{Purl: "pkg:npm/left-pad", Fixed: "2.0.0"}

	// The advisory names the package; the install carries a version qualifier.
	// They are the same package.
	if got := purlMatches(rule, "pkg:npm/left-pad@1.0.0", "1.0.0"); got != matchYes {
		t.Errorf("a versioned install PURL = %v, want yes", got)
	}
	// Qualifiers and subpaths are not part of the identity.
	if got := purlMatches(rule, "pkg:npm/left-pad@1.0.0?arch=x86_64#lib", "1.0.0"); got != matchYes {
		t.Errorf("a qualified install PURL = %v, want yes", got)
	}
	// A different package is a clean no.
	if got := purlMatches(rule, "pkg:npm/right-pad@1.0.0", "1.0.0"); got != matchNo {
		t.Errorf("a different package = %v, want no", got)
	}
	// A different ECOSYSTEM with the same name is a different package.
	if got := purlMatches(rule, "pkg:pypi/left-pad@1.0.0", "1.0.0"); got != matchNo {
		t.Errorf("a same-named package in another ecosystem = %v, want no", got)
	}

	// A rule naming a package with no range at all: every install is affected.
	bare := purlRangeRule{Purl: "pkg:npm/left-pad"}
	if got := purlMatches(bare, "pkg:npm/left-pad@9.9.9", "9.9.9"); got != matchYes {
		t.Errorf("an unranged advisory = %v, want yes", got)
	}

	// Nothing to compare on either side is unknown.
	if got := purlMatches(rule, "", "1.0.0"); got != matchUnknown {
		t.Errorf("an empty install PURL = %v, want unknown", got)
	}
}

func TestPurlIdentity(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/left-pad@1.0.0":                "pkg:npm/left-pad",
		"pkg:npm/@babel/core@7.0.0":             "pkg:npm/@babel/core",
		"pkg:golang/github.com/x/y@v1.2.3":      "pkg:golang/github.com/x/y",
		"pkg:npm/Left-Pad":                      "pkg:npm/left-pad",
		"pkg:npm/left-pad@1.0.0?arch=x86#src/a": "pkg:npm/left-pad",
		"":                                      "",
	}
	for in, want := range cases {
		if got := purlIdentity(in); got != want {
			t.Errorf("purlIdentity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRules(t *testing.T) {
	r, ok := parseCPERule(`{"cpe":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","version_end_excluding":"3.0.7"}`)
	if !ok || r.VersionEndExcluding != "3.0.7" {
		t.Errorf("parseCPERule dropped the bound: %+v, ok=%v", r, ok)
	}
	if _, ok := parseCPERule(`{"version_end_excluding":"3.0.7"}`); ok {
		t.Error("parseCPERule accepted a rule with no CPE; it matches nothing and would be a rule wearing no coat")
	}
	if _, ok := parseCPERule("not json"); ok {
		t.Error("parseCPERule accepted non-JSON")
	}

	pr, ok := parsePURLRule(`{"purl":"pkg:npm/left-pad","fixed":"1.3.0"}`)
	if !ok || pr.Fixed != "1.3.0" {
		t.Errorf("parsePURLRule dropped the bound: %+v, ok=%v", pr, ok)
	}
	if _, ok := parsePURLRule(`{"fixed":"1.3.0"}`); ok {
		t.Error("parsePURLRule accepted a rule with no PURL")
	}
}

func TestCPEProductNeedle(t *testing.T) {
	if got := cpeProductNeedle("cpe:2.3:a:OpenSSL:OpenSSL:3.0.6:*:*:*:*:*:*:*"); got != ":openssl:openssl:" {
		t.Errorf("cpeProductNeedle = %q, want :openssl:openssl: (lowercased, so the SQL prefilter folds case too)", got)
	}
	if got := cpeProductNeedle("garbage"); got != "" {
		t.Errorf("cpeProductNeedle(garbage) = %q, want empty", got)
	}
}
