package producers

import (
	"encoding/json"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// Matching an installed product against an advisory's match rule.
//
// Two shapes, both written by the mirror jobs as deterministic JSON with a
// fixed key order so `vulnerability_matches_identity_uniq` deduplicates them
// (workstream 3.4 part 1). This file parses that shape and decides whether one
// installed version falls inside one rule's bounds.
//
// # Versions are compared component-wise, never lexically
//
// Every comparison goes through [ast.VersionSortKey], which is the definition
// of `software_products.version_sort` and of the query language's `version <
// 3.0`. It pads each numeric component to eight characters, so `1.10` sorts
// ABOVE `1.9` — the comparison a plain string `<` gets backwards, and the one
// that decides whether a host is inside a CVE's affected range. Getting it
// wrong here does not produce an error; it produces a clean bill of health for
// a vulnerable version, which is the worst failure this file can have.
//
// A version with no numeric component at all has no sort key, and a rule with
// bounds cannot be evaluated against it. That is UNKNOWN, and unknown is not a
// match: claiming a CVE affects a version we could not parse would put a
// critical finding on a guess.

// cpeMatchRule is `vulnerability_matches.cpe_match_string`, as NVD's converter
// writes it.
type cpeMatchRule struct {
	CPE                   string `json:"cpe"`
	VersionStartIncluding string `json:"version_start_including,omitempty"`
	VersionStartExcluding string `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string `json:"version_end_including,omitempty"`
	VersionEndExcluding   string `json:"version_end_excluding,omitempty"`
}

// purlRangeRule is `vulnerability_matches.purl_range`, as OSV's converter
// writes it.
type purlRangeRule struct {
	Purl         string `json:"purl"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// matchOutcome is the three-valued answer a match rule gives.
//
// UNKNOWN is a real answer and is kept apart from NO. "This version is outside
// the affected range" and "this version could not be compared" are different
// facts, and collapsing the second into the first is the shape this codebase
// keeps re-finding — a check that could not run rendered as a check that
// passed. The producer counts unknowns and reports them rather than quietly
// treating them as clean.
type matchOutcome int

const (
	matchNo matchOutcome = iota
	matchYes
	matchUnknown
)

// cpeMatches reports whether an installed CPE and version fall inside a CPE
// match rule.
//
// The CPE comparison is case-folded on BOTH sides. CPE 2.3 §5.3.2 makes
// attribute values case-insensitive; `software_products.cpe` is stored
// lowercase by the SBOM writer while `cpe_match_string` carries NVD's criteria
// verbatim, so a case-sensitive comparison would silently miss every advisory
// whose feed happened to publish a capital.
//
// Only the part/vendor/product components are compared. The rule's own version
// component is not the bound — the bounds are the four explicit fields — and a
// rule pinned to `…:openssl:3.0.6:*` with no bounds means exactly that one
// version, which is handled by comparing it as an equality.
func cpeMatches(rule cpeMatchRule, installedCPE, installedVersion string) matchOutcome {
	ruleParts := strings.Split(strings.ToLower(strings.TrimSpace(rule.CPE)), ":")
	instParts := strings.Split(strings.ToLower(strings.TrimSpace(installedCPE)), ":")
	if len(ruleParts) < 6 || len(instParts) < 6 {
		return matchUnknown
	}
	// part, vendor, product — indices 2, 3, 4 of `cpe:2.3:a:vendor:product:…`.
	for i := 2; i <= 4; i++ {
		if ruleParts[i] == "*" {
			continue
		}
		if ruleParts[i] != instParts[i] {
			return matchNo
		}
	}

	bounded := rule.VersionStartIncluding != "" || rule.VersionStartExcluding != "" ||
		rule.VersionEndIncluding != "" || rule.VersionEndExcluding != ""
	if !bounded {
		// No range: the rule's own version component IS the claim. `*` means
		// every version of the product.
		if ruleParts[5] == "*" {
			return matchYes
		}
		if installedVersion == "" {
			return matchUnknown
		}
		return sameVersion(ruleParts[5], installedVersion)
	}

	if installedVersion == "" {
		// A bounded rule against a product whose version we do not know cannot
		// be decided. Reported as unknown, never as a match.
		return matchUnknown
	}
	return withinBounds(installedVersion,
		rule.VersionStartIncluding, rule.VersionStartExcluding,
		rule.VersionEndIncluding, rule.VersionEndExcluding)
}

// purlMatches reports whether an installed PURL and version fall inside an OSV
// range rule.
//
// OSV ranges are half-open: `introduced` is inclusive and `fixed` is EXCLUSIVE
// (the fixed version is the first one that is safe), while `last_affected` is
// inclusive. Treating `fixed` as inclusive would raise a finding on precisely
// the version somebody upgraded to in order to clear it.
//
// The PURL comparison ignores the version qualifier on either side: an install
// is `pkg:npm/left-pad@1.0.0` and an advisory names `pkg:npm/left-pad`, and the
// version travels in the bounds.
func purlMatches(rule purlRangeRule, installedPURL, installedVersion string) matchOutcome {
	rp := purlIdentity(rule.Purl)
	ip := purlIdentity(installedPURL)
	if rp == "" || ip == "" {
		return matchUnknown
	}
	if rp != ip {
		return matchNo
	}

	if rule.Introduced == "" && rule.Fixed == "" && rule.LastAffected == "" {
		// No range at all: OSV said the package is affected and named no
		// versions. Every install of it is in scope.
		return matchYes
	}
	if installedVersion == "" {
		return matchUnknown
	}

	// "0" is OSV's conventional spelling for "from the beginning", and it
	// compares correctly as a version, so it needs no special case.
	return withinBounds(installedVersion, rule.Introduced, "", rule.LastAffected, rule.Fixed)
}

// withinBounds is the one comparison, shared by both rule shapes.
//
// startIncl / startExcl / endIncl / endExcl: any may be empty, meaning
// unbounded on that side. A bound that has no sort key makes the whole
// comparison UNKNOWN rather than dropping that side — an unparseable bound is
// not an absent bound, and treating it as one would widen the range in the
// direction of a false positive or narrow it into a false negative depending on
// which side it was.
func withinBounds(version, startIncl, startExcl, endIncl, endExcl string) matchOutcome {
	v, ok := ast.VersionSortKey(version)
	if !ok {
		return matchUnknown
	}
	cmp := func(bound string) (string, bool) {
		if bound == "" {
			return "", true
		}
		k, ok := ast.VersionSortKey(bound)
		return k, ok
	}

	si, ok1 := cmp(startIncl)
	se, ok2 := cmp(startExcl)
	ei, ok3 := cmp(endIncl)
	ee, ok4 := cmp(endExcl)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return matchUnknown
	}

	// Byte-wise comparison, which is what the sort key is built for — the
	// translator emits COLLATE "C" for the same reason. A locale collation
	// ignores punctuation in its first pass and would undo the padding.
	if si != "" && v < si {
		return matchNo
	}
	if se != "" && v <= se {
		return matchNo
	}
	if ei != "" && v > ei {
		return matchNo
	}
	if ee != "" && v >= ee {
		return matchNo
	}
	return matchYes
}

// sameVersion compares two versions through the sort key, so `1.0` and `1.0.0`
// are one version and `1.10` is not `1.1`.
func sameVersion(a, b string) matchOutcome {
	ka, ok1 := ast.VersionSortKey(a)
	kb, ok2 := ast.VersionSortKey(b)
	if !ok1 || !ok2 {
		// Fall back to an exact string comparison: a version with no numeric
		// component ("stable") is still a name two sides can agree on.
		if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) {
			return matchYes
		}
		return matchUnknown
	}
	if ka == kb {
		return matchYes
	}
	return matchNo
}

// purlIdentity strips the version and everything after it, leaving
// `pkg:type/namespace/name` lowercased.
//
// Case folding here is narrower than [software.NormalizePURL]'s, deliberately:
// that function applies the spec's per-type namespace rules and is the
// validator the stored column already passed through. This is a comparison
// between two strings that both came out of it, so folding the whole thing is
// safe and catches the types whose name rules the normaliser does not yet
// apply.
func purlIdentity(purl string) string {
	s := strings.TrimSpace(purl)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	// The version follows the LAST '@', and a namespace may not contain one.
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// parseCPERule decodes a stored cpe_match_string.
func parseCPERule(raw string) (cpeMatchRule, bool) {
	var r cpeMatchRule
	if err := json.Unmarshal([]byte(raw), &r); err != nil || strings.TrimSpace(r.CPE) == "" {
		return cpeMatchRule{}, false
	}
	return r, true
}

// parsePURLRule decodes a stored purl_range.
func parsePURLRule(raw string) (purlRangeRule, bool) {
	var r purlRangeRule
	if err := json.Unmarshal([]byte(raw), &r); err != nil || strings.TrimSpace(r.Purl) == "" {
		return purlRangeRule{}, false
	}
	return r, true
}
