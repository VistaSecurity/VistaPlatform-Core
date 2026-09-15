package query_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/ladder"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/registrycatalog"
)

// The conformance file, run a second time through the PRODUCTION catalogue.
//
// conformance.json is a contract about the language, and the language is meant
// to be catalogue-independent: the parser, validator, formatter and translator
// see only catalog.Catalog, so swapping the static §4.3 catalogue for the one
// built from the generated registries should change nothing. Running the file
// once against testcatalog proved the implementation. Running it again against
// registrycatalog is what proves the seam — and it is the only check that
// would notice the production catalogue quietly acquiring a different opinion
// about a type, an accessor or a closed value set.
//
// Where the two catalogues genuinely disagree, the case is EXEMPT and the
// exemption says why. The list is asserted in both directions: an exemption
// that is no longer needed fails the test, so it cannot outlive its cause.

// exemptionKind separates two very different things, because lumping them
// together would hide the second.
type exemptionKind int

const (
	// exemptDiverges: the case reaches a different OUTCOME — it passes on one
	// catalogue and fails on the other. Every one of these is a place where the
	// registry knows something the §4.3 examples did not.
	exemptDiverges exemptionKind = iota
	// exemptSQLOnly: the case passes on both, but the generated SQL differs
	// because the field has a different declared type. Weaker, and worth
	// keeping separate: a case in this bucket still proves its error behaviour
	// on both catalogues.
	exemptSQLOnly
)

// registryExemptions is every conformance case the production catalogue does
// not reproduce, with the reason.
//
// It is EMPTY. It held eight of 228 in three groups, every one of them a key
// the registries do not define or define with a different type; all eight are
// resolved rather than exempted, and the note inside says how. The map stays
// declared so a future divergence has to be written down with a reason.
var registryExemptions = map[string]struct {
	kind   exemptionKind
	reason string
}{
	// There is no `environment` group here, and there was: three fixtures wrote
	// `prod`, which `public.environment_type` cannot hold, and the static
	// catalogue left the field open so they passed there. That was not a
	// difference between two catalogues — it was the fixtures lagging §12
	// amendment 1 ("Enum wins. No legacy data exists to carry `prod`; §8 row
	// and ex. 18 rewritten"), which the document had already taken. Fixed at
	// the source: testcatalog closes the enum too, and the three fixtures now
	// write what the amended spec writes. An exemption would have made a stale
	// fixture look like a catalogue disagreement, which is the one thing this
	// list must not be used for.

	// ---- The list is EMPTY, and that is the point.
	//
	// It used to hold eight entries in three groups, every one of them a place
	// where the static §4.3 fixtures named something the registry does not
	// have: `attr.os_version` typed NUMBER against a column asset-classes.yaml
	// declares a string, `attr.managed` and `fact.cve.max_cvss` which are not
	// registered keys at all, and `fact.eol.software.date` for a key spelled
	// `eol.sw.date`. Each one meant a predicate the spec fixture accepted and
	// the production catalogue refused — `attr.os_version < 3` is
	// operator_not_allowed against a keyword — so the fixtures proved a
	// language nobody could actually type.
	//
	// They are resolved in the registry's favour rather than exempted: the
	// fixtures now use attributes and fact keys that exist (`attr.cpu_count`,
	// `attr.controller_managed`, `fact.sw.package_count`, `fact.eol.sw.date`),
	// which keeps every SHAPE they were pinning — the guarded ::numeric out of
	// jsonb, the boolean, the fact presence test — while making them true of
	// both catalogues.
	//
	// Leaving the map declared, empty, is deliberate: the assertion below fails
	// on an exemption that no longer applies, so a future divergence has to be
	// added here with a reason rather than appearing as a quietly passing test.
}

// TestConformance_RegistryCatalog runs every fixture through the production
// catalogue and holds it to the same contract, minus the exemptions above.
func TestConformance_RegistryCatalog(t *testing.T) {
	cat := registrycatalog.New(registrycatalog.Options{})
	used := map[string]bool{}

	for _, c := range loadCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			got := runWith(c, cat, ladder.CVSS)
			ex, exempt := registryExemptions[c.Name]

			// Canonical form and the AST are SYNTACTIC — they come out of the
			// parser and the formatter, which never see a catalogue. An
			// exemption must not be allowed to cover a difference there: if
			// one appeared, it would mean the language itself had become
			// catalogue-dependent.
			if got.Canonical != c.Canonical {
				t.Errorf("canonical:\n  got  %q\n  want %q", got.Canonical, c.Canonical)
			}
			if !equalJSON(got.AST, c.AST) {
				t.Errorf("ast:\n  got  %s\n  want %s", got.AST, c.AST)
			}

			sameOutcome := reflect.DeepEqual(got.Errors, c.Errors) &&
				reflect.DeepEqual(got.SQLErrors, c.SQLErrors)
			sameSQL := equalCaseSQL(got.SQL, c.SQL)

			if exempt {
				used[c.Name] = true
				switch ex.kind {
				case exemptDiverges:
					if sameOutcome && sameSQL {
						t.Errorf("exempt as %q, but the registry catalogue now matches the fixture — "+
							"delete the exemption", ex.reason)
					}
				case exemptSQLOnly:
					if !sameOutcome {
						t.Errorf("exempt as SQL-only, but the OUTCOME differs too "+
							"(errors want %v got %v): re-classify or fix", c.Errors, got.Errors)
					}
					if sameSQL {
						t.Errorf("exempt as %q, but the SQL now matches — delete the exemption", ex.reason)
					}
				}
				return
			}

			if !reflect.DeepEqual(got.Errors, c.Errors) {
				t.Errorf("errors:\n  got  %v\n  want %v", got.Errors, c.Errors)
			}
			if !reflect.DeepEqual(got.SQLErrors, c.SQLErrors) {
				t.Errorf("sql errors:\n  got  %v\n  want %v", got.SQLErrors, c.SQLErrors)
			}
			if !sameSQL {
				t.Errorf("sql:\n  got  %s\n  want %s", showSQL(got.SQL), showSQL(c.SQL))
			}
		})
	}

	// The other direction: an exemption naming a case that no longer exists is
	// a line nobody will ever read again, and it would silently excuse a
	// future case that happened to be given the same name.
	var stale []string
	for name := range registryExemptions {
		if !used[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("exemptions naming no fixture: %s", strings.Join(stale, ", "))
	}
}

// TestConformance_RegistryCatalogNoTenantPredicate is §7.2's rule, checked on
// the catalogue production actually runs. The existing check covers the static
// one; a tenant predicate that only the registry catalogue's accessors could
// produce would slip past it.
func TestConformance_RegistryCatalogNoTenantPredicate(t *testing.T) {
	cat := registrycatalog.New(registrycatalog.Options{})
	for _, c := range loadCases(t) {
		got := runWith(c, cat, ladder.CVSS)
		if got.SQL == nil {
			continue
		}
		if strings.Contains(got.SQL.Where, "tenant") {
			t.Errorf("%s: generated SQL mentions a tenant predicate: %s", c.Name, got.SQL.Where)
		}
		if strings.Contains(got.SQL.Where, "'") {
			t.Errorf("%s: generated SQL contains a quoted literal: %s", c.Name, got.SQL.Where)
		}
	}
}

// TestDefaultCatalogIsTheRegistryCatalogue holds the wire-up hook: the façade's
// default must be the production catalogue on the production ladder, or a
// caller that takes the default gets something other than what this file tests.
func TestDefaultCatalogIsTheRegistryCatalogue(t *testing.T) {
	cat := query.DefaultCatalog()

	if got, want := len(cat.Targets()), 10; got != want {
		t.Errorf("DefaultCatalog has %d targets, want %d", got, want)
	}
	if _, err := cat.Resolve("asset", []string{"attr", "firmware_version"}); err != nil {
		t.Errorf("DefaultCatalog cannot resolve a registry attribute: %v", err)
	}

	// DefaultOptionsFor takes the ladder from the catalogue, so the threshold
	// in the SQL and the labels in the autocomplete cannot come from two
	// different ladders.
	c, err := query.Compile("risk >= high", "asset", cat, query.DefaultOptionsFor(cat))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(c.Args) != 1 || c.Args[0] != 70 {
		t.Errorf("risk >= high bound %v, want the CVSS×10 rung 70", c.Args)
	}

	// And the mutation half: a catalogue built with a DIFFERENT ladder must
	// move the threshold. Without this, DefaultOptionsFor could be ignoring
	// the catalogue and hard-coding CVSS, and every assertion above would
	// still pass.
	shifted := registrycatalog.New(registrycatalog.Options{Ladder: ladder.FromRungs(95, 75, 45, 5)})
	c, err = query.Compile("risk >= high", "asset", shifted, query.DefaultOptionsFor(shifted))
	if err != nil {
		t.Fatalf("compile on the shifted ladder: %v", err)
	}
	if len(c.Args) != 1 || c.Args[0] != 75 {
		t.Errorf("risk >= high bound %v on a ladder whose High is 75", c.Args)
	}
}

// TestRegistryCatalog_JSONBCasts is where the coverage the exemptions give up
// comes back.
//
// Three fixtures pin the guarded jsonb casts through names the registry does
// not define — `attr.cpu_count` typed as a number, `attr.controller_managed`,
// `fact.sw.package_count`. Exempting them without this would quietly drop the
// §7.2 shape-2 coverage on the catalogue production actually uses. These are
// the same shapes through attributes and keys the registry DOES declare.
func TestRegistryCatalog_JSONBCasts(t *testing.T) {
	cat := registrycatalog.New(registrycatalog.Options{})
	opts := query.DefaultOptionsFor(cat)

	for _, tc := range []struct {
		name  string
		query string
		want  string
		args  []any
	}{{
		// integer attribute → the guarded ::numeric cast. The CASE with no
		// ELSE is §5.2: a value that is present but unparseable reads as
		// UNKNOWN, not as a cast error and not as zero.
		name:  "numeric attribute",
		query: "attr.cpu_count < 3",
		want:  `((CASE WHEN (a.attributes ->> $1) ~ $2 THEN ((a.attributes ->> $1))::numeric END) < $3)`,
		args:  []any{"cpu_count", `^-?[0-9]+(\.[0-9]+)?$`, int64(3)},
	}, {
		name:  "boolean attribute",
		query: "attr.mdm_enrolled:true",
		want:  `((CASE WHEN lower((a.attributes ->> $1)) IN ($2, $3) THEN (lower((a.attributes ->> $1)))::boolean END) = $4)`,
		args:  []any{"mdm_enrolled", "true", "false", true},
	}, {
		// §13 A2's second half: presence tests the RAW text, before the
		// declared-type cast, so "present but unparseable" is not "absent".
		name:  "attribute presence",
		query: "exists(attr.cpu_count)",
		want:  `((a.attributes ->> $1) IS NOT NULL)`,
		args:  []any{"cpu_count"},
	}, {
		// A date fact is a timestamp, through the same guard.
		name:  "timestamp fact",
		query: "fact.eol.os.date > now+90d",
		want: `((SELECT (CASE WHEN (af1.value #>> $1::text[]) ~ $2 THEN ((af1.value #>> $1::text[]))::timestamptz END) ` +
			`FROM asset_facts af1 WHERE af1.asset_id = a.id AND af1.key = $7 ` +
			`ORDER BY array_position(ARRAY[$3, $4, $5, $6], af1.source_kind), af1.observed_at DESC LIMIT 1) > $8)`,
	}, {
		// An integer fact: the number shape fact.sw.package_count used to pin.
		name:  "numeric fact",
		query: "fact.sw.package_count >= 900",
		want: `((SELECT (CASE WHEN (af1.value #>> $1::text[]) ~ $2 THEN ((af1.value #>> $1::text[]))::numeric END) ` +
			`FROM asset_facts af1 WHERE af1.asset_id = a.id AND af1.key = $7 ` +
			`ORDER BY array_position(ARRAY[$3, $4, $5, $6], af1.source_kind), af1.observed_at DESC LIMIT 1) >= $8)`,
	}, {
		// An ARRAY fact answers presence and nothing else, and presence is
		// an EXISTS over the raw rows (§13 A4) — no reconciliation, no cast.
		name:  "array fact presence",
		query: "exists(fact.net.interfaces)",
		want: `EXISTS (SELECT 1 FROM asset_facts af1 WHERE af1.asset_id = a.id AND af1.key = $1 ` +
			`AND ((af1.value #>> $2::text[]) IS NOT NULL))`,
		args: []any{"net.interfaces", "{}"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := query.Compile(tc.query, "asset", cat, opts)
			if err != nil {
				t.Fatalf("compile %q: %v", tc.query, err)
			}
			if c.Where != tc.want {
				t.Errorf("where:\n  got  %s\n  want %s", c.Where, tc.want)
			}
			if tc.args != nil && !reflect.DeepEqual(c.Args, tc.args) {
				t.Errorf("args:\n  got  %#v\n  want %#v", c.Args, tc.args)
			}
		})
	}

	// The refusals, which are the other half of the json rule: an array or
	// object value cannot be compared at all, and the error says so rather
	// than generating `unnest(text)` or a substring search over JSON source.
	for _, q := range []string{
		"fact.net.interfaces:eth0",
		"fact.net.vlans:10",
		"attr.industrial_protocols:modbus",
	} {
		if _, err := query.Compile(q, "asset", cat, opts); err == nil {
			t.Errorf("%q compiled; a json field accepts only exists()", q)
		} else if codes := query.Errors(err); len(codes) != 1 || codes[0].Code != "operator_not_allowed" {
			t.Errorf("%q reported %v, want operator_not_allowed", q, codes)
		}
	}
}

func equalCaseSQL(a, b *CaseSQL) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Where == b.Where && a.ArgCount == b.ArgCount && equalJSON(a.Args, b.Args)
}

func showSQL(s *CaseSQL) string {
	if s == nil {
		return "<none>"
	}
	return s.Where + "  args=" + string(s.Args)
}
