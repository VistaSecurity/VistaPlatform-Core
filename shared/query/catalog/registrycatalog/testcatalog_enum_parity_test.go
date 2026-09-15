package registrycatalog

// The source-kind family, held to one answer across both catalogues.
//
// `TestTestcatalogAgreesOnCryptoFieldNames` above compares field NAMES for one
// target, and was written after a rename disagreed across the two. This is its
// sibling for the thing a rename's quieter cousin breaks: a VALUE added to a
// closed set on one side and not the other.
//
// Scoped to the `*_source_kind` columns deliberately, because that family is the
// one with a live asymmetry to get wrong. `assets.class_source_kind` accepts
// five values; every other `source_kind` CHECK — on asset_facts,
// asset_identifiers, asset_endpoints, asset_relationships, software_installs and
// findings — accepts four, and `rule` is the difference (workstream 2.10b). Both
// directions are wrong in their own way: the static catalogue missing `rule`
// tells a user their predicate is invalid while the database accepts it, and any
// of the others GAINING it offers a predicate the database answers with no rows,
// for ever.
//
// It is not hypothetical. 2.10b put `rule` in the registry catalogue and left the
// static one at four. Nothing in Go noticed — no test compared the sets, and no
// conformance fixture writes the value — so it surfaced two workspaces away, as a
// failing assertion about a TypeScript array inside packages/primitives'
// generated-fields test, three hops from the edit that caused it.
//
// A WHOLE-CATALOGUE sweep is deliberately not attempted here: the static
// catalogue is a spec fixture and diverges from the registry on several other
// closed sets on purpose (a cut-down `attr.provider`, a `mac` alias on
// `identifier.kind`). Sorting out which of those are deliberate is its own piece
// of work, not a rider on this one.

import (
	"sort"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
)

func TestBothCataloguesAgreeOnTheSourceKinds(t *testing.T) {
	static := testcatalog.New()
	registry := newCatalog()

	// target -> field name, for every published field that reads a
	// `*_source_kind` column.
	cases := []struct {
		target, field string
		wantRule      bool
	}{
		{"asset", "source", true},
		{"identifier", "source_kind", false},
		{"relationship", "source", false},
	}
	for _, tc := range cases {
		t.Run(tc.target+"."+tc.field, func(t *testing.T) {
			reg := enumOf(t, registry.Fields(tc.target), tc.field)
			sta := enumOf(t, static.Fields(tc.target), tc.field)

			if !sameSet(reg, sta) {
				t.Errorf("closed value set differs:\n  registry %v\n  static   %v\n"+
					"one of them refuses a value the database accepts, or offers one it never answers",
					sorted(reg), sorted(sta))
			}
			for _, got := range [][]string{reg, sta} {
				if contains(got, "rule") != tc.wantRule {
					if tc.wantRule {
						t.Errorf("%v is missing `rule`; assets.class_source_kind is the one column "+
							"that accepts it (workstream 2.10b)", sorted(got))
					} else {
						t.Errorf("%v contains `rule`; only assets.class_source_kind accepts it — "+
							"every other *_source_kind CHECK refuses it, so this predicate would "+
							"validate and then return no rows for ever", sorted(got))
					}
				}
				// The four are the floor in every case, `rule` or no `rule`.
				for _, want := range []string{"measured", "declared", "imported", "inferred"} {
					if !contains(got, want) {
						t.Errorf("%v is missing %q, which every source-kind CHECK accepts", sorted(got), want)
					}
				}
			}
		})
	}
}

func enumOf(t *testing.T, fields []catalog.FieldInfo, name string) []string {
	t.Helper()
	for _, f := range fields {
		if f.Name == name {
			if len(f.Enum) == 0 {
				t.Fatalf("field %q publishes no closed value set; this test would then prove nothing", name)
			}
			return f.Enum
		}
	}
	t.Fatalf("no field named %q; if it was renamed, this guard has to move with it", name)
	return nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := sorted(a), sorted(b)
	for i := range x {
		if !strings.EqualFold(x[i], y[i]) {
			return false
		}
	}
	return true
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func contains(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}
