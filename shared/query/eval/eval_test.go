package eval_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/eval"
)

// mapSource answers from a map keyed by the accessor's column name, which is
// how a real Source is written (see shared/approval's observationSource).
type mapSource struct {
	fields map[string]any
	text   []string
}

func (m mapSource) Field(ref ast.FieldRef) (any, bool) {
	v, ok := m.fields[ref.Accessor.Column]
	return v, ok
}

func (m mapSource) FreeText() []string { return m.text }

func check(t *testing.T, src string, target string, s eval.Source) eval.Result {
	t.Helper()
	cat := query.DefaultCatalog()
	node, err := query.Check(src, target, cat, query.DefaultOptionsFor(cat).Validate)
	if err != nil {
		t.Fatalf("%q did not validate: %v", src, err)
	}
	r, err := eval.Eval(node, s, eval.Options{Now: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC), Ladder: cat.Ladder()})
	if err != nil {
		t.Fatalf("%q: %v", src, err)
	}
	return r
}

// TestObservationConformanceFixtures runs every case in the shared conformance
// file whose target is `observation`.
//
// Those cases carry `sql_errors: [untranslatable]` — the SQL translator refuses
// them by design (§4.1), which is exactly why this package exists. The fixtures
// pin what they PARSE to; this pins that the in-memory evaluator can actually
// ANSWER them, which nothing else checks.
//
// There were three of them for 640 lines of auto-approval logic. There are two
// dozen now, and the assertion changed shape with them: "every fixture matches
// this one observation" was a property of having three fixtures that all
// described the same discovery, not a property of the language.
func TestObservationConformanceFixtures(t *testing.T) {
	path := filepath.Join("..", "testdata", "conformance.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var cases []struct {
		Name   string `json:"name"`
		Query  string `json:"query"`
		Target string `json:"target"`
		// Errors are the PARSE or VALIDATION diagnostics. A fixture that has
		// them documents a refusal — an asset field on the observation target,
		// a sub-predicate over a collection an observation does not carry — and
		// the thing to assert about it is that it is still refused.
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}

	// A FULLY populated observation: every field the target declares, so a
	// fixture that asks about any of them gets a definite answer rather than
	// Unknown. The values are chosen to satisfy the fixtures that describe an
	// ordinary internal discovery.
	populated := mapSource{fields: map[string]any{
		"source":             "agent",
		"confidence":         0.95,
		"class_key":          "server",
		"class_path":         "hardware.computer.server",
		"hostname":           "db-01.example.test",
		"address":            "198.51.100.10",
		"network_ownership":  "internal",
		"network_type":       "private",
		"network_segment_id": "0e8b2e1e-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
		"first_seen_at":      time.Now().Add(-24 * time.Hour),
	}}
	// The same observation with NOTHING measured. No fixture may return True
	// against it — a predicate over an absent value is Unknown, not False, and
	// certainly not True (§5.2).
	empty := mapSource{fields: map[string]any{}}

	seen, refusals := 0, 0
	for _, c := range cases {
		if c.Target != "observation" {
			continue
		}
		seen++
		t.Run(c.Name, func(t *testing.T) {
			if len(c.Errors) > 0 {
				// A documented refusal. It must STILL be refused: an evaluator
				// that quietly accepted an asset field on an observation would
				// answer a question about a value that does not exist yet.
				refusals++
				cat := query.DefaultCatalog()
				_, cErr := query.Check(c.Query, "observation", cat, query.DefaultOptionsFor(cat).Validate)
				if cErr == nil {
					t.Errorf("%q is recorded as invalid on the observation target (%v) and the "+
						"evaluator accepted it", c.Query, c.Errors)
				}
				return
			}
			// Everything else must be ANSWERABLE. The old assertion was that
			// every fixture matched one specific observation, which held while
			// there were three of them and stopped being a property the moment
			// the corpus described more than one kind of discovery.
			if got := check(t, c.Query, "observation", populated); got == eval.Unknown {
				t.Errorf("%q against a fully populated observation = Unknown; the evaluator cannot "+
					"answer a question an approval rule is allowed to ask", c.Query)
			}
			// A fixture that asks about a VALUE must not match an observation
			// with nothing measured: a predicate over an absent value is
			// Unknown, not True (§5.2).
			//
			// Negated EXISTENCE is not an exception to that rule, it is the
			// rule read correctly — `not exists(network.segment_id)` is asking
			// about presence, and the honest answer for an observation with no
			// segment is yes. That is precisely the rule a tenant writes to
			// catch discoveries from unmapped networks.
			if strings.Contains(c.Query, "not exists(") {
				if got := check(t, c.Query, "observation", empty); got != eval.True {
					t.Errorf("%q against an observation with nothing measured = %v, want true — "+
						"the absence IS the thing it asks about", c.Query, got)
				}
				return
			}
			if got := check(t, c.Query, "observation", empty); got == eval.True {
				t.Errorf("%q matched an observation with nothing measured", c.Query)
			}
		})
	}
	if seen < 20 {
		t.Fatalf("only %d observation fixtures ran; 640 lines of auto-approval logic are covered "+
			"by this corpus and it must not shrink back to a handful", seen)
	}
	if refusals == 0 {
		t.Error("no observation fixture documents a REFUSAL; without one, nothing pins that the " +
			"target rejects asset fields and sub-predicates")
	}
}

// TestThreeValuedLogic is §5.2 written out: a predicate over an absent value
// matches NEITHER itself nor its negation, and the two together do not
// partition the input.
func TestThreeValuedLogic(t *testing.T) {
	absent := mapSource{fields: map[string]any{}}
	present := mapSource{fields: map[string]any{"confidence": 0.9}}

	for _, tc := range []struct {
		q    string
		src  eval.Source
		want eval.Result
	}{
		{"confidence >= 0.8", absent, eval.Unknown},
		{"not confidence >= 0.8", absent, eval.Unknown},
		{"confidence >= 0.8", present, eval.True},
		{"not confidence >= 0.8", present, eval.False},
		{"confidence < 0.8", present, eval.False},

		// False beats Unknown in a conjunction; True beats Unknown in a
		// disjunction. Both matter: without the first, an unmeasured term would
		// mask a definite no.
		{"confidence >= 0.8 and source:cloud", withSource(present, "cloud"), eval.True},
		{"confidence >= 0.8 and source:sensor", withSource(present, "cloud"), eval.False},
		{"confidence >= 0.8 and source:sensor", absent, eval.Unknown},
		{"confidence >= 0.8 or source:sensor", present, eval.True},
		{"confidence >= 0.8 or source:sensor", absent, eval.Unknown},
	} {
		if got := check(t, tc.q, "observation", tc.src); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

// TestExistsIsNotAComparison: `exists(f)` is two-valued — it asks whether the
// value is there at all, which is always answerable.
func TestExistsIsNotAComparison(t *testing.T) {
	absent := mapSource{fields: map[string]any{}}
	present := mapSource{fields: map[string]any{"network_segment_id": "550e8400-e29b-41d4-a716-446655440000"}}

	if got := check(t, "exists(network.segment_id)", "observation", absent); got != eval.False {
		t.Errorf("exists over an absent value = %v, want false", got)
	}
	if got := check(t, "exists(network.segment_id)", "observation", present); got != eval.True {
		t.Errorf("exists over a present value = %v, want true", got)
	}
	if got := check(t, "not exists(network.segment_id)", "observation", absent); got != eval.True {
		t.Errorf("not exists over an absent value = %v, want true", got)
	}
}

// TestPerTypeOperators covers each type the observation catalogue declares, in
// both polarities, because a comparison that can only pass is not a comparison.
func TestPerTypeOperators(t *testing.T) {
	src := mapSource{
		fields: map[string]any{
			"source":     "sensor",
			"confidence": 0.75,
			"hostname":   "web-01.corp.example",
			"address":    netip.MustParseAddr("198.51.100.17"),
			// The class field's accessor names class_key as its column and
			// class_path as its subtree column; a Source answers with the PATH
			// for both, which is what lets one value serve `class:` and
			// `class=` (§5.3).
			"class_key":          "hardware.computer.server",
			"network_segment_id": "550e8400-e29b-41d4-a716-446655440000",
			"first_seen_at":      time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		},
		text: []string{"web-01.corp.example", "198.51.100.17"},
	}

	for _, tc := range []struct {
		q    string
		want eval.Result
	}{
		// keyword: `:` is case-insensitive equality.
		{"source:SENSOR", eval.True},
		{"source:cloud", eval.False},
		{"source in (sensor, cloud)", eval.True},
		{"source not in (sensor, cloud)", eval.False},

		// text: `:` is substring, `=` is exact and case-sensitive.
		{"hostname:corp", eval.True},
		{"hostname:CORP", eval.True},
		{`hostname="web-01.corp.example"`, eval.True},
		{`hostname="WEB-01.corp.example"`, eval.False},
		{"hostname:web-*", eval.True},
		{"hostname:db-*", eval.False},
		{`hostname ~ "^web-[0-9]{2}\\."`, eval.True},
		{`hostname ~ "^db-"`, eval.False},

		// number, and a range.
		{"confidence >= 0.75", eval.True},
		{"confidence > 0.75", eval.False},
		{"confidence:[0.5 to 0.8]", eval.True},
		{"confidence:[0.8 to 0.9]", eval.False},

		// inet: `:` is CIDR containment.
		{"address:198.51.100.0/24", eval.True},
		{"address:203.0.113.0/24", eval.False},
		{"address:198.51.100.17", eval.True},

		// class: `:` is the subtree, `=` the exact class.
		{"class:hardware", eval.True},
		{"class:hardware.computer", eval.True},
		{"class:cloud_resource", eval.False},
		{"class=server", eval.True},
		{"class=hardware", eval.False},

		// uuid and timestamp.
		{"network.segment_id=550e8400-e29b-41d4-a716-446655440000", eval.True},
		{"network.segment_id=550e8400-e29b-41d4-a716-446655440001", eval.False},
		{"first_seen < now-5d", eval.True},
		{"first_seen > now-5d", eval.False},

		// Free text is NOT available on an observation: the validator refuses
		// it, because the §5.4 corpus (display name, identifier values, tags)
		// is the asset's and the asset does not exist yet. Covered by
		// TestFreeTextIsRefusedOnObservations below rather than here.
	} {
		if got := check(t, tc.q, "observation", src); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.q, got, tc.want)
		}
	}
}

// TestSubAndTraverseAreRefused: an observation has no child collections and no
// edges — it is not an asset yet. Refusing is the fail-closed answer; returning
// false would let `not endpoint:(port:22)` quietly match everything.
func TestSubAndTraverseAreRefused(t *testing.T) {
	cat := query.DefaultCatalog()
	opts := query.DefaultOptionsFor(cat)
	for _, src := range []string{"endpoint:(port:443)", "depends_on:(class=server)"} {
		node, err := query.Check(src, "observation", cat, opts.Validate)
		if err != nil {
			// Refused by the validator is also fine — better, even.
			continue
		}
		if _, err := eval.Eval(node, mapSource{}, eval.Options{Ladder: cat.Ladder()}); err == nil {
			t.Errorf("%q must be refused by the evaluator, not silently answered", src)
		}
	}
}

func withSource(m mapSource, source string) mapSource {
	fields := make(map[string]any, len(m.fields)+1)
	for k, v := range m.fields {
		fields[k] = v
	}
	fields["source"] = source
	return mapSource{fields: fields, text: m.text}
}

// TestFreeTextIsRefusedOnObservations: §5.4's corpus is the ASSET's display
// name, hostname, identifier values and tags. An observation has not been
// resolved to an asset, so most of that does not exist — and the validator
// refuses the term rather than searching the half of it that does, which would
// be a free-text query that quietly means something narrower than it does
// everywhere else.
func TestFreeTextIsRefusedOnObservations(t *testing.T) {
	cat := query.DefaultCatalog()
	if _, err := query.Check("payroll", "observation", cat, query.DefaultOptionsFor(cat).Validate); err == nil {
		t.Fatal("a bare free-text term must be refused on the observation target")
	}
	// The same term IS legal on an asset, which is the other polarity: the
	// refusal is about the target, not about free text.
	if _, err := query.Check("payroll", "asset", cat, query.DefaultOptionsFor(cat).Validate); err != nil {
		t.Fatalf("free text must still work on assets: %v", err)
	}
}

// TestFreeTextCorpusIsUsedWhereItIsLegal exercises the FreeText path on a
// target that allows it, so the Source method is not dead code that nothing
// ever calls.
func TestFreeTextCorpusIsUsedWhereItIsLegal(t *testing.T) {
	src := mapSource{
		fields: map[string]any{"hostname": "web-01.corp.example"},
		text:   []string{"web-01.corp.example", "Payroll DB"},
	}
	if got := check(t, "payroll", "asset", src); got != eval.True {
		t.Errorf("free text over the corpus = %v, want true", got)
	}
	if got := check(t, "ledger", "asset", src); got != eval.False {
		t.Errorf("free text with no match = %v, want false", got)
	}
}
