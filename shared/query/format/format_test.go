package format_test

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/format"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
)

func TestFormat(t *testing.T) {
	cases := map[string]string{
		// §10: implicit and written out, '-' written as not, ':=' as '='.
		"a:1 b:2":                        "a:1 and b:2",
		"-a:1":                           "not a:1",
		`a:="x"`:                         "a=x",
		"A:1 AND B:2":                    "a:1 and b:2",
		"a  :  1":                        "a:1",
		"a != 1":                         "a != 1",
		"a>=1":                           "a >= 1",
		"a in (1,2)":                     "a in (1, 2)",
		"a not in (1,2)":                 "a not in (1, 2)",
		"a:[1 to 2]":                     "a:[1 to 2]",
		`a~"x"`:                          `a ~ "x"`,
		"exists(a)":                      "exists(a)",
		"(a:1)":                          "a:1",
		"((a:1))":                        "a:1",
		"(a:1 or b:2)":                   "a:1 or b:2",
		"a:1 or (b:2)":                   "a:1 or b:2",
		"(a:1 or b:2) c:3":               "(a:1 or b:2) and c:3",
		"a:1 or b:2 and c:3":             "a:1 or b:2 and c:3",
		"not (a:1 or b:2)":               "not (a:1 or b:2)",
		"not (a:1 and b:2)":              "not (a:1 and b:2)",
		"a:(1 or 2)":                     "a:1 or a:2",
		"a:(1 and 2)":                    "a:1 and a:2",
		"a:(not 1)":                      "not a:1",
		"endpoint:(a:1)":                 "endpoint:(a:1)",
		"depends_on(1):(a:1)":            "depends_on:(a:1)",
		"depends_on(2):(a:1)":            "depends_on(2):(a:1)",
		"rel(connects_to, out, 1):(a:1)": "rel(connects_to, out):(a:1)",
		"last_seen<now-24h":              "last_seen < now-1d",
		"a:'x y'":                        `a:"x y"`,
	}
	for src, want := range cases {
		res, err := parser.Parse(src)
		if err != nil {
			t.Errorf("Parse(%q): %v", src, err)
			continue
		}
		if got := format.Format(res.Root); got != want {
			t.Errorf("Format(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestFormatEmpty(t *testing.T) {
	if got := format.Format(nil); got != "" {
		t.Errorf("Format(nil) = %q, want the empty query", got)
	}
}

// TestFormatIdempotenceProperty is §10's property, exercised over a generated
// grammar rather than a fixed list: for any query the generator can produce,
// Format(Format(q)) == Format(q), and the canonical text parses to the same
// tree. A hand fuzzer rather than testing/quick because the interesting inputs
// are grammatical, and random bytes almost never are — FuzzParse covers those.
func TestFormatIdempotenceProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(20260911))
	for i := 0; i < 3000; i++ {
		src := randomQuery(rng, 0)
		res, err := parser.Parse(src)
		if err != nil {
			t.Fatalf("generated query does not parse: %q: %v", src, err)
		}
		once := format.Format(res.Root)
		again, err := parser.Parse(once)
		if err != nil {
			t.Fatalf("canonical form %q of %q does not reparse: %v", once, src, err)
		}
		if twice := format.Format(again.Root); twice != once {
			t.Fatalf("not idempotent for %q:\n  once  %q\n  twice %q", src, once, twice)
		}
		if !ast.EqualJSON(res.Root, again.Root) {
			a, _ := ast.MarshalJSON(res.Root)
			b, _ := ast.MarshalJSON(again.Root)
			t.Fatalf("canonical form of %q parses differently:\n  %s\n  %s", src, a, b)
		}
	}
}

// randomQuery builds a grammatical query. depth bounds the recursion.
func randomQuery(rng *rand.Rand, depth int) string {
	if depth > 3 {
		return randomTerm(rng, depth)
	}
	switch rng.Intn(10) {
	case 0:
		return randomQuery(rng, depth+1) + " or " + randomQuery(rng, depth+1)
	case 1:
		return randomQuery(rng, depth+1) + " and " + randomQuery(rng, depth+1)
	case 2:
		return randomQuery(rng, depth+1) + " " + randomQuery(rng, depth+1)
	case 3:
		return "not " + randomQuery(rng, depth+1)
	case 4:
		return "-" + randomTerm(rng, depth+1)
	case 5:
		return "(" + randomQuery(rng, depth+1) + ")"
	default:
		return randomTerm(rng, depth)
	}
}

var (
	fields = []string{"hostname", "environment", "class", "risk_score", "attr.cpu_count",
		"tag.env", "id.mac", `tag."cost center"`, "last_seen"}
	values = []string{"production", "web-01", "70", "198.51.100.0/24", "aa:bb:*",
		`"two words"`, `"and"`, "now-24h", "now+90d", "3.0", "*", `"five*"`,
		// QUOTED strings shaped like a relative date. The formatter is
		// type-free, so it used to rewrite these too — see
		// TestQuotedDateShapedStringIsNotRewritten.
		`"now-24h"`, `"now"`, `"NOW+90D"`}
	rels  = []string{"depends_on", "used_by", "hosted_on", "any_rel"}
	colls = []string{"endpoint", "cert", "software", "finding"}
	ops   = []string{":", "=", "!=", " < ", " <= ", " > ", " >= "}
)

func randomTerm(rng *rand.Rand, depth int) string {
	switch rng.Intn(12) {
	case 0:
		return "exists(" + pick(rng, fields) + ")"
	case 1:
		return pick(rng, fields) + " in (" + pick(rng, values) + ", " + pick(rng, values) + ")"
	case 2:
		return pick(rng, fields) + " not in (" + pick(rng, values) + ")"
	case 3:
		return pick(rng, fields) + ":[" + strconv.Itoa(rng.Intn(50)) + " to " + strconv.Itoa(50+rng.Intn(50)) + "]"
	case 4:
		return pick(rng, fields) + ` ~ "^web[0-9]+"`
	case 5:
		return `"free text"`
	case 6:
		if depth > 2 {
			break
		}
		return pick(rng, colls) + ":(" + randomQuery(rng, depth+2) + ")"
	case 7:
		if depth > 2 {
			break
		}
		rel := pick(rng, rels)
		if rng.Intn(2) == 0 {
			rel += "(" + strconv.Itoa(1+rng.Intn(3)) + ")"
		}
		return rel + ":(" + randomQuery(rng, depth+2) + ")"
	case 8:
		if depth > 2 {
			break
		}
		return "rel(connects_to, " + pick(rng, []string{"out", "in", "any"}) + "):(" +
			randomQuery(rng, depth+2) + ")"
	case 9:
		return pick(rng, fields) + ":(" + pick(rng, values) + " or " + pick(rng, values) + ")"
	}
	return pick(rng, fields) + strings.TrimSpace(pick(rng, ops)) + pick(rng, values)
}

func pick(rng *rand.Rand, list []string) string { return list[rng.Intn(len(list))] }

// TestQuotedDateShapedStringIsNotRewritten is S7.
//
// §10 canonicalises a relative date into the largest exact unit, and the
// formatter is type-free — it decides by the shape of the node, never by a
// field's type. So it rewrote any value that LOOKED like one, quoted or not:
// `hostname="now-24h"` came out as `hostname=now-1d`, a different predicate
// that still parses. That is the worst shape a formatter bug can take, because
// nothing downstream can tell it happened.
//
// Quoting is exactly how a user says "I mean the text", so a quoted literal is
// never rewritten. The bare form carries no such ambiguity and still is.
func TestQuotedDateShapedStringIsNotRewritten(t *testing.T) {
	// The quotes are KEPT, for the same reason a quoted "*" keeps them:
	// unquoting would hand the bare form back to the date rule on the next
	// pass, so `Format(Format(q)) == Format(q)` would not hold.
	unchanged := map[string]string{
		`hostname="now-24h"`:      `hostname="now-24h"`,
		`hostname:"now-24h"`:      `hostname:"now-24h"`,
		`display_name:"now+90D"`:  `display_name:"now+90D"`,
		`hostname:'now-24h'`:      `hostname:"now-24h"`,
		`hostname in ("now-24h")`: `hostname in ("now-24h")`,
		// Free text is a substring search and can never be an instant, so it
		// is never date-canonicalised — quoted or not.
		`"now-24h"`: `now-24h`,
		`now-24h`:   `now-24h`,
		`"now+0Y"`:  `now+0Y`,
	}
	for src, want := range unchanged {
		res, err := parser.Parse(src)
		if err != nil {
			t.Errorf("Parse(%q): %v", src, err)
			continue
		}
		if got := format.Format(res.Root); got != want {
			t.Errorf("Format(%q) = %q, want %q — the stored predicate must not change", src, got, want)
		}
	}

	// The other polarity: a BARE date value is still canonicalised, or §10's
	// `24h` -> `1d` rule would have been dropped rather than narrowed.
	canonicalised := map[string]string{
		"last_seen<now-24h":              "last_seen < now-1d",
		"last_seen<now-14d":              "last_seen < now-2w",
		"last_seen < now-6months":        "last_seen < now-6mo",
		"last_seen:[now-24h to now+48h]": "last_seen:[now-1d to now+2d]",
	}
	for src, want := range canonicalised {
		res, err := parser.Parse(src)
		if err != nil {
			t.Errorf("Parse(%q): %v", src, err)
			continue
		}
		if got := format.Format(res.Root); got != want {
			t.Errorf("Format(%q) = %q, want %q", src, got, want)
		}
	}
}
