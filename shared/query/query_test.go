package query_test

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
)

func TestCompile(t *testing.T) {
	c, err := query.Compile("environment:production class:server", "asset",
		testcatalog.New(), query.DefaultOptions(testcatalog.Ladder))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if c.Canonical != "environment:production and class:server" {
		t.Errorf("canonical = %q", c.Canonical)
	}
	if !strings.Contains(c.Where, "$1") || len(c.Args) != 3 {
		t.Errorf("where = %q, args = %v", c.Where, c.Args)
	}
	if c.Target != "asset" || c.Root == nil {
		t.Errorf("compiled query is missing its target or tree")
	}
}

func TestCompileReportsStructuredErrors(t *testing.T) {
	_, err := query.Compile("hostnaem:web-1", "asset",
		testcatalog.New(), query.DefaultOptions(testcatalog.Ladder))
	if err == nil {
		t.Fatal("expected an error")
	}
	list := query.Errors(err)
	if len(list) != 1 || list[0].Code != queryerr.CodeUnknownField {
		t.Fatalf("got %v, want one unknown_field", list)
	}
	// §10: the error carries the span and the fix, and renders with a caret.
	rendered := queryerr.Caret("hostnaem:web-1", list[0])
	if !strings.Contains(rendered, "^^^^^^^^") || !strings.Contains(rendered, "hostname") {
		t.Errorf("caret rendering is missing the span or the suggestion:\n%s", rendered)
	}
}

func TestCheckDoesNotTranslate(t *testing.T) {
	// The observation target has no table, so Compile refuses it and Check
	// does not: an approval rule is validated here and evaluated elsewhere.
	opts := query.DefaultOptions(testcatalog.Ladder)
	if _, err := query.Compile("source:sensor", "observation", testcatalog.New(), opts); err == nil {
		t.Error("Compile should refuse a target with no table")
	}
	if _, err := query.Check("source:sensor", "observation", testcatalog.New(), opts.Validate); err != nil {
		t.Errorf("Check should accept it: %v", err)
	}
}

// TestCompileCapsLengthBeforeParsing is the regression for the unrecoverable
// crash: the §6 query_too_long cap lived in the validator, which cannot run
// until the parser has already built a tree out of the text. Ten megabytes of
// parentheses therefore overflowed the goroutine stack — a runtime FATAL
// error, not a panic, so no recover() could catch it and the process died.
//
// Compile and Check must both refuse an over-long query before it is parsed.
func TestCompileCapsLengthBeforeParsing(t *testing.T) {
	huge := strings.Repeat("(", 5_000_000) + "a:1" + strings.Repeat(")", 5_000_000)
	opts := query.DefaultOptions(testcatalog.Ladder)

	if _, err := query.Compile(huge, "asset", testcatalog.New(), opts); err == nil {
		t.Fatal("Compile accepted a 10MB query")
	} else if list := query.Errors(err); !list.Has(queryerr.CodeQueryTooLong) {
		t.Errorf("Compile reported %v, want %s", list.Codes(), queryerr.CodeQueryTooLong)
	}
	if _, err := query.Check(huge, "asset", testcatalog.New(), opts.Validate); err == nil {
		t.Fatal("Check accepted a 10MB query")
	} else if list := query.Errors(err); !list.Has(queryerr.CodeQueryTooLong) {
		t.Errorf("Check reported %v, want %s", list.Codes(), queryerr.CodeQueryTooLong)
	}
}

func TestCanonicalizeNeedsNoCatalogue(t *testing.T) {
	got, err := query.Canonicalize("HOSTNAEM:x  and  -b:2")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hostnaem:x and not b:2" {
		t.Errorf("Canonicalize = %q", got)
	}
}

// TestCatalogInterfaceIsEnough is the plug-in check: the static catalogue is
// used everywhere through the interface, so the generated one drops in without
// a change to the parser, the validator or the translator.
func TestCatalogInterfaceIsEnough(t *testing.T) {
	var c catalog.Catalog = testcatalog.New()
	if len(c.Targets()) == 0 {
		t.Fatal("the catalogue has no targets")
	}
	if len(c.RelationshipNames()) != 20 {
		t.Errorf("got %d relationship names, want 20", len(c.RelationshipNames()))
	}
	if _, ok := c.ClassExists("server"); !ok {
		t.Error("class server should exist")
	}
	if _, ok := c.ClassExists("nonesuch"); ok {
		t.Error("class nonesuch should not exist")
	}
	for _, tgt := range c.Targets() {
		if len(c.Fields(tgt.Name)) == 0 {
			t.Errorf("target %q has no fields", tgt.Name)
		}
		// Every collection a target offers must have a field catalogue of its
		// own, or a sub-predicate over it could never resolve.
		for _, sub := range tgt.Subs {
			inner, ok := catalog.CollectionTarget[sub]
			if !ok {
				t.Errorf("target %q offers unknown collection %q", tgt.Name, sub)
				continue
			}
			if _, ok := catalog.FindTarget(c, inner); !ok {
				t.Errorf("collection %q has no target %q", sub, inner)
			}
		}
	}
}

// TestCatalogueFieldNamesAreUnique is §13 A1's structural half. `Fields`
// published two entries called "id" on every asset-shaped target — the uuid
// column and the any-kind identifier — so autocomplete offered one name for two
// fields and Resolve silently picked the namespace one, leaving §4.3's uuid
// column unreachable. A name has to mean one field.
func TestCatalogueFieldNamesAreUnique(t *testing.T) {
	c := testcatalog.New()
	for _, tgt := range c.Targets() {
		seen := map[string]ast.Accessor{}
		for _, f := range c.Fields(tgt.Name) {
			if prev, dup := seen[f.Name]; dup {
				t.Errorf("%s publishes %q twice: %+v and %+v", tgt.Name, f.Name, prev, f.Accessor)
			}
			seen[f.Name] = f.Accessor
		}
	}
}

// TestBareIdIsTheRowUUID pins §13 A1 in both directions: the bare name is the
// row's uuid, the any-kind identifier moved to `id.any`, and both resolve to
// the accessor they claim.
func TestBareIdIsTheRowUUID(t *testing.T) {
	c := testcatalog.New()
	opts := query.DefaultOptions(testcatalog.Ladder)

	got, err := query.Compile("id=550e8400-e29b-41d4-a716-446655440000", "asset", c, opts)
	if err != nil {
		t.Fatalf("id=<uuid>: %v", err)
	}
	if !strings.Contains(got.Where, "a.id = $1::uuid") {
		t.Errorf("id=<uuid> compiled to %q, want the uuid column", got.Where)
	}
	if cmp, ok := got.Root.(*ast.Compare); !ok || cmp.Field.Type != ast.TypeUUID {
		t.Errorf("bare id resolved to %v, want the uuid type", got.Root)
	}

	got, err = query.Compile(`id.any:"aa:bb:cc:dd:ee:ff"`, "asset", c, opts)
	if err != nil {
		t.Fatalf(`id.any:"…": %v`, err)
	}
	if !strings.Contains(got.Where, "FROM asset_identifiers") {
		t.Errorf(`id.any compiled to %q, want the identifier EXISTS`, got.Where)
	}
	if strings.Contains(got.Where, ".kind =") {
		t.Errorf("id.any should not filter on a kind: %q", got.Where)
	}

	// The old spelling now type-checks as a uuid, and says where it went.
	_, err = query.Compile(`id:"aa:bb:cc:dd:ee:ff"`, "asset", c, opts)
	list := query.Errors(err)
	if len(list) != 1 || list[0].Code != queryerr.CodeTypeMismatch {
		t.Fatalf(`id:"aa:bb…" reported %v, want one type_mismatch`, list)
	}
	if !strings.Contains(list[0].Suggestion, "id.any") {
		t.Errorf("suggestion %q should point at id.any", list[0].Suggestion)
	}
}

// TestEveryCatalogueFieldIsUsable walks the whole catalogue and compiles one
// query per field. A field that cannot be queried at all is a catalogue bug,
// and this is the cheapest way to find it.
func TestEveryCatalogueFieldIsUsable(t *testing.T) {
	c := testcatalog.New()
	opts := query.DefaultOptions(testcatalog.Ladder)
	for _, tgt := range c.Targets() {
		if tgt.InMemory {
			continue
		}
		for _, f := range c.Fields(tgt.Name) {
			name := f.Name
			if strings.ContainsAny(name, " \"") {
				continue
			}
			// EVERY field answers exists(), derived ones included — a
			// derived field is computed from something, and "is that
			// something there" is a question it can answer (S5).
			q := "exists(" + name + ")"
			if _, err := query.Compile(q, tgt.Name, c, opts); err != nil {
				t.Errorf("%s on %s: %v", q, tgt.Name, err)
			}
		}
	}
}

// TestEveryAllowedOperatorTranslates is S13's table half, and the operator
// matrix's first test of any kind.
//
// §4.4 says which operators each type accepts, and §6 says a validated query
// always translates. Nothing checked that the two agreed, so four operators
// were accepted by the matrix and refused by the translator — `*`, `~`, `in`
// and `!=` on the derived fields — each surfacing as `untranslatable`, the code
// §6 reserves for a parser bug.
//
// This walks every field of every table-backed target and compiles one query
// per operator the matrix allows, plus exists().
func TestEveryAllowedOperatorTranslates(t *testing.T) {
	c := testcatalog.New()
	opts := query.DefaultOptions(testcatalog.Ladder)

	for _, tgt := range c.Targets() {
		if tgt.InMemory {
			// No table, so untranslatable is the correct answer by design.
			continue
		}
		for _, f := range c.Fields(tgt.Name) {
			if strings.ContainsAny(f.Name, " \"") {
				continue // a quoted key needs quoting; covered by the fixtures
			}
			for _, q := range operatorProbes(f) {
				t.Run(tgt.Name+"/"+q, func(t *testing.T) {
					if _, err := query.Compile(q, tgt.Name, c, opts); err != nil {
						for _, e := range query.Errors(err) {
							if e.Code == queryerr.CodeUntranslatable {
								t.Fatalf("§4.4 allows this and the translator refuses it: %v", err)
							}
						}
						t.Fatalf("%v", err)
					}
				})
			}
		}
	}
}

// operatorProbes builds one query per operator §4.4 allows on a field.
func operatorProbes(f catalog.FieldInfo) []string {
	v := probeValue(f)
	var out []string
	for _, op := range []ast.Op{ast.OpColon, ast.OpEq, ast.OpNe, ast.OpLt, ast.OpLte, ast.OpGt, ast.OpGte} {
		if !catalog.OperatorAllowed(f.Type, op) {
			continue
		}
		sep := string(op)
		if op != ast.OpColon && op != ast.OpEq {
			sep = " " + sep + " "
		}
		out = append(out, f.Name+sep+v)
	}
	if catalog.InAllowed(f.Type) {
		out = append(out, f.Name+" in ("+v+")")
		out = append(out, f.Name+" not in ("+v+")")
	}
	if catalog.MatchAllowed(f.Type) {
		out = append(out, f.Name+` ~ "^x"`)
	}
	if catalog.RangeAllowed(f.Type) {
		out = append(out, f.Name+":["+v+" to "+v+"]")
	}
	if catalog.WildcardAllowed(f.Type) {
		out = append(out, f.Name+":"+partialWildcard(f))
	}
	// `field:*` and exists() are the presence spellings, legal on every type.
	return append(out, f.Name+":*", "exists("+f.Name+")")
}

// probeValue returns a literal the field's type accepts, so the probe exercises
// the OPERATOR rather than tripping over the value.
func probeValue(f catalog.FieldInfo) string {
	if len(f.Enum) > 0 {
		return f.Enum[0]
	}
	switch f.Type {
	case ast.TypeNumber:
		return "1"
	case ast.TypeTimestamp:
		return "now-1d"
	case ast.TypeBoolean:
		return "true"
	case ast.TypeInet:
		return "198.51.100.7"
	case ast.TypeClass:
		return "server"
	case ast.TypeBand:
		return "high"
	case ast.TypeVersion:
		return "3.0"
	case ast.TypeUUID:
		return "550e8400-e29b-41d4-a716-446655440000"
	}
	return "weak" // keyword, text, keyword[]: also a legal crypto strength
}

// partialWildcard returns a value with a "*" in it that still parses as the
// field's type where the type constrains the shape.
func partialWildcard(f catalog.FieldInfo) string {
	if f.Type == ast.TypeInet {
		return "198.51.100.*"
	}
	if f.Type == ast.TypeVersion {
		return "3.*"
	}
	return "we*"
}
