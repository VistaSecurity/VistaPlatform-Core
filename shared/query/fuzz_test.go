package query_test

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/format"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
	"github.com/vistasecurity/vistaplatform/shared/query/sql"
	"github.com/vistasecurity/vistaplatform/shared/query/validate"
)

// fuzzMaxBytes caps what the fuzzers feed the parser. It is deliberately far
// above §6's 4096-byte query cap: the parser sits BELOW that cap (Canonicalize
// parses with no options at all), so the fuzzer must be able to reach the
// parser's own depth guard with input the validator would have refused.
const fuzzMaxBytes = 1 << 20

// FuzzParse asserts the two properties that must hold for ANY input: the
// parser never panics, and anything it accepts formats and reparses to the
// same tree. The query language is fed by a URL, a saved view, a stored rule
// and an AI, so "never panics on arbitrary text" is a security property, not a
// tidiness one.
//
// Run longer with:
//
//	cd shared && go test ./query -run FuzzParse -fuzz FuzzParse -fuzztime 2m
func FuzzParse(f *testing.F) {
	for _, c := range loadSeedCorpus(f) {
		f.Add(c)
	}
	f.Fuzz(func(t *testing.T, src string) {
		// The cap is a megabyte, not §6's four kilobytes: the parser is the
		// layer BELOW the size cap (Canonicalize parses without one), so the
		// fuzzer has to be able to reach the depth guard with input the
		// validator would have refused. Anything larger is the explicit
		// ten-megabyte regression in parser_test.go, not a fuzz target.
		if len(src) > fuzzMaxBytes {
			return
		}
		res, err := parser.Parse(src)
		if err != nil {
			if _, ok := err.(queryerr.List); !ok {
				t.Fatalf("Parse(%q) returned %T, want a queryerr.List", src, err)
			}
			return
		}
		if res.Root == nil {
			if strings.TrimSpace(src) != "" {
				t.Fatalf("Parse(%q) returned no tree and no error", src)
			}
			return
		}

		canon := format.Format(res.Root)
		again, err := parser.Parse(canon)
		if err != nil {
			t.Fatalf("canonical form %q of %q does not reparse: %v", canon, src, err)
		}
		if !ast.EqualJSON(res.Root, again.Root) {
			a, _ := ast.MarshalJSON(res.Root)
			b, _ := ast.MarshalJSON(again.Root)
			t.Fatalf("%q canonicalised to %q parses differently:\n  %s\n  %s", src, canon, a, b)
		}
		if twice := format.Format(again.Root); twice != canon {
			t.Fatalf("%q: format is not idempotent:\n  once  %q\n  twice %q", src, canon, twice)
		}

		// Validation and translation must not panic either, whatever the tree.
		if _, err := validate.Validate(res, "asset", testcatalog.New(),
			validate.DefaultOptions().WithLadder(testcatalog.Ladder)); err != nil {
			if _, ok := err.(queryerr.List); !ok {
				t.Fatalf("Validate(%q) returned %T", src, err)
			}
		}
	})
}

// FuzzCompile asserts the invariant the package is built on: a query that
// VALIDATES always TRANSLATES. §6 reserves `untranslatable` for "a node that
// maps to none of the five SQL shapes — a parser bug, failing closed", so
// reaching it from a query the validator accepted is a hole, not a diagnostic,
// and it surfaces to the user as an error about nothing they wrote.
//
// The previous version only checked that Compile's error was a queryerr.List —
// which every error from this package is, so it could not fail, and did not.
// Every untranslatable-after-validation hole this review found (`*` on a
// derived field, `~` on one, `risk:[not_assessed to high]`) would have been
// caught here.
func FuzzCompile(f *testing.F) {
	for _, c := range loadSeedCorpus(f) {
		f.Add(c)
	}
	cat := testcatalog.New()
	opts := query.DefaultOptions(testcatalog.Ladder)
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > fuzzMaxBytes {
			return
		}
		res, err := parser.Parse(src)
		if err != nil {
			return
		}
		root, err := validate.Validate(res, "asset", cat, opts.Validate)
		if err != nil {
			// Not a valid query; what the translator would do with it is not
			// this test's business.
			return
		}
		_, _, err = sql.Translate(root, "asset", cat, opts.SQL)
		if err == nil {
			return
		}
		list, ok := err.(queryerr.List)
		if !ok {
			t.Fatalf("Translate(%q) returned %T, want a queryerr.List", src, err)
		}
		if list.Has(queryerr.CodeUntranslatable) {
			t.Fatalf("%q validated and then failed to translate: %v", src, list)
		}
	})
}

// loadSeedCorpus seeds the fuzzers with every conformance query, so the
// interesting shapes are explored first.
func loadSeedCorpus(f *testing.F) []string {
	f.Helper()
	var t testing.T
	cases := loadCases(&t)
	if t.Failed() {
		f.Fatal("could not load the conformance fixtures")
	}
	out := make([]string, 0, len(cases)+8)
	for _, c := range cases {
		out = append(out, c.Query)
	}
	return append(out,
		"", " ", "(", ")", "\"", "\\", "a:", ":", "not", "and", "-", "~",
		"a:(", "[", "]", "a:[1 to", "exists(", "rel(", "\x00", "é:1", "a:\"\\u",
	)
}
