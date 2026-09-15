package query_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/testcatalog"
	"github.com/vistasecurity/vistaplatform/shared/query/format"
	"github.com/vistasecurity/vistaplatform/shared/query/parser"
	"github.com/vistasecurity/vistaplatform/shared/query/queryerr"
	"github.com/vistasecurity/vistaplatform/shared/query/sql"
	"github.com/vistasecurity/vistaplatform/shared/query/validate"
)

// update rewrites testdata/conformance.json from the current implementation.
// It is how a new case is filled in: add the name, query and note, run
// `go test ./query -run TestConformance -update`, then READ THE DIFF. The file
// is the contract, not a snapshot to be blessed unexamined.
var update = flag.Bool("update", false, "rewrite testdata/conformance.json")

// fixedNow pins the statement timestamp so a case with `now-30d` in it has one
// answer forever.
var fixedNow = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

const fixturePath = "testdata/conformance.json"

// Case is one conformance case. It is the cross-language contract: a
// TypeScript port of the language must produce the same canonical text, the
// same AST and the same SQL for every case in the file.
type Case struct {
	// Name identifies the case.
	Name string `json:"name"`
	// Query is the text under test.
	Query string `json:"query"`
	// Target is the collection the predicate is over; empty means asset.
	Target string `json:"target,omitempty"`
	// Twin names the nearest-passing case, for a failing case whose name does
	// not end in "-bad". Every failing case needs one: an over-strict guard is
	// the same bug as a missing one (§6's closing paragraph).
	Twin string `json:"twin,omitempty"`
	// Note says why the case exists, usually citing the spec section.
	Note string `json:"note,omitempty"`
	// Options override the validator caps, so a cap can be exercised with a
	// short query instead of a four-kilobyte one.
	Options *CaseOptions `json:"options,omitempty"`
	// Canonical is Format(Parse(Query)). Absent when the query does not parse.
	Canonical string `json:"canonical,omitempty"`
	// AST is the compact encoding of the parsed tree.
	AST json.RawMessage `json:"ast,omitempty"`
	// Errors are the parse or validation diagnostics, by code.
	Errors []CaseError `json:"errors,omitempty"`
	// SQL is the translated WHERE clause. Absent when the case does not reach
	// translation, or when the target has no table.
	SQL *CaseSQL `json:"sql,omitempty"`
	// SQLErrors are the translation diagnostics, for a query that validates
	// but has no SQL shape.
	SQLErrors []CaseError `json:"sql_errors,omitempty"`
}

// CaseOptions are the overridable §6 caps.
type CaseOptions struct {
	MaxBytes        int `json:"max_bytes,omitempty"`
	MaxLeaves       int `json:"max_leaves,omitempty"`
	MaxSubs         int `json:"max_subs,omitempty"`
	MaxParenDepth   int `json:"max_paren_depth,omitempty"`
	MaxInValues     int `json:"max_in_values,omitempty"`
	MaxRegexLen     int `json:"max_regex_len,omitempty"`
	MaxRepetition   int `json:"max_repetition,omitempty"`
	TraversalBudget int `json:"traversal_budget,omitempty"`
}

// CaseError is an expected diagnostic. Only the code is pinned: message
// wording should improve without a fixture rewrite.
type CaseError struct {
	Code string `json:"code"`
}

// CaseSQL is the expected translation.
//
// Args is the bind parameters, encoded as JSON. ArgCount alone was not a
// contract: it said how MANY values were bound and nothing about what they
// were, so a reversed range, a LIKE pattern with the padding on the wrong
// side, or a band bound off by a rung all produced the same number. A
// TypeScript port held only to the count would be free to bind anything.
type CaseSQL struct {
	Where    string          `json:"where"`
	ArgCount int             `json:"arg_count"`
	Args     json.RawMessage `json:"args,omitempty"`
}

func loadCases(t *testing.T) []Case {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var cases []Case
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("fixture file is empty")
	}
	return cases
}

// run executes one case against the static §4.3 catalogue — the catalogue the
// fixture file is the contract for.
func run(c Case) Case {
	return runWith(c, testcatalog.New(), testcatalog.Ladder)
}

// runWith executes one case against an arbitrary catalogue and ladder.
//
// The catalogue is a parameter because the fixtures are a contract about the
// LANGUAGE, and the language is meant to be catalogue-independent: nothing in
// the parser, validator, formatter or translator changes when the static
// catalogue is swapped for the production one. conformance_registry_test.go
// runs the whole file through registrycatalog to prove that, with an explicit
// list of the cases where the two catalogues genuinely disagree.
func runWith(c Case, cat catalog.Catalog, bands catalog.BandLadder) Case {
	out := Case{Name: c.Name, Query: c.Query, Target: c.Target, Twin: c.Twin, Note: c.Note, Options: c.Options}
	target := c.Target
	if target == "" {
		target = "asset"
	}

	res, err := parser.Parse(c.Query)
	if err != nil {
		out.Errors = codesOf(err)
		return out
	}
	out.Canonical = format.Format(res.Root)
	if enc, err := ast.MarshalJSON(res.Root); err == nil {
		out.AST = enc
	}

	root, err := validate.Validate(res, target, cat, caseValidateOptions(c, bands))
	if err != nil {
		out.Errors = codesOf(err)
		return out
	}

	where, args, err := sql.Translate(root, target, cat, sql.Options{
		Ladder: bands,
		Now:    fixedNow,
	})
	if err != nil {
		out.SQLErrors = codesOf(err)
		return out
	}
	out.SQL = &CaseSQL{Where: where, ArgCount: len(args), Args: encodeArgs(args)}
	return out
}

// encodeArgs renders the bind parameters as JSON. A time.Time becomes its
// RFC 3339 form, which is what the driver sends and what a port would compare.
func encodeArgs(args []any) json.RawMessage {
	if len(args) == 0 {
		return nil
	}
	out := make([]any, 0, len(args))
	for _, a := range args {
		if t, ok := a.(time.Time); ok {
			out = append(out, t.UTC().Format(time.RFC3339Nano))
			continue
		}
		out = append(out, a)
	}
	enc, err := json.Marshal(out)
	if err != nil {
		return json.RawMessage(`"<unencodable>"`)
	}
	return enc
}

func caseValidateOptions(c Case, bands catalog.BandLadder) validate.Options {
	opts := validate.DefaultOptions().WithLadder(bands)
	if c.Options == nil {
		return opts
	}
	set := func(dst *int, v int) {
		if v != 0 {
			*dst = v
		}
	}
	set(&opts.MaxBytes, c.Options.MaxBytes)
	set(&opts.MaxLeaves, c.Options.MaxLeaves)
	set(&opts.MaxSubs, c.Options.MaxSubs)
	set(&opts.MaxParenDepth, c.Options.MaxParenDepth)
	set(&opts.MaxInValues, c.Options.MaxInValues)
	set(&opts.MaxRegexLen, c.Options.MaxRegexLen)
	set(&opts.MaxRepetition, c.Options.MaxRepetition)
	set(&opts.TraversalBudget, c.Options.TraversalBudget)
	return opts
}

func codesOf(err error) []CaseError {
	list := query.Errors(err)
	if list == nil {
		return []CaseError{{Code: "internal"}}
	}
	out := make([]CaseError, 0, len(list))
	for _, e := range list {
		out = append(out, CaseError{Code: string(e.Code)})
	}
	return out
}

// TestConformance runs the whole fixture file. It is the single table-driven
// test the spec's §3, §5, §6, §9 and §10 examples all land in.
func TestConformance(t *testing.T) {
	cases := loadCases(t)

	if *update {
		updated := make([]Case, 0, len(cases))
		for _, c := range cases {
			updated = append(updated, run(c))
		}
		writeFixtures(t, updated)
		t.Log("fixtures rewritten; review the diff")
		return
	}

	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.Name] {
			t.Errorf("duplicate case name %q", c.Name)
		}
		seen[c.Name] = true

		t.Run(c.Name, func(t *testing.T) {
			got := run(c)
			if got.Canonical != c.Canonical {
				t.Errorf("canonical:\n  got  %q\n  want %q", got.Canonical, c.Canonical)
			}
			if !equalJSON(got.AST, c.AST) {
				t.Errorf("ast:\n  got  %s\n  want %s", got.AST, c.AST)
			}
			if !reflect.DeepEqual(got.Errors, c.Errors) {
				t.Errorf("errors:\n  got  %v\n  want %v", got.Errors, c.Errors)
			}
			if !reflect.DeepEqual(got.SQLErrors, c.SQLErrors) {
				t.Errorf("sql errors:\n  got  %v\n  want %v", got.SQLErrors, c.SQLErrors)
			}
			switch {
			case got.SQL == nil && c.SQL != nil:
				t.Errorf("sql: got none, want %q", c.SQL.Where)
			case got.SQL != nil && c.SQL == nil:
				t.Errorf("sql: got %q, want none", got.SQL.Where)
			case got.SQL != nil && c.SQL != nil:
				if got.SQL.Where != c.SQL.Where {
					t.Errorf("sql where:\n  got  %s\n  want %s", got.SQL.Where, c.SQL.Where)
				}
				if got.SQL.ArgCount != c.SQL.ArgCount {
					t.Errorf("sql arg_count: got %d, want %d", got.SQL.ArgCount, c.SQL.ArgCount)
				}
				if !equalJSON(got.SQL.Args, c.SQL.Args) {
					t.Errorf("sql args:\n  got  %s\n  want %s", got.SQL.Args, c.SQL.Args)
				}
			}
		})
	}
}

// TestConformance_CoversEveryErrorCode holds the fixture file to §6: every code
// appears, and every code that can fail also has a case that passes. An
// over-strict guard is the same bug as a missing one, so both polarities are
// required (§6's closing paragraph).
func TestConformance_CoversEveryErrorCode(t *testing.T) {
	cases := loadCases(t)
	failing := map[string]bool{}
	for _, c := range cases {
		for _, e := range c.Errors {
			failing[e.Code] = true
		}
		for _, e := range c.SQLErrors {
			failing[e.Code] = true
		}
	}
	required := []queryerr.Code{
		queryerr.CodeSyntax,
		queryerr.CodeUnknownField,
		queryerr.CodeOperatorNotAllowed,
		queryerr.CodeTypeMismatch,
		queryerr.CodeUnknownValue,
		queryerr.CodeDepthExceeded,
		queryerr.CodeRegexInvalid,
		queryerr.CodeQueryTooLong,
		queryerr.CodeTooManyClauses,
		queryerr.CodeUntranslatable,
	}
	for _, code := range required {
		if !failing[string(code)] {
			t.Errorf("no fixture produces %s", code)
		}
	}

	// The nearest-passing half, and the reason it is now structural.
	//
	// The rule used to fire only on a name ending "-bad", so a failing case
	// called anything else was silently exempt — and five were. A guard that
	// inspects only the cases which opted into it is not a guard.
	//
	// EVERY failing case must name a passing twin: by the "-bad"/"-ok"
	// convention, or with an explicit "twin" field. And every "-ok" must have
	// something that claims it, so a twin cannot be left behind when the
	// failing case it answers is deleted.
	byName := map[string]Case{}
	for _, c := range cases {
		byName[c.Name] = c
	}
	fails := func(c Case) bool { return len(c.Errors) > 0 || len(c.SQLErrors) > 0 }

	claimed := map[string]bool{}
	for _, c := range cases {
		if !fails(c) {
			if c.Twin != "" {
				t.Errorf("case %q passes, so it should not name a twin", c.Name)
			}
			continue
		}
		twin := c.Twin
		switch {
		case twin != "":
		case strings.HasSuffix(c.Name, "-bad"):
			twin = strings.TrimSuffix(c.Name, "-bad") + "-ok"
		default:
			t.Errorf("case %q reports %v%v but names no nearest-passing twin; "+
				"rename it \"…-bad\" or give it a \"twin\" field", c.Name, c.Errors, c.SQLErrors)
			continue
		}
		claimed[twin] = true
		pair, ok := byName[twin]
		if !ok {
			t.Errorf("case %q has no nearest-passing twin %q", c.Name, twin)
			continue
		}
		if fails(pair) {
			t.Errorf("case %q is meant to pass but reports %v%v", twin, pair.Errors, pair.SQLErrors)
		}
	}

	// The other direction: an "-ok" case nothing claims is a twin whose
	// partner has gone, and it no longer proves anything about a guard.
	for _, c := range cases {
		if !strings.HasSuffix(c.Name, "-ok") || claimed[c.Name] {
			continue
		}
		t.Errorf("case %q is a nearest-passing twin, but nothing fails that it answers", c.Name)
	}
}

// TestConformance_NoTenantPredicate is the §7.2 rule that matters most: every
// statement runs under RLS, so the translator emits no tenant predicate of its
// own. A bug here would look like an isolation control.
func TestConformance_NoTenantPredicate(t *testing.T) {
	for _, c := range loadCases(t) {
		// Both the recorded SQL and the SQL generated right now: the stored
		// half catches a fixture regenerated over a broken translator, and the
		// live half catches a translator that has started emitting one. A
		// check on the file alone could not fail until someone ran -update.
		if c.SQL != nil && strings.Contains(c.SQL.Where, "tenant") {
			t.Errorf("%s: recorded SQL mentions a tenant predicate: %s", c.Name, c.SQL.Where)
		}
		if got := run(c); got.SQL != nil && strings.Contains(got.SQL.Where, "tenant") {
			t.Errorf("%s: generated SQL mentions a tenant predicate: %s", c.Name, got.SQL.Where)
		}
	}
}

// TestConformance_EveryLiteralIsBound proves parameterisation structurally:
// generated SQL contains no quoted literal at all, so nothing from the query
// text can have been interpolated.
func TestConformance_EveryLiteralIsBound(t *testing.T) {
	for _, c := range loadCases(t) {
		for _, s := range []*CaseSQL{c.SQL, run(c).SQL} {
			if s == nil {
				continue
			}
			if strings.Contains(s.Where, "'") {
				t.Errorf("%s: SQL contains a quoted literal: %s", c.Name, s.Where)
			}
			if s.ArgCount == 0 && strings.Contains(s.Where, "$") {
				t.Errorf("%s: SQL has placeholders but no arguments", c.Name)
			}
		}
	}
}

// TestConformance_RoundTrip is §10's property: canonical text reparses to the
// same tree, and formatting is idempotent.
func TestConformance_RoundTrip(t *testing.T) {
	for _, c := range loadCases(t) {
		if c.Canonical == "" {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			first, err := parser.Parse(c.Query)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			again, err := parser.Parse(c.Canonical)
			if err != nil {
				t.Fatalf("reparse canonical %q: %v", c.Canonical, err)
			}
			if !ast.EqualJSON(first.Root, again.Root) {
				t.Errorf("canonical form reparses to a different tree\n  %s\n  %s",
					mustJSON(first.Root), mustJSON(again.Root))
			}
			if twice := format.Format(again.Root); twice != c.Canonical {
				t.Errorf("format is not idempotent:\n  once  %q\n  twice %q", c.Canonical, twice)
			}
		})
	}
}

func mustJSON(n ast.Node) string {
	b, err := ast.MarshalJSON(n)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func equalJSON(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &y); err != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func writeFixtures(t *testing.T, cases []Case) {
	t.Helper()
	var b strings.Builder
	b.WriteString("[\n")
	for i, c := range cases {
		enc, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("encode %s: %v", c.Name, err)
		}
		b.WriteString("  ")
		b.Write(indentCase(enc))
		if i < len(cases)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("]\n")
	if err := os.WriteFile(filepath.Clean(fixturePath), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write fixtures: %v", err)
	}
}

// indentCase re-indents one case object over several lines, so the file stays
// reviewable by a human — which is the only way its contents can be trusted.
func indentCase(enc []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(enc, &obj); err != nil {
		return enc
	}
	order := []string{"name", "query", "target", "twin", "note", "options", "canonical", "ast", "errors", "sql", "sql_errors"}
	var b strings.Builder
	b.WriteString("{\n")
	first := true
	for _, key := range order {
		v, ok := obj[key]
		if !ok {
			continue
		}
		if !first {
			b.WriteString(",\n")
		}
		first = false
		b.WriteString("    ")
		kb, _ := json.Marshal(key)
		b.Write(kb)
		b.WriteString(": ")
		b.Write(v)
	}
	b.WriteString("\n  }")
	return []byte(b.String())
}
