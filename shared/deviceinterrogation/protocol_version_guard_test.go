package deviceinterrogation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Guard for "unknown stays unknown" ( W1.2).
//
// A protocol-version string literal ("TLS 1.2", "SSH-2.0", "TLSv1.2",
// "DTLS 1.0", "SSL 3.0") may appear in collector code only as the ANSWER TO
// SOMETHING READ:
//
//   - in a non-default `case` of a switch — a mapping from a keyword, a wire
//     value or a parsed number the collector read (`case "tlsv1.2": return
//     "TLS 1.2"`); a `default:` clause is not a reading, it is a fallback;
//   - as a pattern being matched — inside an `if` condition, a switch tag, a
//     case list or a comparison (`strings.Contains(line, "TLSv1.3")`);
//   - appended inside the body (not the else) of an `if` whose condition calls
//     something other than len/cap — i.e. was conditioned on what was read;
//   - as one cell of a mapping table: a direct element of a composite literal
//     that also holds a non-version element (`{tls.VersionTLS13, "TLS 1.3"}`).
//
// Everything else — `strPtr("TLS 1.2")` in an else branch, `[]string{"TLS
// 1.2"}` after `if len(v) == 0`, `version := "SSH-2.0"` — is a fabricated
// default, and fails this test with the file and line.

var protocolVersionLiteral = regexp.MustCompile(`^(?i)((D?TLS|SSL) ?v?\d(\.\d+)?|TLSv\d(\.\d+)?|SSH-\d\.\d+)$`)

type versionLiteralFinding struct {
	pos     token.Position
	value   string
	allowed bool
}

// scanVersionLiterals reports every protocol-version literal in file and
// whether its use is the answer to something read.
func scanVersionLiterals(fset *token.FileSet, file *ast.File) []versionLiteralFinding {
	var out []versionLiteralFinding
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil && protocolVersionLiteral.MatchString(v) {
				out = append(out, versionLiteralFinding{
					pos:     fset.Position(lit.Pos()),
					value:   v,
					allowed: versionLiteralIsReading(lit, stack),
				})
			}
		}
		stack = append(stack, n)
		return true
	})
	return out
}

func versionLiteralIsReading(lit *ast.BasicLit, stack []ast.Node) bool {
	child := ast.Node(lit)
	for i := len(stack) - 1; i >= 0; i-- {
		parent := stack[i]
		switch p := parent.(type) {
		case *ast.CaseClause:
			if p.List == nil {
				return false // default: a fallback, not a reading
			}
			// A case of a TAGGED switch maps a value that was read. A case
			// of a tagless switch is an if-chain, held to the if rule.
			if sw, ok := enclosingSwitch(stack[:i]); ok && sw.Tag == nil {
				for _, e := range p.List {
					if e == child || conditionReadsSomething(e) {
						return true
					}
				}
				return false
			}
			return true // a case body or a case pattern
		case *ast.IfStmt:
			if child == p.Cond {
				return true // a pattern the condition matches against
			}
			if child == p.Body {
				return conditionReadsSomething(p.Cond)
			}
			return false // else branch, or init statement
		case *ast.SwitchStmt:
			if child == p.Tag {
				return true
			}
		case *ast.BinaryExpr:
			if p.Op == token.EQL || p.Op == token.NEQ {
				return true // compared against
			}
		case *ast.CompositeLit:
			if child == lit && compositeIsTableRow(p) {
				return true
			}
			if kv, ok := child.(*ast.KeyValueExpr); ok && (kv.Value == lit || kv.Key == lit) {
				if _, isMap := p.Type.(*ast.MapType); isMap {
					return true // a map literal's key or value: a lookup table
				}
			}
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		}
		child = parent
	}
	return false
}

// enclosingSwitch is the expression switch a case clause belongs to: the
// nearest SwitchStmt above it (a CaseClause's parent is the switch's body).
func enclosingSwitch(stack []ast.Node) (*ast.SwitchStmt, bool) {
	for i := len(stack) - 1; i >= 0; i-- {
		switch s := stack[i].(type) {
		case *ast.SwitchStmt:
			return s, true
		case *ast.TypeSwitchStmt:
			return nil, false
		}
	}
	return nil, false
}

// compositeIsTableRow: a composite literal with at least two elements, one of
// which is not itself a version literal — a mapping cell, not a list of
// defaults.
func compositeIsTableRow(c *ast.CompositeLit) bool {
	if len(c.Elts) < 2 {
		return false
	}
	for _, e := range c.Elts {
		bl, ok := e.(*ast.BasicLit)
		if !ok {
			return true
		}
		if v, err := strconv.Unquote(bl.Value); err != nil || !protocolVersionLiteral.MatchString(v) {
			return true
		}
	}
	return false
}

// conditionReadsSomething: the condition calls a function other than len/cap
// (strings.Contains, a regexp, a parser), so its body is conditioned on input
// rather than on the absence of it.
func conditionReadsSomething(cond ast.Expr) bool {
	reads := false
	ast.Inspect(cond, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "len" || id.Name == "cap") {
			return true
		}
		reads = true
		return false
	})
	return reads
}

func TestCollectors_AssignNoUnmeasuredProtocolVersion(t *testing.T) {
	fset := token.NewFileSet()
	seen := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "devicetest", "pipelinetest":
				return filepath.SkipDir // fixtures and fake appliances, not collectors
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, f := range scanVersionLiterals(fset, file) {
			seen++
			if !f.allowed {
				t.Errorf("%s: protocol version %q is assigned without a measurement — a collector reports a version only when it read one (#2014 W1.2)", f.pos, f.value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Not vacuous: the collectors map plenty of versions they read.
	if seen < 20 {
		t.Fatalf("scanned only %d version literals; the guard is not looking at the collectors", seen)
	}
}

// Both polarities of the guard, on source shaped like the regressions it
// exists for and like the readings it must leave alone.
func TestProtocolVersionGuard_Polarity(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		allowed bool
	}{
		{"else default", `if len(v) > 0 { a.P = strPtr(v[0]) } else { a.P = strPtr("TLS 1.2") }`, false},
		{"unconditional constant", `a.P = strPtr("SSH-2.0")`, false},
		{"constant via variable", `version := "SSH-2.0"; a.P = &version`, false},
		{"safe-default list", `if len(versions) == 0 { versions = []string{"TLS 1.2"} }`, false},
		{"default clause", `switch k { case "x": return "y"; default: return "TLS 1.2" }`, false},
		{"struct field", `a := CryptoAsset{ProtocolVersion: strPtr("TLS 1.2"), Port: 443}`, false},
		{"tagless case on absence", `switch { case p.Options == nil: a.P = strPtr("TLS 1.2") }`, false},
		{"tagless case on a reading", `switch { case strings.HasPrefix(s, "x"): a.P = strPtr("TLS 1.2") }`, true},
		{"switch mapping", `switch k { case "tlsv1.2": return "TLS 1.2" }`, true},
		{"pattern in condition", `if strings.Contains(line, "TLSv1.3") { x = 1 }`, true},
		{"append on a reading", `if strings.Contains(line, "TLSv1.3") { v = append(v, "TLS 1.3") }`, true},
		{"table row", `t := []struct{ id uint16; s string }{{tls.VersionTLS13, "TLS 1.3"}}`, true},
		{"map table", `m := map[string]string{"tlsv1.2": "TLS 1.2"}`, true},
		{"comparison", `ok := got == "TLS 1.0"`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "x.go", "package p\nfunc f() {\n"+c.src+"\n}\n", 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			findings := scanVersionLiterals(fset, file)
			if len(findings) == 0 {
				t.Fatal("no version literal found")
			}
			for _, f := range findings {
				if f.allowed != c.allowed {
					t.Errorf("%q at %s: allowed=%v, want %v", f.value, f.pos, f.allowed, c.allowed)
				}
			}
		})
	}
}
