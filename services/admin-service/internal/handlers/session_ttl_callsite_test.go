package handlers

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setPlatformAuthCookies takes the refresh lifetime as a parameter, so
// auth_cookie_test.go — which calls it directly — proves only that it honours
// whatever it is handed. The regression it was written for is the other shape:
// the helper was fine and the CALL SITES passed a hardcoded 7 days, so
// Security -> Policy could save a longer platform session timeout while admin
// sessions still expired early.
//
// This test reads the source instead, and demands the refresh-lifetime argument
// at every call site be derived from the resolved policy rather than written as
// a constant.
//
// Index 2 is a literal 3600 at every site on purpose — that is the ACCESS token
// max-age, which is not policy-controlled. Only index 3 is checked, so this
// guard must not be "tightened" into banning literal arguments wholesale.
const platformRefreshLifetimeArgIndex = 3

// Substrings marking an expression as policy-derived: the hoisted local, or a
// direct authpolicy.SessionLifetime(...) call at the site.
var platformPolicyDerivedMarkers = []string{"sessionTTL", "SessionLifetime"}

func TestPlatformRefreshCookieLifetimeIsPolicyDerivedAtEveryCallSite(t *testing.T) {
	fset := token.NewFileSet()
	// parser.ParseDir is deprecated (SA1019); walk the directory instead. Only
	// non-test .go files matter — the call sites live in production source.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test .go files found — the guard would pass vacuously")
	}

	checked := 0
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if platformCalleeName(call.Fun) != "setPlatformAuthCookies" {
				return true
			}
			if len(call.Args) <= platformRefreshLifetimeArgIndex {
				t.Errorf("%s: setPlatformAuthCookies called with %d args; expected the refresh lifetime at index %d — if the signature moved, fix this guard rather than deleting it",
					fset.Position(call.Pos()), len(call.Args), platformRefreshLifetimeArgIndex)
				return true
			}

			arg := call.Args[platformRefreshLifetimeArgIndex]
			src := platformExprText(fset, arg)
			checked++

			for _, marker := range platformPolicyDerivedMarkers {
				if strings.Contains(src, marker) {
					return true
				}
			}
			t.Errorf("%s: setPlatformAuthCookies receives refresh lifetime %q, which is not derived from the resolved session policy.\n"+
				"A constant here silently caps the platform session at that value no matter what Security -> Policy is set to.\n"+
				"Pass the policy value (sessionTTL / authpolicy.SessionLifetime(...)).",
				fset.Position(arg.Pos()), src)
			return true
		})
	}

	// An AST walk that matches nothing passes vacuously.
	if checked == 0 {
		t.Fatal("no setPlatformAuthCookies call sites found in this package — the guard matched nothing and would pass no matter what the code did")
	}
	t.Logf("checked %d refresh-lifetime argument(s)", checked)
}

// platformExprText renders an expression back to source so the failure message
// quotes what was actually written at the call site.
func platformExprText(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

func platformCalleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
