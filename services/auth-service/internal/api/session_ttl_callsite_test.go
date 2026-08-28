package api

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

// The cookie helpers take the refresh lifetime as a parameter, so a test that
// calls them directly proves only that they honour whatever they are handed.
// The bug they were written for was the opposite shape: the helpers were fine
// and the CALL SITES passed a hardcoded 7 days, so Security -> Policy could
// save a longer session timeout while browser sessions still expired early.
//
// Every existing test in csrf_cookie_test.go invokes the helper directly, which
// means reintroducing the regression at a call site leaves the whole
// auth-service suite green — verified by hand: replacing
// `int(authResponse.RefreshExpiresIn)` at handlers.go's Login call with
// `int((7*24*time.Hour).Seconds())` passes every other test in this module.
//
// This test reads the source instead. For each call to a cookie helper it takes
// the refresh-lifetime argument (index 3 in all three helpers) and demands it be
// derived from the resolved policy rather than written as a constant.
//
// Note index 2 of setPlatformAuthCookies is a literal 3600 on purpose — that is
// the ACCESS token max-age, which is not policy-controlled. Only index 3 is
// checked, so tightening this test must not be done by banning literals
// wholesale.
const refreshLifetimeArgIndex = 3

// Substrings that mark an expression as policy-derived. `sessionLifetime` covers
// a direct authpolicy.SessionLifetime(...) call at the site; `sessionTTL` the
// hoisted local; `RefreshExpiresIn` the value the auth service computed from the
// same policy and put on the response.
var policyDerivedMarkers = []string{"sessionTTL", "SessionLifetime", "RefreshExpiresIn"}

// cookieHelpers is the set whose refresh-lifetime argument is policy-controlled.
var cookieHelpers = map[string]bool{
	"setAuthCookies":               true,
	"setAuthCookiesResponseWriter": true,
}

func TestRefreshCookieLifetimeIsPolicyDerivedAtEveryCallSite(t *testing.T) {
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
			name := calleeName(call.Fun)
			if !cookieHelpers[name] {
				return true
			}
			if len(call.Args) <= refreshLifetimeArgIndex {
				t.Errorf("%s: %s called with %d args; expected the refresh lifetime at index %d — if the signature moved, fix this guard rather than deleting it",
					fset.Position(call.Pos()), name, len(call.Args), refreshLifetimeArgIndex)
				return true
			}

			arg := call.Args[refreshLifetimeArgIndex]
			src := exprText(fset, arg)
			checked++

			for _, marker := range policyDerivedMarkers {
				if strings.Contains(src, marker) {
					return true
				}
			}
			t.Errorf("%s: %s receives refresh lifetime %q, which is not derived from the resolved session policy.\n"+
				"A constant here silently caps the session at that value no matter what Security -> Policy is set to.\n"+
				"Pass the policy value (sessionTTL / authpolicy.SessionLifetime(...) / authResponse.RefreshExpiresIn).",
				fset.Position(arg.Pos()), name, src)
			return true
		})
	}

	// An AST walk that matches nothing passes vacuously. There are call sites in
	// this package; if there are suddenly none, the guard has stopped guarding.
	if checked == 0 {
		t.Fatal("no cookie-helper call sites found in this package — the guard matched nothing and would pass no matter what the code did")
	}
	t.Logf("checked %d refresh-lifetime argument(s)", checked)
}

// exprText renders an expression back to source so the failure message quotes
// what was actually written at the call site.
func exprText(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
