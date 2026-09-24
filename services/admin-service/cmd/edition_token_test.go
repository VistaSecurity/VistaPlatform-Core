package main

import (
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/api"
)

// The start-up edition step on a Core build must say, out loud, that a
// configured licence is being ignored — and must say nothing on the ordinary
// Core install (the chart mounts the Secret path whether or not it exists).

type editionEnv struct {
	env   map[string]string
	files map[string]string
}

func (e editionEnv) getenv(k string) string { return e.env[k] }
func (e editionEnv) readFile(p string) ([]byte, error) {
	if v, ok := e.files[p]; ok {
		return []byte(v), nil
	}
	return nil, os.ErrNotExist
}

func TestApplyEdition_CoreBuildWarnsAboutAnUnreadableTokenFile(t *testing.T) {
	e := editionEnv{env: map[string]string{"LICENSE_TOKEN_FILE": mountedPath}}
	var lines []string
	applyEdition(api.EditionHooks{}, nil, e.getenv, func(string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}, func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) })
	if len(lines) != 1 || !strings.Contains(lines[0], "unreadable") || !strings.Contains(lines[0], mountedPath) {
		t.Fatalf("want one warning naming the unreadable token file, got %q", lines)
	}
}

func runApplyEdition(t *testing.T, h api.EditionHooks, e editionEnv) []string {
	t.Helper()
	var lines []string
	applyEdition(h, nil, e.getenv, e.readFile, func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) })
	return lines
}

const mountedPath = "/etc/vistaplatform/license/token"

func TestApplyEdition_CoreBuildWarnsAboutAMountedLicence(t *testing.T) {
	lines := runApplyEdition(t, api.EditionHooks{}, editionEnv{
		env:   map[string]string{"LICENSE_TOKEN_FILE": mountedPath},
		files: map[string]string{mountedPath: "eyJhbGciOi.payload.sig\n"},
	})
	if len(lines) != 1 {
		t.Fatalf("want exactly one warning, got %q", lines)
	}
	for _, want := range []string{"[edition] WARNING", "Core build", "ignored", "Enterprise images", mountedPath, "Upgrading from Core"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("warning %q lacks %q", lines[0], want)
		}
	}
}

func TestApplyEdition_CoreBuildWarnsAboutAnEnvLicence(t *testing.T) {
	for _, name := range []string{"EDITION_TOKEN", "LICENSE_TOKEN"} {
		lines := runApplyEdition(t, api.EditionHooks{}, editionEnv{env: map[string]string{name: "eyJ.x.y"}})
		if len(lines) != 1 || !strings.Contains(lines[0], name) {
			t.Errorf("%s: want one warning naming it, got %q", name, lines)
		}
	}
}

func TestApplyEdition_CoreBuildSilentWithoutALicence(t *testing.T) {
	cases := map[string]editionEnv{
		"nothing configured":         {},
		"path set, Secret absent":    {env: map[string]string{"LICENSE_TOKEN_FILE": mountedPath}},
		"env var set to whitespace":  {env: map[string]string{"EDITION_TOKEN": "  "}},
		"new-name path, file absent": {env: map[string]string{"EDITION_TOKEN_FILE": mountedPath}},
	}
	for name, e := range cases {
		if lines := runApplyEdition(t, api.EditionHooks{}, e); len(lines) != 0 {
			t.Errorf("%s: want silence, got %q", name, lines)
		}
	}
}

func TestApplyEdition_CoreBuildWarnsAboutAnEmptyTokenFile(t *testing.T) {
	lines := runApplyEdition(t, api.EditionHooks{}, editionEnv{
		env:   map[string]string{"LICENSE_TOKEN_FILE": mountedPath},
		files: map[string]string{mountedPath: " \n\t"},
	})
	if len(lines) != 1 || !strings.Contains(lines[0], "empty") || !strings.Contains(lines[0], mountedPath) {
		t.Fatalf("want one warning naming the empty token file, got %q", lines)
	}
}

// An Enterprise build hands the token to its verifier and adds nothing: the
// verifier logs its own outcome.
func TestApplyEdition_EnterpriseBuildRunsTheHookOnly(t *testing.T) {
	called := 0
	h := api.EditionHooks{ApplyEditionToken: func(*sql.DB) { called++ }}
	lines := runApplyEdition(t, h, editionEnv{
		env:   map[string]string{"LICENSE_TOKEN_FILE": mountedPath},
		files: map[string]string{mountedPath: "eyJ.x.y"},
	})
	if called != 1 {
		t.Fatalf("ApplyEditionToken called %d times, want 1", called)
	}
	if len(lines) != 0 {
		t.Fatalf("an Enterprise build must not log the Core warning, got %q", lines)
	}
}

// Both file variables are read, not just the one the chart sets: an operator
// who sets EDITION_TOKEN_FILE (the name the Enterprise verifier prefers) is
// warned too.
func TestApplyEdition_CoreBuildWarnsAboutTheNewNameTokenFile(t *testing.T) {
	lines := runApplyEdition(t, api.EditionHooks{}, editionEnv{
		env:   map[string]string{"EDITION_TOKEN_FILE": mountedPath},
		files: map[string]string{mountedPath: "eyJ.x.y"},
	})
	if len(lines) != 1 || !strings.Contains(lines[0], "EDITION_TOKEN_FILE") || !strings.Contains(lines[0], mountedPath) {
		t.Fatalf("want one warning naming EDITION_TOKEN_FILE and its path, got %q", lines)
	}
}

// Same precedence as the Enterprise readToken: a token file wins over a
// token env var, so the warning names the file.
func TestApplyEdition_CoreBuildNamesTheFileBeforeTheEnvVar(t *testing.T) {
	lines := runApplyEdition(t, api.EditionHooks{}, editionEnv{
		env:   map[string]string{"LICENSE_TOKEN_FILE": mountedPath, "EDITION_TOKEN": "eyJ.x.y"},
		files: map[string]string{mountedPath: "eyJ.x.y"},
	})
	if len(lines) != 1 || !strings.Contains(lines[0], "LICENSE_TOKEN_FILE") {
		t.Fatalf("want the warning to name the file source, got %q", lines)
	}
}

// main must actually run the edition step, with the bypass pool, before it
// builds the server. applyEdition is unit-tested above, but nothing else
// would notice if main stopped calling it: an Enterprise build would then
// never verify or record its licence, and every tenant would silently stay
// Core. main() needs live databases, so the call is pinned from the source.
func TestMain_RunsApplyEditionWithTheBypassPoolBeforeServing(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	var mainFn *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" {
			mainFn = fn
		}
	}
	if mainFn == nil {
		t.Fatal("main.go has no func main")
	}
	applyPos, serverPos := token.NoPos, token.NoPos
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name != "applyEdition" || applyPos != token.NoPos {
				return true
			}
			applyPos = call.Pos()
			if len(call.Args) != 5 {
				t.Errorf("applyEdition called with %d args, want 5", len(call.Args))
				return true
			}
			for i, want := range []string{"hooks", "bypassDB"} {
				if id, ok := call.Args[i].(*ast.Ident); !ok || id.Name != want {
					t.Errorf("applyEdition arg %d is not %s", i, want)
				}
			}
		case *ast.SelectorExpr:
			if fun.Sel.Name == "NewServerWithConnections" && serverPos == token.NoPos {
				serverPos = call.Pos()
			}
		}
		return true
	})
	if applyPos == token.NoPos {
		t.Fatal("main does not call applyEdition: an Enterprise build would never apply its licence")
	}
	if serverPos == token.NoPos {
		t.Fatal("main does not call api.NewServerWithConnections (did the start-up change shape?)")
	}
	if applyPos > serverPos {
		t.Error("main calls applyEdition after building the server; the licence must be recorded before serving")
	}
}
