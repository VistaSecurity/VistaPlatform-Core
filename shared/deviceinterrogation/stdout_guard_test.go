package deviceinterrogation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Nothing in this package may report on stdout or stderr.
//
// Every collector used to report its sub-failures with `fmt.Printf("Warning:
// …")`, which reaches the log of whichever process ran it and nothing an
// operator can see (P-17). They are collection warnings on the result now, and
// this keeps the next one from going back to stdout.
//
// The scan is over the parsed AST, not the text: a comment that mentions
// `fmt.Printf` must neither trip it nor satisfy it, and a string literal that
// happens to contain the words is not a call. Package names are resolved from
// each file's own imports, so an aliased import (`f "fmt"`, `stdlog "log"`,
// `o "os"`) is caught under its alias. What is flagged:
//
//   - fmt.Print, fmt.Printf, fmt.Println
//   - log.Print*, log.Fatal*, log.Panic*, and log.Default / log.Writer /
//     log.Output / log.SetOutput (the std logger writes to stderr, and
//     log.Default().Printf is the same write reached one call later)
//   - any use of log/slog — its default handler writes to stderr
//   - any reference to os.Stdout or os.Stderr (which also covers
//     fmt.Fprint*(os.Stdout, …) and log.New(os.Stderr, …))
//   - the builtins print and println
//   - a dot-import of fmt, log, log/slog or os, which would hide all of the
//     above behind bare identifiers
//
// Subpackages are included: devicetest and internal/dialguard ship in the same
// binaries.
func TestCollectors_NeverWriteWarningsToStdout(t *testing.T) {
	scanned := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		scanned++
		for _, hit := range stdoutWrites(t, path, nil) {
			t.Errorf("%s writes to stdout/stderr (%s). Record a collection warning on the result instead (result.warn / warnAs / warnTruncated in warnings.go).", hit, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// A walk that finds nothing passes vacuously.
	if scanned < 20 {
		t.Fatalf("the scan read only %d source files; it has stopped testing what it claims to", scanned)
	}
}

// The detector itself, in both polarities, so the guard above cannot go inert
// without this going red.
func TestStdoutWrites_DetectorPolarity(t *testing.T) {
	std := `"fmt"; "log"; "log/slog"; "os"; "strings"`
	flagged := []struct{ name, imports, stmt string }{
		{"printf", std, `fmt.Printf("Warning: failed to get VLANs: %v\n", err)`},
		{"println", std, `fmt.Println("warning")`},
		{"fprintf stdout", std, `fmt.Fprintf(os.Stdout, "warning")`},
		{"fprintln stderr", std, `fmt.Fprintln(os.Stderr, "warning")`},
		{"log", std, `log.Printf("warning %v", err)`},
		{"log fatal", std, `log.Fatalf("warning %v", err)`},
		{"log.Default chain", std, `log.Default().Printf("warning %v", err)`},
		{"log.New to stderr", std, `_ = log.New(os.Stderr, "", 0)`},
		{"slog", std, `slog.Warn("warning", "err", err)`},
		{"slog default logger", std, `slog.Default().Info("warning")`},
		{"builtin print", std, `print("warning")`},
		{"builtin println", std, `println("warning")`},
		{"stdout ref", std, `w := os.Stdout; _ = w`},
		{"aliased fmt", `f "fmt"; "log"; "log/slog"; "os"; "strings"`, `f.Printf("warning %v", err)`},
		{"aliased log", `"fmt"; stdlog "log"; "log/slog"; "os"; "strings"`, `stdlog.Println("warning")`},
		{"aliased os", `"fmt"; "log"; "log/slog"; o "os"; "strings"`, `fmt.Fprintln(o.Stderr, "warning")`},
		{"aliased slog", `"fmt"; "log"; sl "log/slog"; "os"; "strings"`, `sl.Error("warning")`},
		{"dot-imported fmt", `. "fmt"; "log"; "log/slog"; "os"; "strings"`, `Println("warning")`},
	}
	for _, c := range flagged {
		if hits := stdoutWrites(t, "", []byte(detectorSource(c.imports, c.stmt))); len(hits) == 0 {
			t.Errorf("%s: the detector missed %q", c.name, c.stmt)
		}
	}

	clean := []struct{ name, imports, stmt string }{
		// A comment is prose, not a call — in either direction.
		{"comment", std, `// fmt.Printf("Warning: this used to go to stdout")` + "\n_ = err"},
		{"block comment", std, `/* fmt.Println("x") */ _ = err`},
		{"string", std, `_ = "fmt.Printf(\"Warning\")"`},
		{"sprintf", std, `_ = fmt.Sprintf("warning %v", err)`},
		{"errorf", std, `_ = fmt.Errorf("warning %w", err)`},
		{"fprintf buf", std, `var b strings.Builder; fmt.Fprintf(&b, "x"); _ = err`},
		{"os.Exit is not a write", std, `if err == nil { os.Exit(0) }`},
		// A local value that happens to be CALLED log is not the package when
		// the file does not import it: names are resolved from the imports,
		// not matched as text.
		{"shadowing local named log", `"fmt"; "os"; "strings"`, `log := struct{ Printf func(string, ...any) }{}; _ = log`},
		{"method named Printf on a local", std, `var w struct{ Printf func(string, ...any) }; _ = w`},
	}
	for _, c := range clean {
		if hits := stdoutWrites(t, "", []byte(detectorSource(c.imports, c.stmt))); len(hits) != 0 {
			t.Errorf("%s: the detector flagged %q: %v", c.name, c.stmt, hits)
		}
	}
}

// detectorSource builds a compilable-shaped file with the given imports
// (`;`-separated import specs) around one statement. Blank uses keep every
// import referenced, so the file reads like real code.
func detectorSource(imports, stmt string) string {
	var b strings.Builder
	b.WriteString("package p\n\nimport (\n")
	for _, spec := range strings.Split(imports, ";") {
		b.WriteString("\t" + strings.TrimSpace(spec) + "\n")
	}
	b.WriteString(")\n\nfunc probe(err error) {\n\t" + stmt + "\n}\n")
	return b.String()
}

// Packages whose use in this package is a write to stdout or stderr.
const (
	pkgFmt  = "fmt"
	pkgLog  = "log"
	pkgSlog = "log/slog"
	pkgOS   = "os"
)

// stdoutWrites parses a Go source file (or src, when non-nil) and returns a
// description of every write to stdout or stderr in it.
func stdoutWrites(t *testing.T, path string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	var file *ast.File
	var err error
	if src != nil {
		file, err = parser.ParseFile(fset, "detector.go", src, 0)
	} else {
		file, err = parser.ParseFile(fset, path, nil, 0)
	}
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var hits []string
	at := func(n ast.Node, what string) { hits = append(hits, fset.Position(n.Pos()).String()+" "+what) }

	// Local name -> import path, from this file's own imports.
	pkgOf := map[string]string{}
	for _, spec := range file.Imports {
		importPath, _ := strconv.Unquote(spec.Path.Value)
		local := importPath[strings.LastIndex(importPath, "/")+1:]
		if spec.Name != nil {
			local = spec.Name.Name
		}
		switch importPath {
		case pkgFmt, pkgLog, pkgSlog, pkgOS:
			if local == "." {
				at(spec, "dot-import of "+importPath)
				continue
			}
			pkgOf[local] = importPath
		}
	}
	// pkgSel reports the import path and selected name of `pkg.Name`, when
	// pkg is the local name of one of the watched imports.
	pkgSel := func(e ast.Expr) (string, string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", "", false
		}
		importPath, ok := pkgOf[ident.Name]
		return importPath, sel.Sel.Name, ok
	}
	hasPrefix := func(name string, prefixes ...string) bool {
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if importPath, name, ok := pkgSel(node.Fun); ok {
				switch {
				case importPath == pkgFmt && hasPrefix(name, "Print"):
					at(node, "fmt."+name)
				case importPath == pkgLog && (hasPrefix(name, "Print", "Fatal", "Panic") ||
					name == "Default" || name == "Writer" || name == "Output" || name == "SetOutput"):
					at(node, "log."+name)
				}
			}
			if ident, ok := node.Fun.(*ast.Ident); ok && (ident.Name == "print" || ident.Name == "println") {
				at(node, "builtin "+ident.Name)
			}
		case *ast.SelectorExpr:
			if importPath, name, ok := pkgSel(node); ok {
				switch {
				case importPath == pkgSlog:
					at(node, "log/slog."+name)
				case importPath == pkgOS && (name == "Stdout" || name == "Stderr"):
					at(node, "os."+name)
				}
			}
		}
		return true
	})
	return hits
}
