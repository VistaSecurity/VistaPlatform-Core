// Package addrscopeguard keeps shared/network/addrscope the ONE definition of
// private address space ( F3).
//
// Four copies of "is this address private" drifted apart before addrscope
// existed. [Scan] parses every non-test Go file under shared/, services/,
// sensor/ and device-agent/ and reports, by file and line, each place that
// defines private address space itself instead of asking addrscope:
//
//   - a call to an `IsPrivate()` method (net.IP or netip.Addr) — the standard
//     library's half of every copy so far;
//   - a string literal holding an RFC 1918, RFC 4193 or RFC 6598 CIDR — the
//     other half, and the SQL and hand-written ladders.
//
// Comments are not code and are not scanned (the parser drops them), so
// documentation may name the ranges freely. Test files are exempt: they
// legitimately spell the ranges out to check behaviour.
//
// It is a syntax guard, not data-flow analysis: a range assembled from parts or
// an `IsPrivate` reached through a method value escapes it. It exists to stop
// the ordinary copy, which is how all four arrived.
//
// It lives apart from addrscope so the standalone sensor, which imports
// addrscope through shared/probeconsent, does not link go/parser. `make audit`
// runs it through cmd/addrscope-guard: a `go test` that reads files outside its
// module is served from the test cache after those files change, so a test
// alone would be a check that cannot fail.
package addrscopeguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// GuardedLiterals are the CIDRs only addrscope may spell.
var GuardedLiterals = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"100.64.0.0/10",
}

// ScanRoots are the trees that hold product Go code, relative to the repo root.
var ScanRoots = []string{"shared", "services", "sensor", "device-agent"}

// requiredRoots must exist and hold Go code; device-agent is optional so a
// partial checkout still scans.
var requiredRoots = []string{"shared", "services", "sensor"}

// minFilesPerRoot is the floor below which a scan is reporting on nothing.
const minFilesPerRoot = 20

// OwnPackage is the one directory allowed to define the ranges.
var OwnPackage = filepath.Join("shared", "network", "addrscope")

// FindDefinitions reports every private-address definition in one Go source.
func FindDefinitions(fset *token.FileSet, name string, src []byte) ([]string, error) {
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "IsPrivate" && len(x.Args) == 0 {
				found = append(found, fmt.Sprintf("%s: call to IsPrivate() — use addrscope.Classify / IsTenantAddressable / MayAutoProbe",
					fset.Position(x.Pos())))
			}
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(x.Value)
			if err != nil {
				s = x.Value
			}
			for _, lit := range GuardedLiterals {
				if strings.Contains(s, lit) {
					found = append(found, fmt.Sprintf("%s: literal %q — use addrscope.PrivateRanges / CGNATRange",
						fset.Position(x.Pos()), lit))
				}
			}
		}
		return true
	})
	return found, nil
}

// Scan walks the repository at root and returns every violation, sorted. An
// error means the scan itself could not be trusted — a missing root, a file
// that does not parse, or too few files to be looking at the real tree.
func Scan(root string) ([]string, error) {
	fset := token.NewFileSet()
	var violations []string
	scanned := map[string]int{}
	for _, dir := range ScanRoots {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			if contains(requiredRoots, dir) {
				return nil, fmt.Errorf("scan root %s missing: %w", base, err)
			}
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "vendor", "testdata", ".git":
					return filepath.SkipDir
				}
				if rel == OwnPackage {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			found, err := FindDefinitions(fset, rel, src)
			if err != nil {
				return fmt.Errorf("parse %s: %w", rel, err)
			}
			scanned[dir]++
			violations = append(violations, found...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, dir := range requiredRoots {
		if scanned[dir] < minFilesPerRoot {
			return nil, fmt.Errorf("scanned only %d Go files under %s/ — the guard is not looking where it should", scanned[dir], dir)
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
