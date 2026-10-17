package postgres

// The grep-style half of row 1.4's retirement: `ip_address` identifiers are
// ip_addresses rows on interfaces, so the ONE writer of asset_identifiers in
// the Go tree is this package's attach, and attach skips the address kind.
// TestIntegration_Identity_NoIdentifierRowsOfKindIP_AfterIntake is the
// database half.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var identifierInsert = regexp.MustCompile(`(?i)INSERT\s+INTO\s+(public\.)?asset_identifiers\b`)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.work above the test's directory")
		}
		dir = parent
	}
}

// TestNoGoCodeInsertsAddressIdentifiers: no production Go file but
// repository.go inserts into asset_identifiers, and repository.go's attach
// files the address kind elsewhere before its INSERT.
//
// Mutation: add `INSERT INTO asset_identifiers` to any non-test Go file under
// services/ or shared/ (or delete the isAddressKind skip in attach) and this
// fails.
func TestNoGoCodeInsertsAddressIdentifiers(t *testing.T) {
	root := repoRoot(t)
	var writers []string
	for _, top := range []string{"services", "shared", "sensor", "device-agent", "tools"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); name == "node_modules" || name == "vendor" || name == "testdata" {
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
			if identifierInsert.Match(src) {
				rel, _ := filepath.Rel(root, path)
				writers = append(writers, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(writers) != 1 || writers[0] != "shared/identity/postgres/repository.go" {
		t.Fatalf("asset_identifiers writers = %v, want only shared/identity/postgres/repository.go — "+
			"an address is an ip_addresses row on an interface (DCIM row 1.4), and every other kind goes "+
			"through the repository", writers)
	}
	src, err := os.ReadFile(filepath.Join(root, "shared", "identity", "postgres", "repository.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (r *Repository) attach(")
	insert := identifierInsert.FindStringIndex(body)
	if start < 0 || insert == nil || insert[0] < start {
		t.Fatal("repository.go's INSERT is not inside attach any more; re-point this guard")
	}
	if !strings.Contains(body[start:insert[0]], "if isAddressKind(id.Kind) {\n\t\t\tcontinue\n\t\t}") {
		t.Fatal("attach no longer skips the address kind before inserting identifier rows")
	}
}
