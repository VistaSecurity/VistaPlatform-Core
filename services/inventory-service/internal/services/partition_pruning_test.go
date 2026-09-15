package services

// A join to `assets` must carry `tenant_id` in its ON clause.
//
// `assets` is LIST-partitioned by tenant, and a join whose ON clause matches
// only on `id` gives the planner nothing to prune with: it scans all eight
// partitions to find one row, on a table that grows with every tenant on the
// installation. The predicate is also the belt half of the platform's
// belt-and-braces tenancy rule — RLS is the backstop, not the control.
//
// Ten joins in five files were missing it. It reads as a working query, returns
// the right rows, and costs eight times what it should; nothing about the
// result says so, which is why this is a scanner rather than a review note.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A join to assets, capturing the ON clause up to the end of the line.
var assetsJoin = regexp.MustCompile(`(?i)\bjoin\s+assets\s+(\w+)\s+ON\s+([^\n]*)`)

func TestEveryJoinToAssetsPrunesByTenant(t *testing.T) {
	root := repoRootFromService(t)
	var offenders []string
	scanned := 0

	base := filepath.Join(root, "services")
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		for _, m := range assetsJoin.FindAllStringSubmatch(string(body), -1) {
			alias, on := m[1], m[2]
			if strings.Contains(on, alias+".tenant_id") {
				continue
			}
			offenders = append(offenders, rel+"  JOIN assets "+alias+" ON "+strings.TrimSpace(on))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if scanned == 0 {
		t.Fatal("scanned no Go files; the walker has stopped walking, which is the one way this " +
			"guard passes over nothing")
	}
	for _, o := range offenders {
		t.Errorf("a join to `assets` does not prune by tenant:\n  %s\n"+
			"`assets` is LIST-partitioned by tenant_id. Without it in the ON clause the planner "+
			"scans every partition to find one row — and the query still returns the right answer, "+
			"which is why nothing else catches this. Add `<alias>.tenant_id = <other>.tenant_id`.", o)
	}
}

// repoRootFromService walks up to the repository root.
func repoRootFromService(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("go.work not found above the working directory; not a full checkout")
	return ""
}
