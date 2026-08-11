package auth

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestSecurityAdminGrantFilterMatchesSeedSQL guards against drift between the
// security_admin permission filters in assignRolePermissions (this package's
// service.go) and the canonical "Ensure Tenant Roles for All Tenants" DO block
// in scripts/database/seed.sql. seed.sql is the source of truth; the Go side
// is a mirror that new tenants and every reconciliation run take. Drift means
// a post-upgrade reconciliation strips grants that seed.sql just added (the
// 'alerts' resource from commit 8ada815f was lost exactly this way).
//
// Pure source check — no database required.
func TestSecurityAdminGrantFilterMatchesSeedSQL(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	serviceGo := filepath.Join(filepath.Dir(thisFile), "service.go")
	seedSQL := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql")

	svcLists := extractSecurityAdminResourceLists(t, serviceGo)
	seedLists := extractSecurityAdminResourceLists(t, seedSQL)

	// Each file has exactly two security_admin filters: the DELETE (stale-grant
	// removal) and the INSERT (grant). Both must carry the same resource list.
	if len(svcLists) != 2 {
		t.Fatalf("service.go: expected 2 security_admin resource filters (DELETE + INSERT), found %d: %v", len(svcLists), svcLists)
	}
	if len(seedLists) != 2 {
		t.Fatalf("seed.sql: expected 2 security_admin resource filters (DELETE + INSERT), found %d: %v", len(seedLists), seedLists)
	}
	if svcLists[0] != svcLists[1] {
		t.Errorf("service.go: security_admin DELETE and INSERT resource lists differ: %q vs %q", svcLists[0], svcLists[1])
	}
	if seedLists[0] != seedLists[1] {
		t.Errorf("seed.sql: security_admin DELETE and INSERT resource lists differ: %q vs %q", seedLists[0], seedLists[1])
	}
	if svcLists[0] != seedLists[0] {
		t.Errorf("security_admin resource filter drift: service.go has %q, seed.sql (source of truth) has %q — update service.go's assignRolePermissions to match", svcLists[0], seedLists[0])
	}
	if !strings.Contains(svcLists[0], "alerts") {
		t.Errorf("service.go security_admin resource filter is missing 'alerts' (regression of the 8ada815f mirror drift): %q", svcLists[0])
	}
}

// extractSecurityAdminResourceLists returns every `tp.resource IN (...)` list
// that appears in a security_admin filter clause, normalized to a
// comma-joined list of bare resource names in source order.
func extractSecurityAdminResourceLists(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	re := regexp.MustCompile(`tp\.resource IN \(([^)]+)\)`)

	var lists []string
	for i, line := range lines {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// The role name appears on the same line or within the few lines
		// directly above the resource filter in both files.
		start := i - 4
		if start < 0 {
			start = 0
		}
		roleScoped := false
		for j := start; j <= i; j++ {
			if strings.Contains(lines[j], "'security_admin'") {
				roleScoped = true
				break
			}
		}
		if !roleScoped {
			continue
		}
		var names []string
		for _, part := range strings.Split(m[1], ",") {
			names = append(names, strings.Trim(strings.TrimSpace(part), "'"))
		}
		lists = append(lists, strings.Join(names, ","))
	}
	return lists
}
