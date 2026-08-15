package auth

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The grant filters used to be hand-maintained in five places in three
// languages. They drifted: commit 8ada815f dropped the 'alerts' resource from
// the Go mirror of security_admin, so a post-upgrade reconciliation stripped
// grants seed.sql had just added. The predecessor of this file guarded exactly
// one role (security_admin) against exactly that.
//
// Both sides are now generated from standards/permissions.yaml by
// scripts/generate-permissions.mjs, so drift requires a hand-edit of a
// generated artefact. These tests are the trap for that hand-edit, and they
// cover ALL FIVE roles rather than one:
//
//	TestGrantFiltersMatchSeedSQL   — every role's Go filter is character-for-
//	                                 character the SQL seed.sql runs
//	TestSecurityAdminRegressions   — the two specific losses that cost real
//	                                 time (the 'alerts' resource, audit.read)
//
// Pure source checks — no database required. `make audit` catches the same
// class earlier by re-running the generator with --check.

// TestGrantFiltersMatchSeedSQL compares roleGrantFilters (generated into
// role_grants_gen.go, used by assignRolePermissions on the new-tenant path)
// against the reconciliation DO block in scripts/database/seed.sql (the path
// existing tenants take on every helm upgrade). Any difference means the two
// cohorts get different access.
func TestGrantFiltersMatchSeedSQL(t *testing.T) {
	seedPath := filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql")
	seed := extractSeedGrantFilters(t, seedPath)

	if len(roleGrantFilters) == 0 {
		t.Fatal("roleGrantFilters is empty — role_grants_gen.go was not generated")
	}
	if len(seed) != len(roleGrantFilters) {
		t.Fatalf("seed.sql defines %d role filters, role_grants_gen.go defines %d: %v vs %v",
			len(seed), len(roleGrantFilters), keysOf(seed), rolesOf(roleGrantFilters))
	}

	for _, f := range roleGrantFilters {
		got, ok := seed[f.Role]
		if !ok {
			t.Errorf("role %q has a Go filter but no seed.sql filter", f.Role)
			continue
		}
		if got.revoke != normalizeSQL(f.Revoke) {
			t.Errorf("role %q revoke (DELETE) filter drift:\n  seed.sql: %s\n  Go:       %s\n"+
				"Both are generated from standards/permissions.yaml — one has been hand-edited. Run `make generate`.",
				f.Role, got.revoke, normalizeSQL(f.Revoke))
		}
		if got.grant != normalizeSQL(f.Grant) {
			t.Errorf("role %q grant (INSERT) filter drift:\n  seed.sql: %s\n  Go:       %s\n"+
				"Both are generated from standards/permissions.yaml — one has been hand-edited. Run `make generate`.",
				f.Role, got.grant, normalizeSQL(f.Grant))
		}
	}
}

// TestSecurityAdminRegressions pins the two security_admin details that were
// lost or nearly lost in real commits.
//
//   - 'alerts' in the resource allowlist: dropped by 8ada815f.
//   - 'audit.read' by NAME: the resource form would also hand over
// audit.manage, which the pre- audit-service role switch never gave
//     security_admin. The resource clause is an ALLOWLIST, so a newly seeded
//     resource reaches security_admin only if something names it — omitting
//     audit.read would have silently stripped the audit access it already had.
func TestSecurityAdminRegressions(t *testing.T) {
	var found bool
	for _, f := range roleGrantFilters {
		if f.Role != "security_admin" {
			continue
		}
		found = true
		for _, want := range []string{"'alerts'", "'audit.read'"} {
			if !strings.Contains(f.Grant, want) {
				t.Errorf("security_admin grant filter is missing %s — edit standards/permissions.yaml, not this file: %s", want, f.Grant)
			}
			if !strings.Contains(f.Revoke, want) {
				t.Errorf("security_admin revoke filter is missing %s (it would strip the grant on the next reconcile): %s", want, f.Revoke)
			}
		}
	}
	if !found {
		t.Fatal("no security_admin entry in roleGrantFilters")
	}
}

type seedFilter struct{ revoke, grant string }

var (
	// The role each statement targets.
	seedRoleRe = regexp.MustCompile(`tr\.name = '([a-z_]+)'`)
	// The predicate is everything after the last `AND tr.is_system_role = true`
	// on its own line, up to the statement terminator.
	seedPredRe = regexp.MustCompile(`(?s)AND tr\.is_system_role = true\n\s*AND (.*)`)
)

// extractSeedGrantFilters reads the generated reconciliation region of
// seed.sql and returns each role's DELETE and INSERT predicate, normalized.
func extractSeedGrantFilters(t *testing.T, path string) map[string]seedFilter {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(data)

	const beginMarker = "BEGIN GENERATED: system role grant filters"
	const endMarker = "END GENERATED: system role grant filters"
	begin := strings.Index(src, beginMarker)
	end := strings.Index(src, endMarker)
	if begin == -1 || end == -1 || end < begin {
		t.Fatalf("%s: generated grant-filter region markers not found", path)
	}
	region := src[begin:end]

	out := map[string]seedFilter{}
	for _, stmt := range strings.Split(region, ";") {
		// Drop comment lines so a `;` or a role name inside prose can't be
		// mistaken for SQL.
		var lines []string
		for _, l := range strings.Split(stmt, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				lines = append(lines, l)
			}
		}
		stmt = strings.Join(lines, "\n")

		isDelete := strings.Contains(stmt, "DELETE FROM tenant_role_permissions")
		isInsert := strings.Contains(stmt, "INSERT INTO tenant_role_permissions")
		if !isDelete && !isInsert {
			continue
		}
		rm := seedRoleRe.FindStringSubmatch(stmt)
		pm := seedPredRe.FindStringSubmatch(stmt)
		if rm == nil || pm == nil {
			t.Fatalf("%s: could not parse a grant statement:\n%s", path, stmt)
		}
		pred := normalizeSQL(strings.TrimSuffix(strings.TrimSpace(pm[1]), "ON CONFLICT (role_id, permission_id) DO NOTHING"))
		f := out[rm[1]]
		if isDelete {
			f.revoke = pred
		} else {
			f.grant = pred
		}
		out[rm[1]] = f
	}
	if len(out) == 0 {
		t.Fatalf("%s: no grant statements found in the generated region", path)
	}
	return out
}

// normalizeSQL collapses whitespace so line wrapping in seed.sql doesn't count
// as drift — only the predicate's content does.
func normalizeSQL(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func keysOf(m map[string]seedFilter) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func rolesOf(fs []roleGrantFilter) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Role)
	}
	return out
}
