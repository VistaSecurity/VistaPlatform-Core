package main

// The identification-path WRITE gates (workstream 4.6).
//
// Three routes let a tenant user change how the platform decides identity, and
// one of them — PUT /settings/identification — grants the platform permission
// to merge two of their assets without asking. All three are gated in main.go
// with `RequireTenantPermission(rawDB, rbac.PermissionAssetsUpdate)`, and
// nothing failed if that argument were deleted: the route still compiles, the
// handler contract tests build their own router and never see main.go's
// middleware, and `make audit`'s permission parity only asks whether
// `assets.update` is enforced SOMEWHERE in the service — which it is, by the
// neighbours.
//
// That is the shape CLAUDE.md's "test the WIRING, not just the helper" names:
// a correct gate whose call site nothing pins. was the same bug in
// auth-service, where a one-line `tenantSecurity.Use(...)` was what stopped a
// tenant reading another tenant's data and only an isolated middleware test
// existed. So this reads main.go, like admin_plane_test.go above it, and
// asserts the argument is present on the write and absent from the read.
//
// Both polarities, because a test that only demanded gates would pass a
// main.go that gated every route including the reads — which is not the
// arrangement either: reading the threshold is an ordinary inventory read, and
// gating it behind a WRITE permission would hide the setting from the people
// who most need to see what it is set to.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A tenant RBAC gate, in the spellings shared/middleware/rbac offers.
var tenantGate = regexp.MustCompile(`RequireTenantPermission|RequireAnyTenantPermission`)

// The identification-path writes, and the permission each must carry.
//
// `assets.update` for the threshold: what it governs is whether the platform
// may rewrite the tenant's ASSETS on its own, and it is the same permission as
// accepting a merge proposal by hand — which is the act it automates. A
// reviewer who may merge two assets may decide that a high enough score does it
// for them; one who may not, may not.
//
// Security review X.5 (X5-11) then observed that the threshold's endpoint asked
// for `assets.update` while the sibling card on the same Settings page asked
// for `settings.update`, so a role granted one and not the other could edit
// half a page with nothing on screen saying why. Both observations are right,
// and the resolution is AND, not a swap: the route now carries BOTH gates, in
// two chained middlewares. `settings.update` because it is a settings page;
// `assets.update` because the argument above is unchanged and dropping it would
// let `settings.update` alone authorise the platform to merge assets — a
// privilege widening dressed as a tidy-up.
//
// This test asserts the assets.update half; TestTenantSettingsRoutesShareOneWriteGate
// in internal/handlers asserts the settings.update half. Deleting either gate
// fails one of them.
var identityWrites = []struct {
	method, path, permission string
}{
	{"PUT", "/inventory-service/settings/identification", "PermissionAssetsUpdate"},
	{"POST", "/inventory-service/approvals/merge-proposals/:id/accept", "PermissionAssetsUpdate"},
	{"POST", "/inventory-service/approvals/merge-proposals/:id/keep-separate", "PermissionAssetsUpdate"},
}

// The identification-path reads, which must NOT be behind a write permission.
var identityReads = []string{
	"/inventory-service/settings/identification",
	"/inventory-service/approvals/merge-proposals",
	"/inventory-service/approvals/merge-proposals/auto-accepted",
}

func TestIdentityWritesCarryTheTenantPermission(t *testing.T) {
	routes := scanRoutesWithArgs(t)
	for _, want := range identityWrites {
		args, found := routes[want.method+" "+want.path]
		if !found {
			t.Errorf("%s %s is not registered in main.go at all", want.method, want.path)
			continue
		}
		if !tenantGate.MatchString(args) {
			t.Errorf("%s %s has no RequireTenantPermission: any authenticated tenant user can call it.\n%s",
				want.method, want.path, args)
			continue
		}
		if !strings.Contains(args, want.permission) {
			t.Errorf("%s %s is gated, but not on %s:\n%s", want.method, want.path, want.permission, args)
		}
	}
}

func TestIdentityReadsAreNotGatedOnAWritePermission(t *testing.T) {
	routes := scanRoutesWithArgs(t)
	for _, path := range identityReads {
		args, found := routes["GET "+path]
		if !found {
			t.Errorf("GET %s is not registered in main.go at all", path)
			continue
		}
		if strings.Contains(args, "PermissionAssetsUpdate") {
			t.Errorf("GET %s is gated on the WRITE permission; reading what the threshold is set to is an ordinary inventory read:\n%s",
				path, args)
		}
	}
}

// scanRoutesWithArgs is scanRoutes' sibling: "METHOD path" → the call's own
// argument list, gathered by parenthesis balance so a gated neighbour cannot
// make an ungated route look protected.
//
// Registrations that appear on both /api/v1 and /api/v2 are CONCATENATED rather
// than overwritten, and the concatenation is checked as one string, so gating
// only the v2 copy fails — which is the mistake the two loops in main.go
// invite.
func scanRoutesWithArgs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		m := routeReg.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[2] + " " + m[3]
		args := callArgs(lines, i)
		if prev, ok := out[key]; ok {
			// Both copies must satisfy the assertion, so a strings.Contains
			// over the pair is not enough on its own — an UNgated copy is
			// invisible in a concatenation that also holds a gated one. Check
			// each copy here and keep the weaker of the two.
			if tenantGate.MatchString(prev) && !tenantGate.MatchString(args) {
				out[key] = args
				continue
			}
			if !tenantGate.MatchString(prev) {
				continue
			}
		}
		out[key] = args
	}
	if len(out) == 0 {
		t.Fatal("no routes found in main.go; the scan is broken, not main.go")
	}
	return out
}
