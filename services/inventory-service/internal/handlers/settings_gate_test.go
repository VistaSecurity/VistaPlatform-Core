package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The two tenant settings pages are one decision and must ask for one
// permission (security review X.5, X5-11).
//
// `PUT /settings/identification` was gated on `assets.update` and its sibling
// `PUT /settings/drift` — the next card on the same Settings page — on
// `settings.update`. Neither gate was wrong on its own, which is what made the
// pair a trap: a tenant admin role granted `settings.update` but not
// `assets.update` could edit the drift baseline and not the identification
// threshold, and nothing on the page would say why. Identification's own
// handler calls its setting "the only place in the product where a tenant
// grants the platform permission to merge two of their assets without asking",
// which is a settings decision by its own description.
//
// The resolution is AND, not a swap. Identification's gate was `assets.update`
// for a reason workstream 4.6 wrote down at its own test (cmd/identity_write_gate_test.go):
// the threshold authorises the platform to MERGE the tenant's assets without
// asking, which is the same act as accepting a merge proposal by hand. Swapping
// it for `settings.update` would let that permission alone authorise asset
// rewriting — a privilege widening dressed as a tidy-up. So the route carries
// both gates, chained: `settings.update` because it is a settings page,
// `assets.update` because the 4.6 argument is unchanged.
//
// This is a scan of cmd/main.go because that IS the wiring: the route table
// lives there, the handler contract tests stay green whichever gate main.go
// wraps a route in, and a gate is only real where the route is declared.
//
// To mutation-test: drop `settings.update` from either identification PUT and
// this fails; drop `assets.update` and cmd/identity_write_gate_test.go fails.
// Adding a permission gate to either GET fails here too — a read of your own
// tenant's settings is JWT/RLS-scoped like every other read, and gating it
// would hide the page from the people who can see the data it describes.
func TestTenantSettingsRoutesShareOneWriteGate(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	route := regexp.MustCompile(`(?m)^\s*(?:api|apiv2)\.(GET|PUT)\("([^"]+settings/(?:identification|drift))",\s*(.*(?:identificationSettingsHandler|driftSettingsHandler)\.(\w+)\).*)$`)
	matches := route.FindAllStringSubmatch(string(src), -1)
	// Two settings, read and write, on each of v1 and v2.
	if len(matches) != 8 {
		t.Fatalf("expected 8 tenant settings routes, found %d: %v", len(matches), matches)
	}

	counts := map[string]int{}
	for _, m := range matches {
		method, path, args, handler := m[1], m[2], m[3], m[4]
		line := strings.TrimSpace(m[0])
		counts[method+" "+handler]++

		switch method {
		case "GET":
			if strings.Contains(args, "RequireTenantPermission") {
				t.Errorf("GET %s carries a tenant-permission gate; settings reads are JWT/RLS-scoped: %s", path, line)
			}
		case "PUT":
			if !strings.Contains(args, "RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate)") {
				t.Errorf("PUT %s does not require settings.update — the two settings on one page must ask "+
					"for one permission, or a role can edit half a page: %s", path, line)
			}
		}
	}

	for _, want := range []string{
		"GET GetIdentificationSettings", "PUT UpdateIdentificationSettings",
		"GET GetDriftSettings", "PUT UpdateDriftSettings",
	} {
		if counts[want] != 2 {
			t.Errorf("%s registered %d times, want 2 (v1 and v2)", want, counts[want])
		}
	}
}
