package main

// The drift-settings WRITE gate (workstream 4.7).
//
// `PUT /inventory-service/settings/drift` decides how far back the platform
// looks before calling something a change. Narrow it and every fortnightly scan
// reads as drift; widen it and nothing does. It is gated in main.go with
// `RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate)` — and, until
// this file, nothing failed if that argument were deleted.
//
// That was checked rather than assumed: removing the middleware from BOTH
// registrations left `go test ./...` green across the whole service. The
// handler's own tests build their own router and never see main.go, and `make
// audit`'s permission parity only asks whether a permission is enforced
// SOMEWHERE in the service — which `settings.update` is, by a dozen
// neighbours. That is the shape CLAUDE.md names in "test the WIRING, not just
// the helper", and the shape shipped in auth-service.
//
// Both polarities: the write must carry the gate, and the READ must not.
// Reading the number the platform judges you against is an ordinary settings
// read, and putting it behind a write permission would hide the setting from
// the people who most need to see what it is set to.
//
// It scans EVERY registration of the route rather than going through
// scanRoutesWithArgs, which collapses the /api/v1 and /api/v2 copies into the
// weaker of the two. That collapse is right for a write (gating only one copy
// must fail) and wrong for a read (gating only one copy would be invisible),
// and this route needs both directions checked.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// driftSettingsPath is the route, registered on both /api/v1 and /api/v2.
const driftSettingsPath = "/inventory-service/settings/drift"

// registrationsOf returns the argument list of EVERY main.go registration of
// one method+path — one entry per api/apiv2 copy — so an assertion can be made
// about each independently.
//
// Fails closed: a path that matches nothing means the scan broke or the route
// was renamed, and either way the gate is no longer being checked.
func registrationsOf(t *testing.T, method, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	lines := strings.Split(string(raw), "\n")
	var out []string
	for i, line := range lines {
		m := routeReg.FindStringSubmatch(line)
		if m == nil || m[2] != method || m[3] != path {
			continue
		}
		out = append(out, callArgs(lines, i))
	}
	if len(out) == 0 {
		t.Fatalf("%s %s is not registered in main.go at all", method, path)
	}
	return out
}

func TestDriftSettingsWriteCarriesTheTenantPermission(t *testing.T) {
	for _, args := range registrationsOf(t, "PUT", driftSettingsPath) {
		if !tenantGate.MatchString(args) {
			t.Errorf("PUT %s has no RequireTenantPermission: any authenticated tenant user can widen or narrow "+
				"the window the whole estate is judged against.\n%s", driftSettingsPath, args)
			continue
		}
		if !strings.Contains(args, "PermissionSettingsUpdate") {
			t.Errorf("PUT %s is gated, but not on PermissionSettingsUpdate:\n%s", driftSettingsPath, args)
		}
	}
}

func TestDriftSettingsReadIsNotGatedOnAWritePermission(t *testing.T) {
	for _, args := range registrationsOf(t, "GET", driftSettingsPath) {
		if strings.Contains(args, "PermissionSettingsUpdate") {
			t.Errorf("GET %s is gated on the WRITE permission; reading the baseline window is an ordinary settings read:\n%s",
				driftSettingsPath, args)
		}
	}
}
