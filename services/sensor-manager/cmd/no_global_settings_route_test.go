package main

import (
	"os"
	"regexp"
	"testing"
)

// PUT /admin/settings used to overwrite a process-global struct that every
// tenant's key creation and registration read, so any tenant holding
// settings.update could change the pending-key cap, key lifetime and address
// validation for all tenants. No client called it, so the route (and GET) were
// removed. Routes are registered inside main(), which a test cannot call, so
// this reads the source — the technique desired_config_routes_test.go uses —
// and fails if ANY registration under /admin/settings comes back, whatever
// middleware it carries.
//
// Mutation check: adding
//
//	sensorManager.PUT("/admin/settings", handler.Heartbeat)
//
// to main.go turns this red.
func TestNoTenantWritableGlobalSettingsRoute(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^[^/\n]*\.(GET|PUT|POST|PATCH|DELETE|Any|Handle)\(\s*(?:"[A-Z]+",\s*)?"[^"]*admin/settings[^"]*"`)
	if loc := re.FindString(string(src)); loc != "" {
		t.Errorf("a route under admin/settings is registered again: %q — sensor-manager's registration "+
			"limits are process-global, so a tenant-reachable write changes them for every tenant", loc)
	}
}
