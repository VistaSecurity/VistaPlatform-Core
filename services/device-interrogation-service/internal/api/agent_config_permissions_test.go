package api

import (
	"os"
	"regexp"
	"testing"
)

// The desired-state routes' permissions, pinned at the registration.
//
// Review reverted `agents.PUT("/:id/config")` from sensors.update to
// sensors.manage and every test stayed green: the route-registration test
// checks that the routes EXIST, and nothing checked what gates them. A
// permission is exactly the kind of one-word change that a refactor makes by
// accident and nobody notices until a role cannot do its job.
//
// sensors.update for configuration and sensors.manage for destructive or
// credential operations is the line this repo already draws — see
// inpage-permission-gates.test.ts, which pins the same split on the sensor side.
func TestAgentConfigRoutePermissions(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("reading router.go: %v", err)
	}
	router := string(src)

	for _, want := range []struct {
		name  string
		match *regexp.Regexp
	}{
		{"per-agent read is sensors.read",
			regexp.MustCompile(`agents\.GET\("/:id/config",[^\n]*PermissionSensorsRead`)},
		{"per-agent write is sensors.update, not manage",
			regexp.MustCompile(`agents\.PUT\("/:id/config",[^\n]*PermissionSensorsUpdate`)},
		{"fleet defaults read is sensors.read",
			regexp.MustCompile(`agents\.GET\("/config/defaults",[^\n]*PermissionSensorsRead`)},
		{"fleet defaults write is sensors.update, not manage",
			regexp.MustCompile(`agents\.PUT\("/config/defaults",[^\n]*PermissionSensorsUpdate`)},
	} {
		if !want.match.MatchString(router) {
			t.Errorf("%s — the route is registered behind the wrong permission, or not at all", want.name)
		}
	}
}
