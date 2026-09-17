package main

import (
	"os"
	"regexp"
	"testing"
)

// The desired-state routes are registered inside main(), which cannot be called
// from a test, so this reads the source — the same technique frontend-v2 uses
// for reachability. It is a weaker check than driving a router, and it is here
// because the alternative is no check at all: a handler nothing routes to
// passes every test it has and answers no request.
//
// Each assertion corresponds to a deletion that compiles and leaves every other
// test green. The patterns are line-scoped ([^\n]*) rather than ([^)]*): a
// route line contains the middleware's own parentheses, and the first version
// of this test failed against correctly-registered routes for that reason —
// a guard that cries wolf gets deleted as fast as one that never fires.
func TestDesiredConfigRoutesAreRegistered(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	main := string(src)

	for _, want := range []struct {
		name  string
		match *regexp.Regexp
	}{
		{
			"fleet defaults read, gated on sensors.read",
			regexp.MustCompile(`GET\("/sensors/config/defaults",[^\n]*PermissionSensorsRead[^\n]*sensorConfig\.GetSensorFleetDefaults`),
		},
		{
			"fleet defaults write, gated on sensors.update",
			regexp.MustCompile(`PUT\("/sensors/config/defaults",[^\n]*PermissionSensorsUpdate[^\n]*sensorConfig\.PutSensorFleetDefaults`),
		},
		{
			"per-sensor read, gated on sensors.read",
			regexp.MustCompile(`GET\("/sensors/:sensor_id/desired-config",[^\n]*PermissionSensorsRead[^\n]*sensorConfig\.GetSensorDesiredConfig`),
		},
		{
			"per-sensor write, gated on sensors.update",
			regexp.MustCompile(`PUT\("/sensors/:sensor_id/desired-config",[^\n]*PermissionSensorsUpdate[^\n]*sensorConfig\.PutSensorDesiredConfig`),
		},
	} {
		if !want.match.MatchString(main) {
			t.Errorf("%s is not registered — the handler exists but nothing routes to it, "+
				"or it is gated on the wrong permission", want.name)
		}
	}

}

// What this guard is NOT
//
// An earlier version asserted that `/sensors/config/defaults` is registered
// BEFORE the `:sensor_id` wildcard, on the belief that order decides which
// matches. Review built the real route pair both ways: gin prefers a static
// segment over a param at the same level, resolves the static route correctly
// either way, and does not panic. The assertion could only ever have fired on a
// harmless reorder — a check that cannot fail, guarding a hazard that does not
// exist — so it is gone rather than left to mislead the next reader.
//
// This guard is also defeatable: wrapping the registrations in `if false` keeps
// it green, and it does not pin the router group the routes hang off. It earns
// its place against the deletions that actually happen — a route removed in a
// refactor, a write gated on read — and not as proof of reachability.
