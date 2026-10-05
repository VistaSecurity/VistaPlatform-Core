package sensordispatch

// Sensor capabilities a dispatch depends on.
//
// A sensor reports what its software can do on every heartbeat
// (reported_capabilities). The platform hands a sensor a kind of command only
// when the sensor said it can run it: a version string says nothing a dev
// build or a patched build can be trusted with, and a binary that stops
// reporting a capability (a downgrade, a replacement) stops being eligible on
// its next beat — sensor-manager clears a capability the heartbeat no longer
// carries.

import (
	"fmt"
	"strings"
)

// ScanPlanCapability is what a sensor reports when it can run a planned scan
// (scan depth, ports, pace — a job with a scan plan) on the shared engine and
// report its hosts as they finish ( WP2b). A planned job is never handed
// to a sensor that does not report it: an older sensor reads such a job as
// "no protocols" and would finish it having scanned almost nothing — a success
// that did nothing.
const ScanPlanCapability = "scan_plan_v1"

// CodeScanPlanUnsupported is the machine-readable code of the 409 a scan-plan
// job gets when the tenant sensor it names cannot run planned scans.
const CodeScanPlanUnsupported = "sensor_scan_plan_unsupported"

// HasCapability reports whether caps (a sensor's reported_capabilities)
// includes want.
func HasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// ScanPlanUnsupportedMessage is what a person reads when a scan-plan job names
// a sensor whose software cannot run it. It says what to do: nothing ran.
func ScanPlanUnsupportedMessage(sensorName string) string {
	who := "this sensor's"
	if n := strings.TrimSpace(sensorName); n != "" {
		who = fmt.Sprintf("sensor %s's", n)
	}
	return who + " software does not support scan depth — upgrade it, or run the scan from the platform; nothing was scanned"
}
