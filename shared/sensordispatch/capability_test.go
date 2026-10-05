package sensordispatch

import (
	"strings"
	"testing"
)

func TestHasCapability(t *testing.T) {
	if !HasCapability([]string{IdentityDNSCapability, ScanPlanCapability}, ScanPlanCapability) {
		t.Fatal("a reported capability was not found")
	}
	for _, caps := range [][]string{nil, {}, {IdentityDNSCapability}, {"scan_plan_v2"}, {"SCAN_PLAN_V1"}} {
		if HasCapability(caps, ScanPlanCapability) {
			t.Fatalf("%v reported as carrying %s", caps, ScanPlanCapability)
		}
	}
}

func TestScanPlanUnsupportedMessage_SaysWhatToDo(t *testing.T) {
	msg := ScanPlanUnsupportedMessage("branch-01")
	for _, want := range []string{"branch-01", "does not support scan depth", "upgrade", "platform", "nothing was scanned"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}
