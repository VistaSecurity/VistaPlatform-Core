package jobs

import (
	"os"
	"strings"
	"testing"
)

// The sweep is only a sweep if something starts it. A worker that is defined
// and never launched passes every test of its pass and leaves every floor
// asset nothing observes on `unknown_host` for ever.
func TestClassFloorSweep_MainStartsTheWorker(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	want := "go jobs.StartClassFloorSweepWorker(ctx, bypassDB, services.ClassFloorSweepTenants, assetService)"
	if !strings.Contains(string(src), want) {
		t.Errorf("cmd/main.go no longer contains %q — the class floor sweep is built and never run", want)
	}
}

// The sweep reads vendors the OUI backfill writes, so it must not start first.
func TestClassFloorSweep_StartsAfterTheOUIBackfill(t *testing.T) {
	if classFloorSweepStartDelay <= ouiVendorBackfillStartDelay {
		t.Errorf("class floor sweep starts after %s, not after the OUI backfill's %s",
			classFloorSweepStartDelay, ouiVendorBackfillStartDelay)
	}
	if classFloorSweepLockKey == ouiVendorBackfillLockKey {
		t.Error("the class floor sweep shares the OUI backfill's advisory lock key")
	}
}
