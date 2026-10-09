package jobs

import (
	"os"
	"strings"
	"testing"
)

// The backfill is only a backfill if something starts it. A worker that is
// defined and never launched passes every test of its pass and leaves every
// pre-existing asset on the sensor's old vendor answer for ever.
func TestOUIVendorBackfill_MainStartsTheWorker(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	want := "go jobs.StartOUIVendorBackfillWorker(ctx, bypassDB, services.OUIVendorBackfillDueTenants, assetService)"
	if !strings.Contains(string(src), want) {
		t.Errorf("cmd/main.go no longer contains %q — the OUI vendor backfill is built and never run", want)
	}
}
