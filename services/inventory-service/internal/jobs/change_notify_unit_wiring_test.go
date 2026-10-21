package jobs

import (
	"os"
	"strings"
	"testing"
)

// The identity enrichment worker drives a concrete coordinator that a unit
// test cannot fake without a sensor fleet, so its change-notification unit is
// pinned here; the cable resolver and identity evidence passes are driven for
// real in change_notify_unit_integration_test.go.
func TestIdentityEnrichmentWorkerOpensAChangeUnitPerTenant(t *testing.T) {
	raw, err := os.ReadFile("identity_enrichment_job.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "changenotify.Unit(ctx, func(ctx context.Context) error { return coordinator.Sweep(ctx, tenant) })") {
		t.Fatal("the enrichment worker no longer sweeps each tenant inside a changenotify.Unit — its identity-engine writes would raise nothing")
	}
}
