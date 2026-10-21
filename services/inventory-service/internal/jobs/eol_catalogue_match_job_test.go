package jobs

import (
	"os"
	"strings"
	"testing"
)

// A matcher that is built and never launched leaves every catalogue link to be
// made by hand. Mutation: delete the go line in cmd/main.go.
func TestEOLCatalogueMatch_MainStartsTheWorker(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	want := "go jobs.StartEOLCatalogueMatchWorker(ctx, bypassDB, services.EOLMatchTenants, catalogueService)"
	if !strings.Contains(string(src), want) {
		t.Errorf("cmd/main.go no longer contains %q — the EOL catalogue matcher is built and never run", want)
	}
}

func TestEOLCatalogueMatch_LockKeyIsDistinct(t *testing.T) {
	for name, other := range map[string]int64{
		"cable resolver": cableResolverLockKey, "orphan sweep": orphanSweepLockKey,
		"crypto risk": cryptoRiskJudgmentLockKey, "cert trust": certTrustBackfillLockKey,
		"class floor": classFloorSweepLockKey, "oui": ouiVendorBackfillLockKey,
		"active scan finish": activeScanFinishLockKey, "auto scan sweep": sweepAdvisoryLockKey,
	} {
		if other == eolCatalogueMatchLockKey {
			t.Errorf("shares the %s advisory lock key", name)
		}
	}
}
