package services

// The upgrade-path guard is disarmed by DECISION, and nothing re-arms it.
//
// `upgradeFromTagCount` is 0 because phase 1 REPLACES the asset tables rather
// than migrating them, and there are no installs of any current `core-v*`
// release to carry forward (ADR-0007 D2.5). That is correct today and wrong the
// moment core-v1.0.0 ships: v1.0.0 is the first release of the new shape and
// therefore the first one anything can upgrade FROM.
//
// A comment saying "re-arm this at core-v1.0.0" is a reminder nobody receives.
// This is a tripwire: the day a `core-v1.*` tag exists in the repository, the
// constant being 0 becomes a failing test with the reason attached.
//
// It is deliberately CHEAP — one `git tag` call, no database — so it runs in the
// ordinary unit suite rather than waiting for a nightly.

import (
	"os/exec"
	"strings"
	"testing"
)

func TestUpgradePathGuardIsArmedOnceV1Exists(t *testing.T) {
	out, err := exec.Command("git", "tag", "--list", "core-v1.*").Output()
	if err != nil {
		// No git, a tarball checkout, a shallow clone with no tags: nothing to
		// say. Skipped rather than failed — a tripwire that fires on its own
		// absence is noise.
		t.Skipf("cannot list git tags (%v); the tripwire needs a checkout with tags", err)
	}
	tags := strings.Fields(strings.TrimSpace(string(out)))
	if len(tags) == 0 {
		if upgradeFromTagCount != 0 {
			// Armed early. Harmless, and worth knowing about.
			t.Logf("upgradeFromTagCount = %d before any core-v1 tag exists; the upgrade test will "+
				"try to apply pre-phase-1 schemas, which ADR-0007 D2.5 says will not work",
				upgradeFromTagCount)
		}
		return
	}

	if upgradeFromTagCount == 0 {
		t.Errorf("core-v1 has shipped (%s) and upgradeFromTagCount is still 0, so "+
			"TestIntegration_Schema_UpgradesFromPriorReleases skips.\n\n"+
			"That test is the ONLY thing that catches a statement which is fine against today's "+
			"tables and fails against the shape a prior release left behind — a SET NOT NULL on a "+
			"column old rows hold NULL in, a CHECK old-format data violates. A populated "+
			"double-apply is structurally blind to that class, because both of its passes build "+
			"today's shape.\n\n"+
			"Set upgradeFromTagCount to 2 (ADR-0007 D2.5).", strings.Join(tags, ", "))
	}
}
