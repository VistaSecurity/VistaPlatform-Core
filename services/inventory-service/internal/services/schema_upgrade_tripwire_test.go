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
// This is a tripwire: the day a FINAL `core-v1.Y.Z` tag exists in the
// repository, the constant being 0 becomes a failing test with the reason
// attached.
//
// Release CANDIDATES do not arm it. `core-v1.0.0-rc.1` is not a release anyone
// runs and then upgrades away from — it exists so we can install it, look at
// it and throw it away — so there is no prior shape for the upgrade test to
// start from, and firing on one is the over-strict polarity of this guard:
// a red suite on main that says "re-arm me" when there is nothing yet to
// upgrade from. It stayed invisible for exactly as long as it took someone to
// run the suite in a checkout WITH tags; CI clones without them.
//
// It is deliberately CHEAP — one `git tag` call, no database — so it runs in the
// ordinary unit suite rather than waiting for a nightly.

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// finalV1Tags keeps the released core-v1 tags and drops prereleases. Split out
// from the test so the decision itself is testable without a repository whose
// tags say what the case needs — asserting that the filter EXISTS would not
// tell you it is right.
var finalV1Tag = regexp.MustCompile(`^core-v1\.[0-9]+\.[0-9]+$`)

func finalV1Tags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if finalV1Tag.MatchString(t) {
			out = append(out, t)
		}
	}
	return out
}

func TestUpgradePathGuardIsArmedOnceV1Exists(t *testing.T) {
	out, err := exec.Command("git", "tag", "--list", "core-v1.*").Output()
	if err != nil {
		// No git, a tarball checkout, a shallow clone with no tags: nothing to
		// say. Skipped rather than failed — a tripwire that fires on its own
		// absence is noise.
		t.Skipf("cannot list git tags (%v); the tripwire needs a checkout with tags", err)
	}
	tags := finalV1Tags(strings.Fields(strings.TrimSpace(string(out))))
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

// Both polarities of the filter, because the tripwire's whole value is firing
// at the right moment: a release candidate must not arm it, and a final
// release must.
func TestFinalV1TagsIgnoresCandidates(t *testing.T) {
	for _, c := range []struct {
		name string
		tags []string
		want []string
	}{
		{"candidates alone do not arm it", []string{"core-v1.0.0-rc.1", "core-v1.0.0-rc.2"}, nil},
		{"the final release arms it", []string{"core-v1.0.0-rc.2", "core-v1.0.0"}, []string{"core-v1.0.0"}},
		{"a later patch arms it", []string{"core-v1.2.3"}, []string{"core-v1.2.3"}},
		{"a v2 tag is not this tripwire's business", []string{"core-v2.0.0"}, nil},
		{"a commercial tag is not a core tag", []string{"v1.0.0"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := finalV1Tags(c.tags)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("finalV1Tags(%v) = %v, want %v", c.tags, got, c.want)
			}
		})
	}
}
