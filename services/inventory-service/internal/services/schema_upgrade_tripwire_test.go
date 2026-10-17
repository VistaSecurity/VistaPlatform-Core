package services

// The upgrade-path guard is disarmed by DECISION, and nothing re-arms it.
//
// `upgradeFromTagCount` is 0 because asset-inventory ADR-0010 D11 re-baselined
// scripts/database/schema.sql for 5.0.0 as a fresh install: the 4.x migration
// block is gone, every 5.0 release candidate is installed onto an empty
// database, and there is no 4.x install to carry forward. That is correct
// today and wrong the moment core-v5.0.0 ships: 5.0.0 is the first release of
// the re-baselined shape and therefore the first one anything can upgrade
// FROM. (ADR-0007 D2.5 disarmed the same guard the same way until core-v1.0.0.)
//
// A comment saying "re-arm this at core-v5.0.0" is a reminder nobody receives.
// This is a tripwire: the day a FINAL `core-v5.Y.Z` tag exists in the
// repository, the constant being 0 becomes a failing test with the reason
// attached. Re-arming also brings back the rest of the upgrade rules ADR-0010
// D11 suspends: the POST-MIGRATIONS block, the two-edit enum rule, DROP POLICY
// + CREATE POLICY for a changed policy (CLAUDE.md, "Database").
//
// Release CANDIDATES do not arm it. `core-v5.0.0-rc.1` is not a release anyone
// runs and then upgrades away from — it exists so we can install it, look at
// it and throw it away — so there is no prior shape for the upgrade test to
// start from, and firing on one is the over-strict polarity of this guard.
//
// It is deliberately CHEAP — one `git tag` call, no database — so it runs in the
// ordinary unit suite rather than waiting for a nightly.

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// finalV5Tag matches a released core-v5 tag and nothing else (no candidates,
// no commercial tags, no other major). Split out from the test so the decision
// itself is testable without a repository whose tags say what the case needs —
// asserting that the filter EXISTS would not tell you it is right.
var finalV5Tag = regexp.MustCompile(`^core-v5\.[0-9]+\.[0-9]+$`)

func finalV5Tags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if finalV5Tag.MatchString(t) {
			out = append(out, t)
		}
	}
	return out
}

// upgradePathArmingError is the tripwire's decision, given the final core-v5
// tags that exist and the configured count. Split out so both polarities are
// testable without creating tags.
func upgradePathArmingError(tags []string, count int) string {
	if len(tags) == 0 || count != 0 {
		return ""
	}
	return "core-v5 has shipped (" + strings.Join(tags, ", ") + ") and upgradeFromTagCount is still 0, so " +
		"TestIntegration_Schema_UpgradesFromPriorReleases skips.\n\n" +
		"asset-inventory ADR-0010 D11 disarmed it for the 5.0 cycle only: schema.sql was re-baselined " +
		"as the 5.0.0 fresh install, with no migration block, because no 4.x database is carried " +
		"forward. A released 5.0 IS carried forward, so from now on the upgrade rules apply again: " +
		"set upgradeFromTagCount to 2, and restore the POST-MIGRATIONS block (ADD COLUMN IF NOT " +
		"EXISTS, the two-edit enum rule, DROP POLICY + CREATE POLICY for a changed policy) — retire " +
		"TestIntegration_Schema_HasNoMigrationBlock in the same change.\n\n" +
		"The upgrade test is the ONLY thing that catches a statement which is fine against today's " +
		"tables and fails against the shape a prior release left behind — a SET NOT NULL on a " +
		"column old rows hold NULL in, a CHECK old-format data violates. A populated double-apply " +
		"is structurally blind to that class, because both of its passes build today's shape."
}

func TestUpgradePathGuardIsArmedOnceV5Exists(t *testing.T) {
	out, err := exec.Command("git", "tag", "--list", "core-v5.*").Output()
	if err != nil {
		// No git, a tarball checkout, a shallow clone with no tags: nothing to
		// say. Skipped rather than failed — a tripwire that fires on its own
		// absence is noise.
		t.Skipf("cannot list git tags (%v); the tripwire needs a checkout with tags", err)
	}
	tags := finalV5Tags(strings.Fields(strings.TrimSpace(string(out))))
	if len(tags) == 0 && upgradeFromTagCount != 0 {
		// Armed early. Harmless, and worth knowing about.
		t.Logf("upgradeFromTagCount = %d before any core-v5 tag exists; the upgrade test will "+
			"try to apply 5.0 release shapes that do not exist yet (ADR-0010 D11)",
			upgradeFromTagCount)
	}
	if msg := upgradePathArmingError(tags, upgradeFromTagCount); msg != "" {
		t.Error(msg)
	}
}

// Both polarities of the filter, because the tripwire's whole value is firing
// at the right moment: a release candidate must not arm it, and a final
// release must.
func TestFinalV5TagsIgnoresCandidates(t *testing.T) {
	for _, c := range []struct {
		name string
		tags []string
		want []string
	}{
		{"candidates alone do not arm it", []string{"core-v5.0.0-rc.1", "core-v5.0.0-rc.2"}, nil},
		{"the final release arms it", []string{"core-v5.0.0-rc.2", "core-v5.0.0"}, []string{"core-v5.0.0"}},
		{"a later patch arms it", []string{"core-v5.2.3"}, []string{"core-v5.2.3"}},
		{"a 4.x release is not this tripwire's business", []string{"core-v4.6.0"}, nil},
		{"a v6 tag is not this tripwire's business", []string{"core-v6.0.0"}, nil},
		{"a commercial tag is not a core tag", []string{"v5.0.0"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := finalV5Tags(c.tags)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("finalV5Tags(%v) = %v, want %v", c.tags, got, c.want)
			}
		})
	}
}

// The decision in both polarities: a final v5 tag with the count at 0 fails,
// naming ADR-0010 D11; no tag, or a re-armed count, passes.
func TestUpgradePathArmingError(t *testing.T) {
	if msg := upgradePathArmingError([]string{"core-v5.0.0"}, 0); !strings.Contains(msg, "ADR-0010 D11") {
		t.Errorf("core-v5.0.0 shipped with the count at 0: want a failure naming ADR-0010 D11, got %q", msg)
	}
	if msg := upgradePathArmingError(nil, 0); msg != "" {
		t.Errorf("no core-v5 release yet: want no failure, got %q", msg)
	}
	if msg := upgradePathArmingError([]string{"core-v5.0.0"}, 2); msg != "" {
		t.Errorf("re-armed after core-v5.0.0: want no failure, got %q", msg)
	}
}
