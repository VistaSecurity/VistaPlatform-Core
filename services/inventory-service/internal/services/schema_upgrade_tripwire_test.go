package services

// The upgrade-path guard must stay armed once a 5.x release exists.
//
// `upgradeFromTagCount` was 0 for the 5.0 cycle by decision (asset-inventory
// ADR-0010 D11): schema.sql was re-baselined as the 5.0.0 fresh install, every
// 5.0 release candidate went onto an empty database, and there was no install
// to carry forward. core-v5.0.0 shipped on — the first release of the
// re-baselined shape and the first one anything can upgrade FROM — and this
// tripwire fired, as designed, until the constant was re-armed to 2. (ADR-0007
// D2.5 disarmed the same guard the same way until core-v1.0.0.)
//
// Its first job is done; it stays as the cheap half of the guard. The upgrade
// test itself only runs under TEST_DATABASE_URL (nightly / make
// test-integration-db), so setting the constant back to 0 would turn it into a
// silent skip that no PR gate notices. This test runs in the ordinary unit suite
// — one `git tag` call, no database — and fails that change with the reason
// attached.
//
// Release CANDIDATES do not count. `core-v5.0.0-rc.1` is not a release anyone
// runs and then upgrades away from — it exists so we can install it, look at
// it and throw it away — so firing on one is the over-strict polarity of this
// guard.

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
	return "core-v5 has shipped (" + strings.Join(tags, ", ") + ") and upgradeFromTagCount is 0, so " +
		"TestIntegration_Schema_UpgradesFromPriorReleases skips.\n\n" +
		"asset-inventory ADR-0010 D11 disarmed it for the 5.0 cycle only, while schema.sql was the " +
		"5.0.0 fresh-install baseline and no database was carried forward. A released 5.0 IS carried " +
		"forward, so the upgrade rules apply (CLAUDE.md, \"Database\": POST-MIGRATIONS, the two-edit " +
		"enum rule, DROP POLICY + CREATE POLICY for a changed policy) and the count must stay at 2.\n\n" +
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
	if len(tags) == 0 {
		// core-v5.0.0 has shipped, so no visible tag means a checkout without
		// tags (a shallow clone), not a world before 5.0. Nothing to check.
		t.Logf("no final core-v5 tag visible in this checkout; upgradeFromTagCount = %d is not checked",
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
