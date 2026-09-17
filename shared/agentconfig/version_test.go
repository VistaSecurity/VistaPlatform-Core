package agentconfig

import "testing"

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		name             string
		device, expected string
		want             VersionState
	}{
		{"identical", "1.0.0", "1.0.0", VersionCurrent},
		{"leading v on either side", "v1.0.0", "1.0.0", VersionCurrent},
		{"older patch", "1.0.0", "1.0.1", VersionBehind},
		{"older minor", "1.0.9", "1.1.0", VersionBehind},
		{"older major", "0.9.9", "1.0.0", VersionBehind},
		{"newer than the platform", "1.1.0", "1.0.0", VersionAhead},
		{"short forms", "1.0", "1.0.0", VersionCurrent},

		// A release candidate compares as its release: telling an operator to
		// upgrade from rc.9 to 1.0.0 is noise.
		{"release candidate of the same release", "1.0.0-rc.9", "1.0.0", VersionCurrent},
		{"the release against its own candidate", "1.0.0", "1.0.0-rc.9", VersionCurrent},
		{"release candidate of an older release", "1.0.0-rc.9", "1.1.0", VersionBehind},

		// Everything unparseable is unknown, never "current".
		{"device reports nothing", "", "1.0.0", VersionUnknown},
		{"platform knows nothing", "1.0.0", "", VersionUnknown},
		{"both unknown", "", "", VersionUnknown},
		{"device reports a branch name", "main", "1.0.0", VersionUnknown},
		{"device reports a commit", "9fc7834e", "1.0.0", VersionUnknown},
		{"too many segments", "1.0.0.1", "1.0.0", VersionUnknown},
		{"negative", "1.-1.0", "1.0.0", VersionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompareVersions(tc.device, tc.expected); got != tc.want {
				t.Errorf("CompareVersions(%q, %q) = %s, want %s", tc.device, tc.expected, got, tc.want)
			}
		})
	}
}

// The distinction that matters most: not knowing must never be displayed as
// being up to date. An operator reading "current" against an unknown baseline
// would believe a fleet was patched when nobody had checked.
func TestUnknownIsNeverCurrent(t *testing.T) {
	for _, tc := range [][2]string{{"", "1.0.0"}, {"1.0.0", ""}, {"", ""}, {"dev", "1.0.0"}} {
		if got := CompareVersions(tc[0], tc[1]); got == VersionCurrent {
			t.Errorf("CompareVersions(%q, %q) = current; an unmade comparison must not read as up to date", tc[0], tc[1])
		}
	}
}

func TestExpectedVersionReadsTheReleaseTag(t *testing.T) {
	t.Setenv("SERVICE_VERSION", " v1.2.3 ")
	if got := ExpectedVersion(); got != "v1.2.3" {
		t.Errorf("ExpectedVersion() = %q, want the trimmed release tag", got)
	}
	t.Setenv("SERVICE_VERSION", "")
	if got := ExpectedVersion(); got != "" {
		t.Errorf("ExpectedVersion() = %q, want empty when the platform does not know its own version", got)
	}
}

// Two DIFFERENT pre-releases of one version are different builds, and calling
// either "up to date" is the false reassurance this comparison exists to avoid.
//
// Live, not hypothetical: this repo ships core-v*-rc.N tags and stamps the
// agent and sensor binaries from them, so a fleet mid-RC has exactly this
// shape. Review found it by asking what rc.2 reads as against rc.9.
func TestDifferentPreReleasesOfOneVersionAreNotCurrent(t *testing.T) {
	for _, tc := range []struct{ device, expected string }{
		{"1.0.0-rc.2", "1.0.0-rc.9"},
		{"1.0.0-rc.9", "1.0.0-rc.2"},
		{"v1.0.0-rc.1", "v1.0.0-rc.10"},
		{"1.0.0-alpha", "1.0.0-beta"},
	} {
		if got := CompareVersions(tc.device, tc.expected); got == VersionCurrent {
			t.Errorf("CompareVersions(%q, %q) = current — they are different builds, and one of them is not up to date",
				tc.device, tc.expected)
		}
	}

	// The same pre-release IS current: an rc.9 fleet against an rc.9 platform
	// is exactly right, and reporting that as unknown would be its own noise.
	if got := CompareVersions("1.0.0-rc.9", "v1.0.0-rc.9"); got != VersionCurrent {
		t.Errorf("CompareVersions of matching candidates = %s, want current", got)
	}

	// And a candidate against its own release stays current, which is the
	// noise-suppression the ordering rule is for.
	if got := CompareVersions("1.0.0-rc.9", "1.0.0"); got != VersionCurrent {
		t.Errorf("a candidate against its own release = %s, want current", got)
	}
}

// Build metadata does not affect precedence — semver is explicit about that —
// so two builds of one version are the same version for this display. Treating
// them as different would be noise of exactly the kind the
// candidate-against-its-release rule exists to suppress.
//
// A PRE-RELEASE is significant, and is handled the other way. The distinction
// is the whole reason this helper exists rather than a string compare.
func TestBuildMetadataDoesNotAffectTheComparison(t *testing.T) {
	for _, tc := range []struct{ device, expected string }{
		{"1.0.0+build.1", "1.0.0+build.2"},
		{"1.0.0+build.1", "1.0.0"},
		{"v1.0.0+abc", "1.0.0+def"},
	} {
		if got := CompareVersions(tc.device, tc.expected); got != VersionCurrent {
			t.Errorf("CompareVersions(%q, %q) = %s, want current — build metadata is not significant",
				tc.device, tc.expected, got)
		}
	}

	// And metadata does not mask a pre-release difference underneath it.
	if got := CompareVersions("1.0.0-rc.2+abc", "1.0.0-rc.9+abc"); got == VersionCurrent {
		t.Error("two candidates differing only in pre-release read as current when build metadata was present")
	}
}
