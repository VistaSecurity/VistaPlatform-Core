package agentconfig

import (
	"os"
	"strconv"
	"strings"
)

// Version visibility (owner decision 4).
//
// The platform tells an operator which version each device runs and whether it
// is behind — and nothing more. It does not fetch a new binary, and it does not
// ask an external service what the newest version is.
//
// The expected version is the RELEASE this platform is itself running, because
// the agent and sensor binaries ship from that same release tag. That has one
// honest consequence, stated here so nobody reads the display as more than it
// is: the platform can only say a device is behind once the PLATFORM has been
// upgraded. It cannot know about a release newer than itself.
//
// Chosen over querying GitHub because a control plane on a customer's estate
// should not make outbound calls to do this, an air-gapped install would get
// nothing, and a page load should not depend on somebody else's uptime.

// ExpectedVersion is the device version that ships with this platform release,
// read from the same SERVICE_VERSION the chart injects into every pod.
//
// Empty when the platform does not know its own version — a local build, a
// docker-compose dev stack. Empty means "say nothing", never "everything is up
// to date": a comparison against an unknown baseline is not a comparison.
func ExpectedVersion() string {
	return strings.TrimSpace(os.Getenv("SERVICE_VERSION"))
}

// VersionState is how a device's version compares with the expected one.
type VersionState string

const (
	// VersionUnknown means the comparison could not be made: the device does
	// not report a version, the platform does not know its own, or one of them
	// is not a version this can parse. Distinct from Current, deliberately —
	// "I cannot tell" must never be displayed as "up to date".
	VersionUnknown VersionState = "unknown"
	// VersionCurrent means the device matches the expected version.
	VersionCurrent VersionState = "current"
	// VersionBehind means the device is older than this platform release.
	VersionBehind VersionState = "behind"
	// VersionAhead means the device is NEWER than the platform. Not an error:
	// it happens during a rollout, when agents are upgraded before the control
	// plane. Worth showing rather than hiding, because it also happens when
	// somebody installs the wrong binary.
	VersionAhead VersionState = "ahead"
)

// CompareVersions reports how a device's self-reported version compares with
// the expected one.
//
// Parses a leading "v" and the numeric major.minor.patch, ignoring any
// pre-release or build suffix for the ORDERING: `1.0.0-rc.9` is not behind
// `1.0.0`, because telling an operator to upgrade from a release candidate to
// its own release is noise, and pre-release ordering is not what this display
// is for.
//
// But two DIFFERENT pre-releases of the same version are not the same build,
// and saying "up to date" about one that is not the expected one is exactly the
// false reassurance this whole comparison exists to avoid. `1.0.0-rc.2` against
// an expected `1.0.0-rc.9` is `unknown`, not `current`: the display cannot
// order them and must not pretend they match. This repo ships `core-v*-rc.N`
// tags and stamps the agent binaries from them, so it is a live case rather
// than a hypothetical one.
func CompareVersions(device, expected string) VersionState {
	d, okD := parseVersion(device)
	e, okE := parseVersion(expected)
	if !okD || !okE {
		return VersionUnknown
	}
	for i := 0; i < 3; i++ {
		switch {
		case d[i] < e[i]:
			return VersionBehind
		case d[i] > e[i]:
			return VersionAhead
		}
	}
	// Same numbers. Two DIFFERENT pre-releases of one version are different
	// builds, and calling either "up to date" is false — `1.0.0-rc.2` against an
	// expected `1.0.0-rc.9` is unknown.
	//
	// But a candidate against its own RELEASE is current, and that asymmetry is
	// deliberate: one side having no suffix is the noise-suppression case the
	// ordering rule exists for, while two suffixes that disagree is a real
	// difference the display cannot rank.
	dPre, ePre := preRelease(device), preRelease(expected)
	if dPre != "" && ePre != "" && dPre != ePre {
		return VersionUnknown
	}
	return VersionCurrent
}

// preRelease returns the PRE-RELEASE suffix only — the part after "-", with any
// build metadata after "+" removed.
//
// Build metadata is excluded deliberately: semver says it does not affect
// precedence, so `1.0.0+build.1` and `1.0.0+build.2` are the same version and
// telling an operator otherwise would be noise of exactly the kind the
// candidate-against-its-release rule exists to suppress. A pre-release IS
// significant, and two that differ are different builds.
func preRelease(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[i:]
	}
	return ""
}

// parseVersion reads major.minor.patch, tolerating a leading v and any
// pre-release suffix. It returns false for anything it cannot read, which the
// caller renders as "unknown" rather than guessing.
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return out, false
	}
	// Drop a pre-release or build suffix: 1.0.0-rc.9, 1.0.0+build.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
