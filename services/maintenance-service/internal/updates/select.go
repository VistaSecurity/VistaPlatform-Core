package updates

import (
	"sort"
	"strconv"
	"strings"
)

// Version is a parsed semantic version. Build metadata is ignored for
// precedence, as semver specifies.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string
	raw                 string
}

// String is the version as it appeared (the tag).
func (v Version) String() string { return v.raw }

// Prerelease reports whether the version carries a pre-release part.
func (v Version) Prerelease() bool { return len(v.Pre) > 0 }

// ParseVersion parses a strict MAJOR.MINOR.PATCH[-pre][+build] tag. Helm
// publishes chart versions to OCI registries as bare semver with `_` standing
// in for `+`, so both are accepted. A leading "v" is rejected: it is not how a
// chart is tagged, and accepting it would surface image-style tags from a
// mirror that is full of unrelated repositories' leftovers as installable
// chart versions.
func ParseVersion(s string) (Version, bool) {
	raw := s
	s = strings.ReplaceAll(s, "_", "+")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if i == len(s)-1 || !validIdentifiers(s[i+1:], false) {
			return Version{}, false
		}
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre, s = s[i+1:], s[:i]
		if pre == "" || !validIdentifiers(pre, true) {
			return Version{}, false
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var nums [3]uint64
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return Version{}, false
		}
		n, err := strconv.ParseUint(p, 10, 63)
		if err != nil {
			return Version{}, false
		}
		nums[i] = n
	}
	v := Version{Major: nums[0], Minor: nums[1], Patch: nums[2], raw: raw}
	if pre != "" {
		v.Pre = strings.Split(pre, ".")
	}
	return v, true
}

func validIdentifiers(s string, numericNoLeadingZero bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		numeric := true
		for _, r := range id {
			switch {
			case r >= '0' && r <= '9':
			case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '-':
				numeric = false
			default:
				return false
			}
		}
		if numericNoLeadingZero && numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// Compare orders two versions by semver precedence: -1, 0 or 1.
func Compare(a, b Version) int {
	for _, p := range [][2]uint64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		if c := comparePreID(a.Pre[i], b.Pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.Pre) < len(b.Pre):
		return -1
	case len(a.Pre) > len(b.Pre):
		return 1
	}
	return 0
}

func comparePreID(a, b string) int {
	an, aerr := strconv.ParseUint(a, 10, 63)
	bn, berr := strconv.ParseUint(b, 10, 63)
	switch {
	case aerr == nil && berr == nil:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// Selection is what the tag list says about newer releases.
type Selection struct {
	// Latest is the highest eligible tag strictly greater than the running
	// version, or "" when the install is current.
	Latest string
	// PrereleasesSeen lists pre-release tags newer than the running version that
	// were passed over because pre-releases are not wanted (ascending). It is
	// recorded so the console and a support engineer can see the check did see
	// them.
	PrereleasesSeen []string
}

// Select picks the newest release in tags that is strictly newer than current.
// Tags that are not strict semver are ignored (a mirror holds all sorts).
// Pre-releases are dropped unless includePrereleases. An unparsable current
// version (a dev build reports "unknown") yields no Latest: with nothing to
// compare against, "newer" has no meaning and a banner would be noise.
func Select(tags []string, current string, includePrereleases bool) Selection {
	cur, ok := ParseVersion(current)
	if !ok {
		return Selection{}
	}
	var best *Version
	var seenPre []Version
	for _, t := range tags {
		v, ok := ParseVersion(t)
		if !ok || Compare(v, cur) <= 0 {
			continue
		}
		if v.Prerelease() && !includePrereleases {
			seenPre = append(seenPre, v)
			continue
		}
		if best == nil || Compare(v, *best) > 0 {
			vv := v
			best = &vv
		}
	}
	var sel Selection
	if best != nil {
		sel.Latest = best.raw
	}
	sort.Slice(seenPre, func(i, j int) bool { return Compare(seenPre[i], seenPre[j]) < 0 })
	for _, v := range seenPre {
		sel.PrereleasesSeen = append(sel.PrereleasesSeen, v.raw)
	}
	return sel
}

// Newer reports whether latest is strictly newer than current. Either failing
// to parse is "no".
func Newer(latest, current string) bool {
	l, ok1 := ParseVersion(latest)
	c, ok2 := ParseVersion(current)
	return ok1 && ok2 && Compare(l, c) > 0
}
