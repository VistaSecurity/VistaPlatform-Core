package ast

import (
	"strconv"
	"strings"
)

// VersionSortKey normalises a version string into a text key that sorts
// component-wise, which is what `version < 3.0` must compare on (§5.5:
// `1.1.1w` < `3.0.2`, never lexically).
//
// This function is the definition of `software_products.version_sort` and of
// any other *_sort column a version-typed field points at: whatever writes
// those columns MUST use it, or the comparison compares two different
// normalisations and quietly returns the wrong rows. It lives here, next to the
// literal parsing, so there is exactly one of it.
//
// The shape, and why each part of it is there:
//
//		<slot1>.<slot2>.….<slot6>|<pre>
//
//	  - A fixed six slots, missing ones zero-filled, so a shorter version compares
//	    against the longer one component by component: 3.0 must be BELOW 3.0.2,
//	    and a variable-length key makes it above.
//	  - Each slot is the component's leading digits zero-padded to eight
//	    characters, so 1.10 sorts after 1.9 rather than before it.
//	  - A letter glued to a component's digits is kept in the slot, so OpenSSL's
//	    1.1.1w sorts just after 1.1.1 — a glued letter is a patch release.
//	  - Anything after the first "-" or "+" is a pre-release tag and goes in the
//	    final field, where a release's "~" (above every alphanumeric byte) makes
//	    1.0.0-rc1 sort BELOW 1.0.0 — a hyphenated tag is a pre-release. The two
//	    conventions are opposite, and the separator is what tells them apart.
//
// The key must be compared byte-wise, which is why the translator emits
// COLLATE "C": a locale collation ignores punctuation in its first pass and
// would undo all of this.
//
// ok is false when the string carries no numeric component at all. A version
// that does not parse has no sort key, the column is NULL, and every
// comparison against it is UNKNOWN — which is the point (§5.2).
func VersionSortKey(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")

	core, pre := v, ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		core, pre = v[:i], strings.ToLower(v[i+1:])
	}

	slots := make([]string, versionSlots)
	for i := range slots {
		slots[i] = padNumber(0)
	}
	sawNumber := false
	for i, p := range strings.Split(core, ".") {
		if p == "" {
			continue
		}
		d := 0
		for d < len(p) && p[d] >= '0' && p[d] <= '9' {
			d++
		}
		digits, suffix := p[:d], strings.ToLower(p[d:])
		if digits == "" {
			// A component with no digits at all inside the core (say "1.x.3")
			// is not a version component; fold it into the pre-release field so
			// it still compares, rather than pretending it is a number.
			pre = strings.TrimPrefix(suffix+"."+pre, ".")
			continue
		}
		n, err := strconv.ParseUint(digits, 10, 64)
		if err != nil || n > maxVersionComponent {
			return "", false
		}
		sawNumber = true
		if i < versionSlots {
			slots[i] = padNumber(n) + suffix
			continue
		}
		// Beyond the sixth component the value is vanishingly rare; keep it in
		// the trailing field so it is not silently dropped.
		pre = strings.TrimSuffix(pre+"."+padNumber(n)+suffix, ".")
	}
	if !sawNumber {
		return "", false
	}
	if pre == "" {
		pre = releaseSentinel
	}
	return strings.Join(slots, ".") + "|" + pre, true
}

const (
	// versionSlots is how many numeric components the key holds.
	versionSlots = 6
	// maxVersionComponent is the largest component the padding can represent.
	maxVersionComponent = 99999999
	// releaseSentinel sorts above every alphanumeric byte, which is what makes
	// a release sort above its own pre-releases.
	releaseSentinel = "~"
)

func padNumber(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) >= 8 {
		return s
	}
	return strings.Repeat("0", 8-len(s)) + s
}

// LooksLikeVersion reports whether v could be a version literal, which is the
// validator's type check for a version-typed field.
func LooksLikeVersion(v string) bool {
	_, ok := VersionSortKey(v)
	return ok
}
