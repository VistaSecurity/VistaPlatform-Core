package updates

import (
	"reflect"
	"testing"
)

func TestParseVersion(t *testing.T) {
	for _, ok := range []string{"4.5.0", "0.0.1", "4.6.0-rc.1", "4.6.0-rc.12", "1.0.0-alpha", "1.2.3_build5", "1.2.3-rc.1_b"} {
		if _, parsed := ParseVersion(ok); !parsed {
			t.Errorf("ParseVersion(%q) rejected a valid version", ok)
		}
	}
	for _, bad := range []string{"", "latest", "v4.5.0", "4.5", "4", "4.5.0.1", "04.5.0", "4.5.x", "sha256-abcdef", "main", "4.5.0-", "4.5.0-01", "1.2.3_", "-1.0.0", "4.5.0-rc..1", "4.5.0-rc!"} {
		if _, parsed := ParseVersion(bad); parsed {
			t.Errorf("ParseVersion(%q) accepted a non-chart tag", bad)
		}
	}
}

func TestCompare_SemverPrecedence(t *testing.T) {
	// Ascending order from the semver spec, section 11.
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	for i := range order {
		for j := range order {
			a, _ := ParseVersion(order[i])
			b, _ := ParseVersion(order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := Compare(a, b); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	// 10 > 9 numerically, not lexically.
	a, _ := ParseVersion("4.10.0")
	b, _ := ParseVersion("4.9.0")
	if Compare(a, b) != 1 {
		t.Error("4.10.0 must outrank 4.9.0")
	}
}

func TestSelect(t *testing.T) {
	cases := []struct {
		name    string
		tags    []string
		current string
		pre     bool
		want    string
		seen    []string
	}{
		{"newer stable wins", []string{"4.4.0", "4.5.0", "4.6.0", "4.5.1"}, "4.5.0", false, "4.6.0", nil},
		{"current is latest", []string{"4.4.0", "4.5.0"}, "4.5.0", false, "", nil},
		{"only older tags", []string{"3.0.0", "4.0.0"}, "4.5.0", false, "", nil},
		{"prerelease dropped by default but recorded", []string{"4.5.0", "4.6.0-rc.1", "4.6.0-rc.2"}, "4.5.0", false, "", []string{"4.6.0-rc.1", "4.6.0-rc.2"}},
		{"prerelease wanted", []string{"4.5.0", "4.6.0-rc.1", "4.6.0-rc.2"}, "4.5.0", true, "4.6.0-rc.2", nil},
		{"final outranks its own rc when both wanted", []string{"4.6.0-rc.2", "4.6.0"}, "4.5.0", true, "4.6.0", nil},
		{"stable wins and rcs above it are still recorded", []string{"4.6.0", "4.7.0-rc.1"}, "4.5.0", false, "4.6.0", []string{"4.7.0-rc.1"}},
		{"rc of an older line is not newer", []string{"4.4.0-rc.9"}, "4.5.0", true, "", nil},
		{"running an rc, the final is an update", []string{"4.6.0-rc.1", "4.6.0"}, "4.6.0-rc.1", false, "4.6.0", nil},
		{"a mirror full of unrelated tags", []string{"latest", "main", "sha256-deadbeef", "v9.9.9", "4.6", "2024-01-01", "4.7.0", "buildcache", "1.2.3.4", ""}, "4.5.0", false, "4.7.0", nil},
		{"empty list", nil, "4.5.0", false, "", nil},
		{"unparsable running version never nags", []string{"4.6.0"}, "unknown", false, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Select(tc.tags, tc.current, tc.pre)
			if got.Latest != tc.want {
				t.Errorf("Latest = %q, want %q", got.Latest, tc.want)
			}
			if !reflect.DeepEqual(got.PrereleasesSeen, tc.seen) {
				t.Errorf("PrereleasesSeen = %v, want %v", got.PrereleasesSeen, tc.seen)
			}
		})
	}
}

func TestNewer(t *testing.T) {
	if !Newer("4.6.0", "4.5.0") || Newer("4.5.0", "4.5.0") || Newer("4.4.0", "4.5.0") || Newer("4.6.0", "unknown") || Newer("junk", "4.5.0") {
		t.Fatal("Newer misjudged")
	}
}
