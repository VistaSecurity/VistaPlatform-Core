package network

import (
	"net/netip"
	"testing"
)

// A learned segment's network_type is safety-relevant, not cosmetic: a
// `private` segment puts its range in scope for unattended scanning, so a
// public prefix mislabelled private is how "public addresses are never probed"
// silently becomes false.
func TestPrefixNetworkType(t *testing.T) {
	for prefix, want := range map[string]string{
		"10.0.0.0/8":          "private",
		"10.20.30.0/24":       "private",
		"172.16.0.0/12":       "private",
		"172.31.255.0/24":     "private",
		"192.168.1.0/24":      "private",
		"100.64.0.0/10":       "public", // RFC 6598 carrier space: never learned as ownership
		"100.64.8.0/22":       "public",
		"100.127.255.0/24":    "public",
		"fd00::/8":            "private", // RFC 4193
		"fc00::/7":            "private",
		"::ffff:10.1.0.0/112": "private",
		"198.51.100.0/24":     "public", // RFC 5737 documentation space is not private
		"203.0.113.0/24":      "public",
		"2001:db8::/32":       "public",
		"10.0.0.0/7":          "public", // wider than the private block it starts in
		"172.0.0.0/8":         "public",
		"100.0.0.0/8":         "public",
		"fc00::/6":            "public",
		"::ffff:0.0.0.0/95":   "public",
		"172.32.0.0/16":       "public",
		"192.169.0.0/16":      "public",
	} {
		if got := PrefixNetworkType(netip.MustParsePrefix(prefix)); got != want {
			t.Errorf("PrefixNetworkType(%s) = %q, want %q", prefix, got, want)
		}
	}
	if got := PrefixNetworkType(netip.Prefix{}); got != "public" {
		t.Errorf("invalid prefix = %q, want public (never assume private)", got)
	}
}

func TestUnmapPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:10.1.0.0/112":  "10.1.0.0/16",
		"::ffff:192.0.2.9/120": "192.0.2.0/24",
		"10.1.2.0/24":          "10.1.2.0/24",
		"2001:db8::/32":        "2001:db8::/32",
	} {
		got, ok := UnmapPrefix(netip.MustParsePrefix(in))
		if !ok || got.String() != want {
			t.Errorf("UnmapPrefix(%s) = %s,%v want %s", in, got, ok, want)
		}
	}
	if _, ok := UnmapPrefix(netip.MustParsePrefix("::ffff:0.0.0.0/95")); ok {
		t.Error("a mapped prefix shorter than /96 has no IPv4 form")
	}
}
