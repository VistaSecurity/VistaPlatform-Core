package services

import (
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"net/netip"
	"testing"
)

func TestNetworkTypeForAddress(t *testing.T) {
	cases := map[string]string{
		"10.1.2.3":              "private",
		"172.16.0.9":            "private",
		"192.168.5.5":           "private",
		"169.254.10.1":          "private",
		"127.0.0.1":             "private",
		"::1":                   "private",
		"fd88:202:11b3:7e08::1": "private",
		"fc00::1":               "private",
		"fe80::1%eth0":          "private",
		"::ffff:192.168.1.1":    "private",
		// D1: carrier-grade NAT is an internal candidate; network_type
		// has no value of its own for it, so it reports private.
		"100.64.0.1":           "private",
		"100.127.255.254":      "private",
		"100.128.0.1":          "public",
		"8.8.8.8":              "public",
		"203.0.113.7":          "public",
		"2001:db8::1":          "public",
		"2606:4700:4700::1111": "public",
		"":                     "public",
		"not-an-ip":            "public",
	}
	for in, want := range cases {
		if got := NetworkTypeForAddress(in); got != want {
			t.Errorf("NetworkTypeForAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

// An imported segment's network_type is what the automatic-scan gates read as
// ownership, so CGNAT must stay "public" there even though an unmatched CGNAT
// address classifies as an internal candidate ( D1).
func TestSourceNetworkTypeKeepsCGNATOutOfAutoScan(t *testing.T) {
	cases := map[string]string{
		"10.20.0.0/16":    "private",
		"fd00:db8::/48":   "private",
		"169.254.0.0/16":  "private",
		"100.64.0.0/10":   "public",
		"100.100.0.0/16":  "public",
		"198.51.100.0/24": "public",
	}
	for in, want := range cases {
		if got := sourceNetworkType(netip.MustParsePrefix(in)); got != want {
			t.Errorf("sourceNetworkType(%s) = %q, want %q", in, got, want)
		}
	}
}

// PrefixSet answers every prefix question from one read: the LONGEST match,
// and a nil set (nothing read) matches nothing and still classifies by address
// class.
func TestPrefixSetMatchClassifyAndNilSafety(t *testing.T) {
	var nilSet *PrefixSet
	str := func(s string) *string { return &s }
	if nilSet.Match(str("10.0.0.1")) != nil {
		t.Fatal("a nil set matched a prefix")
	}
	for addr, want := range map[string]string{
		"10.0.0.1":    "unknown",
		"100.64.3.4":  "unknown", // #2374 D1
		"203.0.113.4": "third_party",
	} {
		if got := nilSet.Classify(str(addr)); got != want {
			t.Errorf("Classify(%s) = %q, want %q", addr, got, want)
		}
	}
	if got := nilSet.Classify(nil); got != "third_party" {
		t.Errorf("address-less Classify = %q, want third_party", got)
	}

	wide, narrow := uuid.New(), uuid.New()
	set := &PrefixSet{byID: map[uuid.UUID]*prefixInfo{
		wide:   {ID: wide, Prefix: netip.MustParsePrefix("10.0.0.0/16"), NetworkType: "private"},
		narrow: {ID: narrow, Prefix: netip.MustParsePrefix("10.0.1.0/24"), NetworkType: "vpn"},
	}}
	set.match = approval.NewPrefixSet([]approval.Prefix{
		{ID: wide, Prefix: netip.MustParsePrefix("10.0.0.0/16")},
		{ID: narrow, Prefix: netip.MustParsePrefix("10.0.1.0/24")},
	})
	if p := set.Match(str("10.0.1.9")); p == nil || p.ID != narrow {
		t.Fatalf("10.0.1.9 matched %+v, want the /24 (longest match)", p)
	}
	if p := set.Match(str("10.0.2.9")); p == nil || p.ID != wide {
		t.Fatalf("10.0.2.9 matched %+v, want the /16", p)
	}
	if got := set.Classify(str("10.0.1.9")); got != "internal" {
		t.Errorf("Classify inside a prefix = %q, want internal", got)
	}
	if got := classificationType(set.Match(str("10.0.1.9")), str("10.0.1.9")); got != "vpn" {
		t.Errorf("classificationType = %q, want the prefix's vpn", got)
	}
}
