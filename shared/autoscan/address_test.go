package autoscan

import (
	"net/netip"
	"testing"
)

// Public addresses in this file are RFC 5737 documentation ranges. They are
// here to be REFUSED, and a test that refuses a real third party's address is
// still a test that wrote a real third party's address down.
const (
	docPublicA = "192.0.2.10"    // TEST-NET-1
	docPublicB = "198.51.100.42" // TEST-NET-2
	docPublicC = "203.0.113.7"   // TEST-NET-3
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestClassify(t *testing.T) {
	segments := ParsePrefixes([]string{"203.0.113.0/24", "not-a-cidr", "example.internal"})
	excluded := ParsePrefixes([]string{"10.42.0.0/16", "192.168.77.5"})

	cases := []struct {
		name    string
		address string
		want    bool
		reason  Reason
	}{
		// --- accepted: private by address class -------------------------
		{"rfc1918 ten", "10.1.2.3", true, ReasonPrivate},
		{"rfc1918 172.16", "172.16.4.5", true, ReasonPrivate},
		{"rfc1918 172.31 top of range", "172.31.255.254", true, ReasonPrivate},
		{"rfc1918 192.168", "192.168.1.20", true, ReasonPrivate},
		{"ipv6 ula", "fd00:1234::5", true, ReasonPrivate},
		{"ipv4-mapped private", "::ffff:10.0.0.9", true, ReasonPrivate},

		// --- accepted: the tenant declared the range as theirs -----------
		{"inside a registered segment", docPublicC, true, ReasonSegment},

		// --- refused: not the tenant's, or not a host at all -------------
		// The whole point of the feature's scope rule: an unattended DAILY
		// scan of somebody else's address is us port-scanning a third party on
		// a schedule.
		{"public", docPublicA, false, ReasonPublic},
		{"public, second range", docPublicB, false, ReasonPublic},
		{"172.32 is NOT rfc1918", "172.32.0.1", false, ReasonPublic},
		{"172.15 is NOT rfc1918", "172.15.255.255", false, ReasonPublic},
		// RFC 6598 carrier space reaches other operators' customers. Refused
		// like public, but under its OWN reason: a Tailscale or ZeroTier
		// estate lives entirely in this range, and the page has to be able to
		// say so rather than call their whole network "public".
		{"cgnat shared space", "100.64.0.1", false, ReasonCarrierGradeNAT},
		{"cgnat top of range", "100.127.255.254", false, ReasonCarrierGradeNAT},
		{"just past cgnat is public", "100.128.0.1", false, ReasonPublic},
		{"just before cgnat is public", "100.63.255.255", false, ReasonPublic},
		{"ipv6 global unicast", "2001:db8::1", false, ReasonPublic},

		{"loopback", "127.0.0.1", false, ReasonLoopback},
		{"ipv6 loopback", "::1", false, ReasonLoopback},
		{"ipv4 link-local", "169.254.10.1", false, ReasonLinkLocal},
		{"ipv6 link-local", "fe80::1", false, ReasonLinkLocal},
		// 224.0.0.1 and ff02::1 are LINK-LOCAL multicast, so the link-local arm
		// answers first. Both arms refuse; the reason names which rule fired.
		{"link-local multicast", "224.0.0.1", false, ReasonLinkLocal},
		{"ipv6 link-local multicast", "ff02::1", false, ReasonLinkLocal},
		{"organization-scoped multicast", "239.1.1.1", false, ReasonMulticast},
		{"ipv6 global multicast", "ff0e::1", false, ReasonMulticast},
		{"interface-local multicast", "ff01::1", false, ReasonMulticast},
		{"limited broadcast", "255.255.255.255", false, ReasonMulticast},
		{"unspecified", "0.0.0.0", false, ReasonUnspecified},
		{"ipv6 unspecified", "::", false, ReasonUnspecified},

		// --- refused: explicitly excluded, and exclusion WINS -------------
		// Both of these are RFC 1918 and would otherwise be accepted. The
		// platform's own addresses must not come back into scope just because
		// they happen to be private.
		{"excluded range beats private", "10.42.0.7", false, ReasonExcluded},
		{"excluded host beats private", "192.168.77.5", false, ReasonExcluded},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := Classify(mustAddr(t, tc.address), segments, excluded)
			if ok != tc.want || reason != tc.reason {
				t.Fatalf("Classify(%s) = (%v, %s), want (%v, %s)", tc.address, ok, reason, tc.want, tc.reason)
			}
		})
	}
}

// A segment declaration must not be able to re-admit an address the platform
// excluded — the exclusion list is the platform protecting itself, and it is
// not a tenant-editable list.
func TestClassify_ExclusionBeatsSegment(t *testing.T) {
	segments := ParsePrefixes([]string{"10.0.0.0/8"})
	excluded := ParsePrefixes([]string{"10.0.5.0/24"})
	ok, reason := Classify(mustAddr(t, "10.0.5.5"), segments, excluded)
	if ok || reason != ReasonExcluded {
		t.Fatalf("got (%v, %s), want (false, %s)", ok, reason, ReasonExcluded)
	}
}

// A registered segment is the explicit statement of ownership the CGNAT
// refusal asks for, so a tenant who declares their 100.64/10 estate gets it
// scanned — the refusal names the fix, and the fix has to work.
func TestClassify_RegisteredSegmentAdmitsCarrierGradeNAT(t *testing.T) {
	segments := ParsePrefixes([]string{"100.100.0.0/16"})
	if ok, reason := Classify(mustAddr(t, "100.100.4.9"), segments, nil); !ok || reason != ReasonSegment {
		t.Fatalf("got (%v, %s), want (true, %s)", ok, reason, ReasonSegment)
	}
	if ok, reason := Classify(mustAddr(t, "100.64.4.9"), segments, nil); ok || reason != ReasonCarrierGradeNAT {
		t.Fatalf("outside the segment: got (%v, %s), want (false, %s)", ok, reason, ReasonCarrierGradeNAT)
	}
}

func TestClassify_InvalidAddr(t *testing.T) {
	if ok, reason := Classify(netip.Addr{}, nil, nil); ok || reason != ReasonUnparseable {
		t.Fatalf("got (%v, %s), want (false, %s)", ok, reason, ReasonUnparseable)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantOK  bool
		reason  Reason
		wantStr string
	}{
		{"plain ipv4", "10.0.0.1", true, "", "10.0.0.1"},
		{"surrounding space", "  10.0.0.1  ", true, "", "10.0.0.1"},
		{"ipv4-mapped is unmapped", "::ffff:10.0.0.1", true, "", "10.0.0.1"},
		{"empty", "", false, ReasonUnparseable, ""},
		{"hostname", "host.example.internal", false, ReasonUnparseable, ""},
		{"host:port", "10.0.0.1:443", false, ReasonUnparseable, ""},
		// Postgres `inet` cannot hold a zone, so a zoned value did not come
		// from the inet column — and dropping the zone would probe a different
		// interface's idea of that address.
		{"ipv6 zone id", "fe80::1%eth0", false, ReasonZoned, ""},
		{"numeric zone id", "fe80::1%6", false, ReasonZoned, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, reason, ok := ParseTarget(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (reason %s)", ok, tc.wantOK, reason)
			}
			if !ok {
				if reason != tc.reason {
					t.Fatalf("reason = %s, want %s", reason, tc.reason)
				}
				return
			}
			if addr.String() != tc.wantStr {
				t.Fatalf("addr = %s, want %s", addr, tc.wantStr)
			}
		})
	}
}

func TestParsePrefixes(t *testing.T) {
	got := ParsePrefixes([]string{
		"10.0.0.0/8",
		"10.1.2.3/8",        // unmasked input is masked on the way in
		"192.168.1.7",       // bare host becomes /32
		"fd00::/8",          //
		"vpc-0abc123",       // a segment can be a VPC id — not an address
		"corp.example.test", // or a domain
		"",
		"fe80::1%eth0", // zoned values are not prefixes we will honour
	})
	want := []string{"10.0.0.0/8", "10.0.0.0/8", "192.168.1.7/32", "fd00::/8"}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, got[i], want[i])
		}
	}
}
