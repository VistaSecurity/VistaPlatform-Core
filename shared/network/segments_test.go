package network

import "testing"

// Which segment an address is in decides two things that are easy to get wrong
// quietly: the environment/site/owner an asset inherits, and — since phase 1 —
// the SCOPE a hostname or an IP identifies within. A wrong answer here puts one
// host in two segments and therefore under two identities.
//
// Every case below checks the value that came back, not merely that something
// did: a resolver that always returned the first segment would pass a
// "did we match" test perfectly.

func segs() []Segment {
	return []Segment{
		// Deliberately in the WRONG order, so the ordering rule is exercised
		// rather than accidentally satisfied by the input order.
		{ID: "wide", Type: "cidr", Value: "198.51.100.0/24"},
		{ID: "domain", Type: "domain", Value: "*.corp.example.test"},
		{ID: "range", Type: "ip_range", Value: "203.0.113.10-203.0.113.20"},
		{ID: "narrow", Type: "cidr", Value: "198.51.100.192/28"},
		{ID: "vpc", Type: "cloud_vpc", Value: "vpc-0123456789abcdef0"},
		{ID: "unparseable", Type: "cidr", Value: "not-a-cidr"},
	}
}

func TestMatchSegmentPrefersTheMostSpecificCIDR(t *testing.T) {
	// .200 is inside BOTH the /24 and the /28. The /28 wins: a carve-out is a
	// more specific statement than the block it sits inside, and inheriting the
	// /24's environment for a host in the carve-out is exactly the silent-wrong
	// answer this ordering exists to prevent.
	got, ok := MatchSegment(segs(), "198.51.100.200", "")
	if !ok || got.ID != "narrow" {
		t.Errorf("MatchSegment(198.51.100.200) = %q (ok=%v), want narrow", got.ID, ok)
	}

	// And an address in the /24 but OUTSIDE the /28 still matches the /24, so
	// the assertion above is about specificity and not about the /24 being
	// unreachable.
	got, ok = MatchSegment(segs(), "198.51.100.10", "")
	if !ok || got.ID != "wide" {
		t.Errorf("MatchSegment(198.51.100.10) = %q (ok=%v), want wide", got.ID, ok)
	}
}

func TestMatchSegmentIPRangeAndDomain(t *testing.T) {
	got, ok := MatchSegment(segs(), "203.0.113.15", "")
	if !ok || got.ID != "range" {
		t.Errorf("MatchSegment(203.0.113.15) = %q (ok=%v), want range", got.ID, ok)
	}
	// Just outside the range, in no CIDR either.
	if got, ok := MatchSegment(segs(), "203.0.113.25", ""); ok {
		t.Errorf("MatchSegment(203.0.113.25) = %q, want no match", got.ID)
	}

	// The hostname is matched only when the IP matched nothing — an address is
	// a stronger statement about where a host IS than a name pattern.
	got, ok = MatchSegment(segs(), "", "printer-2.corp.example.test")
	if !ok || got.ID != "domain" {
		t.Errorf("MatchSegment(hostname) = %q (ok=%v), want domain", got.ID, ok)
	}
	got, ok = MatchSegment(segs(), "198.51.100.200", "printer-2.corp.example.test")
	if !ok || got.ID != "narrow" {
		t.Errorf("MatchSegment(ip + hostname) = %q (ok=%v), want the IP to decide", got.ID, ok)
	}
}

func TestMatchSegmentReportsNoMatchRatherThanGuessing(t *testing.T) {
	cases := []struct{ ip, hostname string }{
		{"192.0.2.5", ""},                    // in no segment
		{"", "somewhere.else.test"},          // matches no domain pattern
		{"", ""},                             // nothing to match on
		{"not-an-ip", ""},                    // unparseable
		{"192.0.2.5", "somewhere.else.test"}, // neither half matches
	}
	for _, tc := range cases {
		if got, ok := MatchSegment(segs(), tc.ip, tc.hostname); ok {
			t.Errorf("MatchSegment(%q, %q) = %q, want no match — a wrong scope splits one host into two assets, "+
				"which is worse than no scope", tc.ip, tc.hostname, got.ID)
		}
	}
	if got, ok := MatchSegment(nil, "198.51.100.200", ""); ok {
		t.Errorf("MatchSegment(no segments) = %q, want no match", got.ID)
	}
}

// A cloud_vpc segment carries no address predicate, so it can never match here.
// It is in the vocabulary for the cloud collectors to key on, and answering
// with it would attach every unmatched address to a VPC.
func TestMatchSegmentNeverReturnsACloudVPC(t *testing.T) {
	for _, ip := range []string{"198.51.100.200", "203.0.113.15", "192.0.2.5"} {
		if got, ok := MatchSegment(segs(), ip, ""); ok && got.Type == "cloud_vpc" {
			t.Errorf("MatchSegment(%s) returned a cloud_vpc segment", ip)
		}
	}
}
