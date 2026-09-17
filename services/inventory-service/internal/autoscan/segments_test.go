package autoscan

import (
	"net/netip"
	"testing"

	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

// sharedClassify names the address rule these tests exercise through, so the
// assertions read as statements about scope rather than about an import path.
func sharedClassify(addr netip.Addr, segments []netip.Prefix) (bool, sharedautoscan.Reason) {
	return sharedautoscan.Classify(addr, segments, nil)
}

// Which registered segments put an address in scope for an UNATTENDED scan.
//
// The case that matters is the `public` segment. A tenant can create one — it
// is a legitimate segment type, and a perfectly good thing to scan when a person
// asks — but the Active Scanning page tells them "public addresses and
// third-party systems are never probed", and a registered public segment is
// exactly how that sentence becomes false without anyone noticing. Addresses
// here are RFC 5737 documentation ranges.
func TestAutomaticSegmentPrefixes(t *testing.T) {
	cases := []struct {
		name     string
		segments []Segment
		want     []string
	}{
		{
			name:     "a private segment is in scope",
			segments: []Segment{{Value: "10.20.0.0/16", NetworkType: "private"}},
			want:     []string{"10.20.0.0/16"},
		},
		{
			name:     "a vpn segment is in scope",
			segments: []Segment{{Value: "172.20.0.0/16", NetworkType: "vpn"}},
			want:     []string{"172.20.0.0/16"},
		},
		{
			name:     "a cloud segment is in scope",
			segments: []Segment{{Value: "10.30.0.0/16", NetworkType: "cloud"}},
			want:     []string{"10.30.0.0/16"},
		},
		{
			// The whole point of this filter.
			name:     "a PUBLIC segment is NOT in scope",
			segments: []Segment{{Value: "203.0.113.0/24", NetworkType: "public"}},
			want:     nil,
		},
		{
			name: "a public segment does not drag its siblings out of scope",
			segments: []Segment{
				{Value: "203.0.113.0/24", NetworkType: "public"},
				{Value: "10.40.0.0/16", NetworkType: "private"},
				{Value: "198.51.100.0/24", NetworkType: "public"},
			},
			want: []string{"10.40.0.0/16"},
		},
		{
			name:     "the type is matched case- and space-insensitively",
			segments: []Segment{{Value: "10.50.0.0/16", NetworkType: " Private "}},
			want:     []string{"10.50.0.0/16"},
		},
		{
			// A type outside the CHECK constraint's vocabulary is not a licence
			// to scan. Default deny.
			name:     "an unknown type is not in scope",
			segments: []Segment{{Value: "10.60.0.0/16", NetworkType: "dmz"}},
			want:     nil,
		},
		{
			name:     "an empty type is not in scope",
			segments: []Segment{{Value: "10.70.0.0/16", NetworkType: ""}},
			want:     nil,
		},
		{
			// A segment can equally be a domain or a VPC id. Those are not
			// addresses, and are simply not this function's business.
			name: "non-address segment values are dropped",
			segments: []Segment{
				{Value: "corp.example.test", NetworkType: "private"},
				{Value: "vpc-0abc123", NetworkType: "cloud"},
				{Value: "10.80.0.0/16", NetworkType: "private"},
			},
			want: []string{"10.80.0.0/16"},
		},
		{
			name:     "no segments",
			segments: nil,
			want:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AutomaticSegmentPrefixes(tc.segments)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i, want := range tc.want {
				if got[i] != netip.MustParsePrefix(want) {
					t.Errorf("prefix %d = %s, want %s", i, got[i], want)
				}
			}
		})
	}
}

// The end-to-end consequence, stated as a fact about Classify rather than about
// the filter: an address inside a registered PUBLIC segment must still be
// refused, because that is the sentence on the page.
func TestPublicSegmentDoesNotPutAnAddressInScope(t *testing.T) {
	const addr = "203.0.113.7"

	inScope := AutomaticSegmentPrefixes([]Segment{{Value: "203.0.113.0/24", NetworkType: "public"}})
	parsed := netip.MustParseAddr(addr)
	if ok, _ := sharedClassify(parsed, inScope); ok {
		t.Fatalf("%s is scannable through a registered PUBLIC segment; the page says public addresses are never probed", addr)
	}

	// And the same address IS scannable once the tenant declares the range
	// private — otherwise this test would pass with the segment rule removed
	// altogether.
	declared := AutomaticSegmentPrefixes([]Segment{{Value: "203.0.113.0/24", NetworkType: "private"}})
	if ok, _ := sharedClassify(parsed, declared); !ok {
		t.Fatalf("%s is not scannable through a registered PRIVATE segment; the segment rule does nothing", addr)
	}
}
