package dispatchguard

import (
	"net/netip"
	"testing"
)

// TestSegmentGrantsOwnership pins which registered segments put their range in
// scope. The public rows are the ones that matter: a LEARNED public segment — a
// firewall's ISP transit network, its carrier-NAT WAN VLAN — is where the
// device is connected, not an estate the tenant owns, and it grants nothing.
func TestSegmentGrantsOwnership(t *testing.T) {
	for _, tc := range []struct {
		networkType        string
		learned, automatic bool
		want               bool
	}{
		{"private", false, false, true},
		{"private", true, false, true},
		{"private", true, true, true},
		{"vpn", false, true, true},
		{"cloud", true, true, true},
		{"public", false, false, true}, // declared, person-initiated: the registry's purpose
		{"public", true, false, false}, // learned: never ownership
		{"public", false, true, false}, // unattended: never public space
		{"public", true, true, false},
		{"", false, false, false},
		{"unknown", false, false, false},
	} {
		if got := SegmentGrantsOwnership(tc.networkType, tc.learned, tc.automatic); got != tc.want {
			t.Errorf("SegmentGrantsOwnership(%q, learned=%v, automatic=%v) = %v, want %v",
				tc.networkType, tc.learned, tc.automatic, got, tc.want)
		}
	}
}

// TestSegmentPrefixGrantsOwnership: the breadth cap (network.TooBroadToClaim)
// applies whatever the segment's type, and private space is exempt.
func TestSegmentPrefixGrantsOwnership(t *testing.T) {
	for _, tc := range []struct {
		prefix, networkType string
		automatic           bool
		want                bool
	}{
		{"0.0.0.0/0", "public", false, false},
		{"0.0.0.0/0", "private", false, false}, // mislabelled: still no claim
		{"92.0.0.0/7", "public", false, false},
		{"93.0.0.0/8", "public", false, true},
		{"::/0", "cloud", false, false},
		{"2600::/15", "public", false, false},
		{"2606::/16", "public", false, true},
		{"fc00::/7", "private", true, true}, // ULA exempt, however wide
		{"10.0.0.0/8", "private", true, true},
		{"93.0.0.0/8", "public", true, false}, // automatic never owns public
	} {
		if got := SegmentPrefixGrantsOwnership(netip.MustParsePrefix(tc.prefix), tc.networkType, false, tc.automatic); got != tc.want {
			t.Errorf("SegmentPrefixGrantsOwnership(%s, %s, automatic=%v) = %v, want %v", tc.prefix, tc.networkType, tc.automatic, got, tc.want)
		}
	}
}
