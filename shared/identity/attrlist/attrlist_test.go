package attrlist

import (
	"net/netip"
	"slices"
	"testing"
)

// TestAddressAttribute pins D2's disposition table. Mutation: return ""
// for RoleTemporary → the temporary rows fail; ignore segmentScoped → the
// link-local rows fail in one polarity or the other.
func TestAddressAttribute(t *testing.T) {
	tests := []struct {
		addr   string
		scoped bool
		want   string
	}{
		{"192.0.2.10", false, ""},
		{"fd00::a2b2:c3ff:fed4:e5f6", false, ""},               // EUI-64: identifier
		{"2001:db8::10", false, ""},                            // hand-assigned: identifier
		{"fd00::1234:5678:9abc:def0", false, KeyIPv6Temporary}, // random IID
		{"fd00::1234:5678:9abc:def0", true, KeyIPv6Temporary},  // scope does not rescue it
		{"fe80::1", true, ""},                                  // link-local in a real segment
		{"fe80::1", false, KeyLinkLocal},                       // link-local with nowhere to scope
		{"fe80::a2b2:c3ff:fed4:e5f6", false, KeyLinkLocal},     // EUI-64 does not make it global
	}
	for _, tc := range tests {
		if got := AddressAttribute(netip.MustParseAddr(tc.addr), tc.scoped); got != tc.want {
			t.Errorf("AddressAttribute(%s, scoped=%v) = %q, want %q", tc.addr, tc.scoped, got, tc.want)
		}
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name               string
		incoming, existing []string
		max                int
		want               []string
	}{
		{"newest first, then existing", []string{"b"}, []string{"a"}, 10, []string{"b", "a"}},
		{"a repeat moves to the front", []string{"a"}, []string{"b", "a"}, 10, []string{"a", "b"}},
		{"normalised and deduplicated", []string{" Host.Local. ", "host.local"}, nil, 10, []string{"host.local"}},
		{"IPv6 text folds to one spelling", []string{"2001:DB8::1"}, []string{"2001:db8::1"}, 10, []string{"2001:db8::1"}},
		{"capped, oldest fall off", []string{"c", "d"}, []string{"a", "b"}, 3, []string{"c", "d", "a"}},
		{"empty values skipped", []string{"", " "}, []string{"a"}, 10, []string{"a"}},
		{"zero cap keeps nothing", []string{"a"}, nil, 0, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Merge(tc.incoming, tc.existing, tc.max); !slices.Equal(got, tc.want) {
				t.Fatalf("Merge = %q, want %q", got, tc.want)
			}
		})
	}
}
