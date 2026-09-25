package probeconsent

import (
	"net/netip"
	"testing"
)

// The address-class half of ownership. Public space and "merely not routable"
// space are third parties; only private, loopback and link-local are owned
// without the tenant saying so.
func TestOwnedByAddressClass(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.0.0.5": true, "172.16.1.1": true, "192.168.1.10": true,
		"fd00::1": true, "127.0.0.1": true, "::1": true, "169.254.1.1": true, "fe80::1": true,
		"::ffff:10.1.2.3": true,
		// RFC 6598: carrier space, a third party unless declared.
		"100.64.0.1": false,
		// RFC 5737 documentation space stands in for "the public internet"
		// throughout these tests; it is not owned by class.
		"192.0.2.10": false, "198.51.100.7": false, "203.0.113.5": false,
		"2001:db8::1": false,
	} {
		if got := OwnedByAddressClass(netip.MustParseAddr(ip)); got != want {
			t.Errorf("OwnedByAddressClass(%s) = %v, want %v", ip, got, want)
		}
	}
}

// The zero Scope is what a sensor has before the platform has said anything,
// and what it keeps when the platform is too old to say it: private space and
// nothing else.
func TestZeroScopeOwnsOnlyPrivateSpace(t *testing.T) {
	var s Scope
	if !s.Owns("10.0.0.5", 443) {
		t.Error("private address not owned by the zero scope")
	}
	for _, ip := range []string{"203.0.113.5", "100.64.0.1", "not-an-ip", "", "fe80::1%eth0"} {
		if s.Owns(ip, 443) {
			t.Errorf("zero scope owns %q; absent consent is not consent", ip)
		}
	}
}

func TestDeclaredPrefixesAndElevatedEndpoints(t *testing.T) {
	s, rejected := Parse(OwnedNetworks{
		Prefixes:  []string{"203.0.113.0/24", " 2001:db8:1::/48 ", "::ffff:192.0.2.0/120", "garbage", "fe80::/10%eth0"},
		Endpoints: []string{"198.51.100.7:443", "[2001:db8:2::9]:8443", "198.51.100.8", "198.51.100.9:0"},
	})
	if rejected != 4 {
		t.Errorf("rejected = %d, want 4 (garbage, zoned prefix, portless and port-0 endpoints)", rejected)
	}
	for _, tc := range []struct {
		ip   string
		port int
		want bool
	}{
		{"203.0.113.5", 443, true},        // inside a declared prefix, any port
		{"203.0.113.5", 8443, true},       //
		{"203.0.114.5", 443, false},       // just outside it
		{"2001:db8:1::5", 443, true},      // IPv6 declared prefix
		{"192.0.2.200", 443, true},        // a mapped prefix is the IPv4 prefix it denotes
		{"::ffff:203.0.113.9", 443, true}, // a mapped address is the IPv4 address
		{"198.51.100.7", 443, true},       // the elevated endpoint
		{"198.51.100.7", 8443, false},     // ...not every port on that host
		{"2001:db8:2::9", 8443, true},     //
		{"198.51.100.8", 443, false},      // the rejected portless entry grants nothing
		{"100.64.0.1", 443, false},        // CGN stays a third party unless declared
	} {
		if got := s.Owns(tc.ip, tc.port); got != tc.want {
			t.Errorf("Owns(%s, %d) = %v, want %v", tc.ip, tc.port, got, tc.want)
		}
	}
	if p, e, x := s.Len(); p != 3 || e != 2 || x != 0 {
		t.Errorf("Len() = %d prefixes, %d endpoints, %d excluded; want 3, 2, 0", p, e, x)
	}
}

// MayProbe is the enricher's whole decision. Every rule in both directions:
// owned → yes; third party → only with the opt-in; excluded → never, even
// private space and even with the opt-in; not an address → never.
func TestMayProbe(t *testing.T) {
	s, rejected := Parse(OwnedNetworks{
		Prefixes:  []string{"203.0.113.0/24"},
		Endpoints: []string{"198.51.100.7:443"},
		Excluded:  []string{"203.0.113.128/25", "10.9.0.0/16", "192.0.2.0/24"},
	})
	if rejected != 0 {
		t.Fatalf("rejected = %d", rejected)
	}
	for _, tc := range []struct {
		name     string
		ip       string
		port     int
		optIn    bool
		want     bool
		wantOwns bool
	}{
		{"private, opt-in off", "10.0.0.5", 443, false, true, true},
		{"declared public prefix, opt-in off", "203.0.113.5", 443, false, true, true},
		{"elevated endpoint, opt-in off", "198.51.100.7", 443, false, true, true},
		{"third party, opt-in off", "198.51.100.8", 443, false, false, false},
		{"third party, opt-in on", "198.51.100.8", 443, true, true, false},
		{"CGN, opt-in off", "100.64.0.1", 443, false, false, false},
		{"excluded slice of a declared prefix", "203.0.113.200", 443, false, false, false},
		{"excluded slice of a declared prefix, opt-in on", "203.0.113.200", 443, true, false, false},
		{"excluded private segment", "10.9.1.1", 443, false, false, false},
		{"excluded third party, opt-in on", "192.0.2.10", 443, true, false, false},
		{"not an address, opt-in on", "vendor.example", 443, true, false, false},
	} {
		if got := s.MayProbe(tc.ip, tc.port, tc.optIn); got != tc.want {
			t.Errorf("%s: MayProbe(%s:%d, %v) = %v, want %v", tc.name, tc.ip, tc.port, tc.optIn, got, tc.want)
		}
		if got := s.Owns(tc.ip, tc.port); got != tc.wantOwns {
			t.Errorf("%s: Owns(%s:%d) = %v, want %v", tc.name, tc.ip, tc.port, got, tc.wantOwns)
		}
	}
	// And the zero scope — an older platform — probes private space and, the
	// opt-in being off by default, nothing else.
	var zero Scope
	if !zero.MayProbe("10.0.0.5", 443, false) || zero.MayProbe("203.0.113.5", 443, false) {
		t.Error("zero scope must probe private space only")
	}
}

// The sanity cap (owner decision on): /0, any IPv4 prefix shorter than /8
// and any IPv6 prefix shorter than /16 is never a claim of ownership. Both
// polarities at each boundary, plus the private-space exemption.
func TestTooBroadToClaim(t *testing.T) {
	for prefix, want := range map[string]bool{
		"0.0.0.0/0":            true,
		"::/0":                 true,
		"192.0.0.0/7":          true,  // one bit short of the IPv4 floor
		"192.0.0.0/8":          false, // exactly at it
		"203.0.113.0/24":       false,
		"2001:d00::/15":        true,  // one bit short of the IPv6 floor
		"2001:db8::/16":        true,  // masks to 2001::/16, which contains all Teredo destinations
		"2001:db8::/32":        false,
		"::ffff:0.0.0.0/96":    true,  // the whole IPv4 space, spelled mapped
		"::ffff:192.0.0.0/104": false, // a mapped /8
		"::/8":                 true,  // mapped-looking but not: a /8 of IPv6
		"10.0.0.0/7":           true,  // starts private, reaches into public 11/8
		"fd00::/8":             false, // wholly ULA: owned by class, nothing to claim
		"fc00::/7":             false, // likewise
	} {
		if got := TooBroadToClaim(netip.MustParsePrefix(prefix)); got != want {
			t.Errorf("TooBroadToClaim(%s) = %v, want %v", prefix, got, want)
		}
	}
}

// A too-broad declared prefix grants nothing through Parse — whether the
// platform or a sensor's local file supplied it — while a too-broad EXCLUSION
// still excludes.
func TestTooBroadPrefixIsNotOwnership(t *testing.T) {
	s, rejected := Parse(OwnedNetworks{
		Prefixes: []string{"0.0.0.0/0", "192.0.0.0/7", "2001:d00::/15", "198.51.100.0/24"},
		Excluded: []string{"0.0.0.0/1"},
	})
	if rejected != 3 {
		t.Errorf("rejected = %d, want the three too-broad prefixes", rejected)
	}
	if s.MayProbe("192.0.2.10", 443, false) || s.MayProbe("2001:db8::1", 443, false) {
		t.Error("a destination inside only a too-broad declared prefix was probed without the opt-in")
	}
	if !s.MayProbe("198.51.100.7", 443, false) {
		t.Error("the narrow declared prefix beside them stopped counting")
	}
	if s.MayProbe("100.64.0.1", 443, true) {
		t.Error("a wide exclusion must still exclude, even with the opt-in on")
	}
}

func TestEndpointStringRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		port int
		want string
	}{
		{"198.51.100.7", 443, "198.51.100.7:443"},
		{"::ffff:198.51.100.7", 443, "198.51.100.7:443"},
		{"2001:db8::1", 8443, "[2001:db8::1]:8443"},
	} {
		got := EndpointString(tc.ip, tc.port)
		if got != tc.want {
			t.Errorf("EndpointString(%s, %d) = %q, want %q", tc.ip, tc.port, got, tc.want)
		}
		s, rejected := Parse(OwnedNetworks{Endpoints: []string{got}})
		if rejected != 0 || !s.Owns(tc.ip, tc.port) {
			t.Errorf("%q did not parse back into an owned endpoint", got)
		}
	}
}
