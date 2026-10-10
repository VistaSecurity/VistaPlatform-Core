package addrscope

import (
	"math/rand"
	"net"
	"net/netip"
	"testing"
)

func TestClassifyString(t *testing.T) {
	cases := []struct {
		in   string
		want Scope
	}{
		// RFC 1918, including both edges of each block.
		{"10.0.0.0", Private},
		{"10.255.255.255", Private},
		{"172.16.0.1", Private},
		{"172.31.255.255", Private},
		{"172.32.0.1", Public},
		{"172.15.255.255", Public},
		{"192.168.1.1", Private},
		{"192.169.0.1", Public},
		// IPv6 unique local, loopback, link-local.
		{"fd00::1", Private},
		{"fc00::1", Private},
		{"fe00::1", Public},
		{"127.0.0.1", Private},
		{"::1", Private},
		{"169.254.10.1", Private},
		{"fe80::1", Private},
		// Normalization: zone stripped, mapped unmapped, whitespace trimmed.
		{"fe80::1%eth0", Private},
		{"::ffff:10.1.2.3", Private},
		{"::ffff:100.64.0.1", CGNAT},
		{"  192.168.0.5\t", Private},
		// RFC 6598, both edges, and just outside.
		{"100.64.0.0", CGNAT},
		{"100.127.255.255", CGNAT},
		{"100.63.255.255", Public},
		{"100.128.0.0", Public},
		// Documentation ranges are public: not routable is not the tenant's.
		{"192.0.2.10", Public},
		{"198.51.100.7", Public},
		{"203.0.113.9", Public},
		{"2001:db8::1", Public},
		// Neither multicast nor unspecified is private by address class.
		{"224.0.0.1", Public},
		{"ff02::1", Public},
		{"0.0.0.0", Public},
		{"8.8.8.8", Public},
		// Not addresses.
		{"", Invalid},
		{"   ", Invalid},
		{"example.com", Invalid},
		{"10.0.0.0/8", Invalid},
		{"10.0.0.1:443", Invalid},
	}
	for _, tc := range cases {
		if got := ClassifyString(tc.in); got != tc.want {
			t.Errorf("ClassifyString(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestDerivedPredicates(t *testing.T) {
	cases := []struct {
		in                    string
		addressable, autoProb bool
	}{
		{"10.1.2.3", true, true},
		{"fd12::1", true, true},
		{"127.0.0.1", true, true},
		{"169.254.1.1", true, true},
		// D1: CGNAT is an internal candidate but NOT auto-probed on address
		// class alone.
		{"100.64.1.1", true, false},
		{"203.0.113.5", false, false},
		{"2001:db8::5", false, false},
	}
	for _, tc := range cases {
		a := netip.MustParseAddr(tc.in)
		if got := IsTenantAddressable(a); got != tc.addressable {
			t.Errorf("IsTenantAddressable(%s) = %v, want %v", tc.in, got, tc.addressable)
		}
		if got := MayAutoProbe(a); got != tc.autoProb {
			t.Errorf("MayAutoProbe(%s) = %v, want %v", tc.in, got, tc.autoProb)
		}
	}
	if IsTenantAddressable(netip.Addr{}) || MayAutoProbe(netip.Addr{}) {
		t.Error("the zero Addr must be neither addressable nor probeable")
	}
}

// The prefix table must say exactly what the standard library's IsPrivate
// says (RFC 1918 + RFC 4193), and Private must be exactly the union every
// replaced copy wrote by hand. Random addresses, both families, plus mapped.
func TestMatchesStandardLibraryDefinition(t *testing.T) {
	r := rand.New(rand.NewSource(2374))
	check := func(a netip.Addr) {
		u := a.Unmap()
		if got, want := IsPrivateRange(a), u.IsPrivate(); got != want {
			t.Fatalf("IsPrivateRange(%s) = %v, netip IsPrivate = %v", a, got, want)
		}
		wantPrivate := u.IsPrivate() || u.IsLoopback() || u.IsLinkLocalUnicast()
		if got := Classify(a) == Private; got != wantPrivate {
			t.Fatalf("Classify(%s) private = %v, want %v", a, got, wantPrivate)
		}
		if ip := net.IP(a.AsSlice()); ClassifyIP(ip) != Classify(a) {
			t.Fatalf("ClassifyIP(%s) disagrees with Classify", a)
		}
	}
	for i := 0; i < 200000; i++ {
		var b4 [4]byte
		r.Read(b4[:])
		a4 := netip.AddrFrom4(b4)
		check(a4)
		check(netip.AddrFrom16(a4.As16()))
		var b16 [16]byte
		r.Read(b16[:])
		// Bias a quarter of the IPv6 draws into fc00::/7 and fe80::/10.
		switch i % 4 {
		case 1:
			b16[0] = 0xfc | (b16[0] & 1)
		case 2:
			b16[0], b16[1] = 0xfe, 0x80|(b16[1]&0x3f)
		}
		check(netip.AddrFrom16(b16))
	}
}

func TestPrivateRangesIsACopy(t *testing.T) {
	r := PrivateRanges()
	r[0] = netip.MustParsePrefix("203.0.113.0/24")
	if ClassifyString("203.0.113.1") != Public || ClassifyString("10.0.0.1") != Private {
		t.Fatal("editing PrivateRanges' result changed the definition")
	}
	if CGNATRange().String() != "100.64.0.0/10" {
		t.Fatalf("CGNATRange = %s", CGNATRange())
	}
}

func TestClassifyIPInvalid(t *testing.T) {
	if ClassifyIP(nil) != Invalid || ClassifyIP(net.IP{1, 2, 3}) != Invalid {
		t.Fatal("nil and malformed net.IP must be Invalid")
	}
}
