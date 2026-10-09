package derive

import (
	"net/netip"
	"regexp"
	"testing"
)

func TestMACFromEUI64(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantMAC string
		wantOK  bool
	}{
		// RFC 4291 Appendix A: the IID's U/L bit is the inverse of the MAC's.
		// IID first octet 0x02 -> MAC first octet 0x00 (universal).
		{"ULA, flip back to universal", "fd00::0211:22ff:fe33:4455", "00:11:22:33:44:55", true},
		{"GUA documentation prefix", "2001:db8::0211:22ff:fe33:4455", "00:11:22:33:44:55", true},
		{"link-local", "fe80::0211:22ff:fe33:4455", "00:11:22:33:44:55", true},
		{"link-local with zone", "fe80::a2b2:c3ff:fed4:e5f6%eth0", "a0:b2:c3:d4:e5:f6", true},
		{"upper-case hex in the IID is emitted lower-case", "fd00::A2B2:C3FF:FED4:E5F6", "a0:b2:c3:d4:e5:f6", true},
		{"IID first octet 0x00 means MAC first octet 0x02: locally administered", "fd00::0011:22ff:fe33:4455", "", false},
		{"IID first octet 0xff means MAC 0xfd: multicast", "fd00::ff11:22ff:fe33:4455", "", false},
		{"IID first octet 0x03 means MAC 0x01: multicast", "fd00::0311:22ff:fe33:4455", "", false},
		{"IID first octet 0x02 with zero rest means all-zero MAC", "fd00::0200:00ff:fe00:0000", "", false},
		{"all-zero IID is not EUI-64", "fd00::", "", false},
		{"RFC 8981 style random IID", "fd00::1234:5678:9abc:def0", "", false},
		{"only 0xfe in byte 12", "fd00::0211:22aa:fe33:4455", "", false},
		{"only 0xff in byte 11", "fd00::0211:22ff:aa33:4455", "", false},
		{"ff fe shifted one byte", "fd00::0211:2233:fffe:4455", "", false},
		{"IPv4", "192.0.2.10", "", false},
		{"IPv4-mapped IPv6", "::ffff:192.0.2.10", "", false},
		// Bytes 11 and 12 are ff fe here, so without the IPv4-mapped guard this
		// would pass the shape test and return a MAC for what is an IPv4 host.
		{"IPv4-mapped whose bytes 11-12 are ff fe", "::ffff:254.1.2.3", "", false},
		// EUI-64 shaped, but the MAC under it is locally administered (0x02).
		{"EUI-64 shape over a locally administered MAC", "::ff:fe00:1", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("bad test vector %q: %v", tc.addr, err)
			}
			mac, ok := MACFromEUI64(addr)
			if ok != tc.wantOK || mac != tc.wantMAC {
				t.Fatalf("MACFromEUI64(%s) = %q, %v; want %q, %v", tc.addr, mac, ok, tc.wantMAC, tc.wantOK)
			}
		})
	}
}

func TestMACFromEUI64_ZeroAddr(t *testing.T) {
	if mac, ok := MACFromEUI64(netip.Addr{}); ok || mac != "" {
		t.Fatalf("invalid Addr: got %q, %v", mac, ok)
	}
	if IsEUI64(netip.Addr{}) {
		t.Fatal("invalid Addr must not be EUI-64")
	}
}

func TestIsEUI64(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"fd00::0211:22ff:fe33:4455", true},
		{"fe80::0211:22ff:fe33:4455", true},
		// Shape only: the MAC under this one is locally administered, so
		// MACFromEUI64 refuses it, but it is still an EUI-64 address and not a
		// temporary one.
		{"fd00::0011:22ff:fe33:4455", true},
		{"fd00::1234:5678:9abc:def0", false},
		{"fd00::1", false},
		{"192.0.2.10", false},
		{"::ffff:192.0.2.10", false},
		{"::ffff:254.1.2.3", false},
	}
	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			if got := IsEUI64(netip.MustParseAddr(tc.addr)); got != tc.want {
				t.Fatalf("IsEUI64(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestMACFromSerial(t *testing.T) {
	all := func(string) bool { return true }
	none := func(string) bool { return false }
	tests := []struct {
		name       string
		serial     string
		registered func(string) bool
		wantMAC    string
		wantOK     bool
	}{
		{"bare 12 hex upper-case", "00AABBCCDDEE", all, "00:aa:bb:cc:dd:ee", true},
		{"bare 12 hex lower-case", "00aabbccddee", all, "00:aa:bb:cc:dd:ee", true},
		{"mixed case", "00aAbBcCdDeE", all, "00:aa:bb:cc:dd:ee", true},
		{"surrounding whitespace trimmed", "  00AABBCCDDEE\t\n", all, "00:aa:bb:cc:dd:ee", true},
		{"11 chars", "00AABBCCDDE", all, "", false},
		{"13 chars", "00AABBCCDDEEF", all, "", false},
		{"empty", "", all, "", false},
		{"whitespace only", "   ", all, "", false},
		{"non-hex letter", "00AABBCCDDEG", all, "", false},
		{"non-hex first char", "G0AABBCCDDEE", all, "", false},
		{"colon separated", "00:aa:bb:cc:dd:ee", all, "", false},
		{"dash separated", "00-AA-BB-CC-DD-EE", all, "", false},
		{"dotted", "00aa.bbcc.ddee", all, "", false},
		{"interior space", "00AABB CCDDEE", all, "", false},
		{"12 chars but a multi-byte rune", "00AABBCCDDé", all, "", false},
		{"multicast first octet", "01AABBCCDDEE", all, "", false},
		{"multicast, broadcast", "FFFFFFFFFFFF", all, "", false},
		{"locally administered first octet", "02AABBCCDDEE", all, "", false},
		{"locally administered, 0xfe", "FEAABBCCDDEE", all, "", false},
		{"all zero", "000000000000", all, "", false},
		{"OUI not registered", "00AABBCCDDEE", none, "", false},
		{"nil registry never derives", "00AABBCCDDEE", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mac, ok := MACFromSerial(tc.serial, tc.registered)
			if ok != tc.wantOK || mac != tc.wantMAC {
				t.Fatalf("MACFromSerial(%q) = %q, %v; want %q, %v", tc.serial, mac, ok, tc.wantMAC, tc.wantOK)
			}
		})
	}
}

// The registry function must be handed the OUI in the exact form the table
// keys use, or every lookup silently misses.
func TestMACFromSerial_PassesLowerCaseOUI(t *testing.T) {
	var got string
	// 0xaa is locally administered, so this is refused before the registry is
	// ever asked.
	mac, ok := MACFromSerial("AABBCCDDEEFF", func(oui string) bool { got = oui; return true })
	if ok || mac != "" {
		t.Fatalf("locally administered serial derived %q", mac)
	}
	if got != "" {
		t.Fatalf("registry consulted for a refused MAC (%q); cheap refusals must come first", got)
	}
	// 0xa8 is universal unicast, so the registry is consulted.
	mac, ok = MACFromSerial("A8BBCCDDEEFF", func(oui string) bool { got = oui; return true })
	if !ok || mac != "a8:bb:cc:dd:ee:ff" {
		t.Fatalf("got %q, %v", mac, ok)
	}
	if got != "a8:bb:cc" {
		t.Fatalf("registry asked about %q, want the lower-case form %q", got, "a8:bb:cc")
	}
}

func TestMACFromSerialRegistered(t *testing.T) {
	tests := []struct {
		name    string
		serial  string
		wantMAC string
		wantOK  bool
	}{
		// 00:00:0c is a long-standing Cisco prefix.
		{"registered OUI", "00000C1A2B3C", "00:00:0c:1a:2b:3c", true},
		{"registered OUI, lower-case", "00000c1a2b3c", "00:00:0c:1a:2b:3c", true},
		// 00:b4:63 (Ring) is in the IEEE registry but was never in the old
		// curated table: the full registry is what this now consults.
		{"registered OUI outside the old curated table", "00B46312AB34", "00:b4:63:12:ab:34", true},
		// 00:ab:12 is not assigned in the IEEE registry. (The old curated
		// table's case, 00:11:22, is assigned — to CIMSYS Inc — and so now
		// derives, correctly: the registry says it is a manufacturer's prefix.)
		{"unlisted OUI", "00AB123344 55", "", false},
		{"unlisted OUI, bare", "00AB12334455", "", false},
		{"numeric part number", "123456789012", "", false},
		{"registered OUI but locally administered", "02000C1A2B3C", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mac, ok := MACFromSerialRegistered(tc.serial)
			if ok != tc.wantOK || mac != tc.wantMAC {
				t.Fatalf("MACFromSerialRegistered(%q) = %q, %v; want %q, %v", tc.serial, mac, ok, tc.wantMAC, tc.wantOK)
			}
		})
	}
}

var canonicalMAC = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

func assertCanonical(t *testing.T, mac string) {
	t.Helper()
	if !canonicalMAC.MatchString(mac) {
		t.Fatalf("%q is not lower-case aa:bb:cc:dd:ee:ff", mac)
	}
}

// eui64IID rebuilds the 8-byte modified EUI-64 interface identifier for a MAC:
// insert ff:fe in the middle and invert the U/L bit (RFC 4291 Appendix A). It
// is written independently of the code under test.
func eui64IID(mac [6]byte) [8]byte {
	return [8]byte{mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

func parseMAC(t *testing.T, s string) [6]byte {
	t.Helper()
	var m [6]byte
	for i := 0; i < 6; i++ {
		hi, ok1 := hexVal(s[3*i])
		lo, ok2 := hexVal(s[3*i+1])
		if !ok1 || !ok2 {
			t.Fatalf("derived MAC %q is not hex", s)
		}
		m[i] = hi<<4 | lo
	}
	return m
}

func FuzzMACFromEUI64(f *testing.F) {
	for _, s := range []string{
		"fd00::0211:22ff:fe33:4455",
		"fe80::a2b2:c3ff:fed4:e5f6",
		"fd00::0011:22ff:fe33:4455",
		"fd00::1234:5678:9abc:def0",
		"192.0.2.10",
		"::ffff:192.0.2.10",
	} {
		a := netip.MustParseAddr(s).As16()
		f.Add(a[:])
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) != 16 {
			return
		}
		addr := netip.AddrFrom16([16]byte(raw))
		mac, ok := MACFromEUI64(addr)
		if !ok {
			if mac != "" {
				t.Fatalf("refused but returned %q", mac)
			}
			return
		}
		if !IsEUI64(addr) {
			t.Fatalf("%s: ok result for a non-EUI-64 address", addr)
		}
		if addr.Is4In6() {
			t.Fatalf("%s: ok result for an IPv4-mapped address", addr)
		}
		m := parseMAC(t, mac)
		if m[0]&0x03 != 0 {
			t.Fatalf("%s -> %s: multicast or locally administered MAC accepted", addr, mac)
		}
		if m == [6]byte{} {
			t.Fatalf("%s: all-zero MAC accepted", addr)
		}
		assertCanonical(t, mac)
		// Round trip: rebuilding the IID from the MAC gives back the input IID.
		want := eui64IID(m)
		b := addr.As16()
		if [8]byte(b[8:]) != want {
			t.Fatalf("%s -> %s: rebuilt IID % x, input IID % x", addr, mac, want, b[8:])
		}
	})
}
