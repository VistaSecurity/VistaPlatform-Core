package network

import (
	"net/netip"
	"testing"
)

func TestTooBroadToClaim(t *testing.T) {
	for prefix, want := range map[string]bool{
		// The bound, both directions.
		"0.0.0.0/0":       true,
		"12.0.0.0/7":      true,
		"93.0.0.0/8":      false,
		"93.184.216.0/24": false,
		"::/0":            true,
		"2600::/15":       true,
		"2606::/16":       false,
		"2606:2800::/32":  false,
		// Private space is exempt however wide — it widens nothing.
		"10.0.0.0/8":    false,
		"172.16.0.0/12": false,
		"fc00::/7":      false, // all of ULA
		"fd00::/8":      false,
		"fe80::/10":     false, // link-local
		"127.0.0.0/8":   false,
		// ...but not a prefix that merely STARTS in private space.
		"10.0.0.0/7": true, // 10.0.0.0–11.255.255.255
		"fc00::/6":   true,
		// IPv6 blocks that embed IPv4 are as broad as the IPv4 space they
		// carry (review N6): 2002::/16 is 0.0.0.0/0 in 6to4 form.
		"2002::/16":                    true,
		"2002:5d00::/24":               false, // = 93.0.0.0/8
		"2002:5c00::/23":               true,  // = 92.0.0.0/7
		"2002:5db8:d822::/48":          false, // = 93.184.216.34/32
		"2001::/32":                    true,  // all of Teredo
		"2001:0:5db8:d822::/64":        true,  // one server, every client
		"2001:0:5db8:d822::a200:0/104": false, // client /8
		"64:ff9b::/96":                 true,
		"64:ff9b::5d00:0/104":          false, // = 93.0.0.0/8
		"64:ff9b:1::/48":               true,
		"64:ff9b:1:5d00::/56":          true, // local-use: layout unknown
		"64:ff9b:1::5d00:0/104":        true, // even narrow: the position is the operator's choice
		"::/96":                        true, // IPv4-compatible
		"::ffff:0:0:0/96":              true, // SIIT
		"64:ff9b::/32":                 true, // contains the whole NAT64 block
		"2001::/16":                    true, // contains Teredo
		"2000::/15":                    true, // contains 2002::/16 and 2001::/32
		// Mapped prefixes are judged as the IPv4 they name.
		"::ffff:0:0/96":       true,  // = 0.0.0.0/0
		"::ffff:93.0.0.0/104": false, // = 93.0.0.0/8
		"::ffff:0:0/95":       true,  // reaches outside the mapped space
	} {
		if got := TooBroadToClaim(netip.MustParsePrefix(prefix)); got != want {
			t.Errorf("TooBroadToClaim(%s) = %v, want %v", prefix, got, want)
		}
	}
	if !TooBroadToClaim(netip.Prefix{}) {
		t.Error("the zero prefix is not too broad")
	}
}
