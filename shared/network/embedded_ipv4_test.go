package network

import (
	"net/netip"
	"testing"
)

func TestEmbeddedIPv4(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:169.254.169.254":         "169.254.169.254", // IPv4-mapped
		"::ffff:0:a9fe:a9fe":             "169.254.169.254", // SIIT
		"::a9fe:a9fe":                    "169.254.169.254", // IPv4-compatible
		"::127.0.0.1":                    "127.0.0.1",
		"64:ff9b::a9fe:a9fe":             "169.254.169.254", // NAT64 well-known
		"64:ff9b::7f00:1":                "127.0.0.1",
		"2002:a9fe:a9fe::1":              "169.254.169.254", // 6to4
		"2002:5db8:d822::":               "93.184.216.34",
		"2001:0:5db8:d822:0:0:5646:5601": "169.185.169.254", // Teredo: client = ^bits 96-127
		"2001:0:5db8:d822:0:0:80ff:fffe": "127.0.0.1",
		"2001:0:5db8:d822:0:0:a247:27de": "93.184.216.33",
		"2001:0:a9fe:a9fe::ffff:ffff":    "0.0.0.0", // the SERVER field is not returned
		"::ffff:10.0.0.1":                "10.0.0.1",
	} {
		got, ok := EmbeddedIPv4(netip.MustParseAddr(in))
		if !ok || got.String() != want {
			t.Errorf("EmbeddedIPv4(%s) = %v, %v; want %s", in, got, ok, want)
		}
	}
	for _, none := range []string{
		"::", "::1", // unspecified and loopback, not compatible-form IPv4
		"2606:2800:21f:cb07::1", "fd00::1", "fe80::1", "2001:db8::1",
		"2001:1::1",                // outside Teredo's /32
		"2003::1",                  // outside 6to4
		"64:ff9b:2::1",             // neither NAT64 prefix
		"64:ff9b:1::c000:221",      // local-use NAT64: position depends on the operator's prefix
		"64:ff9b:1:a9fe:a9:fe00::", // ...at any length, so never guessed
		"93.184.216.34",            // IPv4 embeds nothing
	} {
		if got, ok := EmbeddedIPv4(netip.MustParseAddr(none)); ok {
			t.Errorf("EmbeddedIPv4(%s) = %v, want none", none, got)
		}
	}
	if _, ok := EmbeddedIPv4(netip.Addr{}); ok {
		t.Error("EmbeddedIPv4(zero) reported an address")
	}
}

func TestEmbeddedIPv4Prefix(t *testing.T) {
	for in, want := range map[string]string{
		"2002::/16":                          "0.0.0.0/0", // every IPv4 in 6to4 form
		"2002:5d00::/24":                     "93.0.0.0/8",
		"2002:5db8:d800::/40":                "93.184.216.0/24",
		"2002:5db8:d822::/48":                "93.184.216.34/32",
		"2002:5db8:d822::/64":                "93.184.216.34/32", // bits past the IPv4 do not narrow it
		"64:ff9b::/96":                       "0.0.0.0/0",
		"64:ff9b::5d00:0/104":                "93.0.0.0/8",
		"64:ff9b::a9fe:a9fe/128":             "169.254.169.254/32",
		"::/96":                              "0.0.0.0/0", // IPv4-compatible
		"::ffff:0:0:0/96":                    "0.0.0.0/0", // SIIT
		"::ffff:0:0/96":                      "0.0.0.0/0", // IPv4-mapped
		"::ffff:93.184.216.0/120":            "93.184.216.0/24",
		"2001:0:5db8:d822::a200:0/104":       "93.0.0.0/8", // Teredo client /8 (0xa2 inverted = 0x5d)
		"2001:0:5db8:d822:0:0:a247:27de/128": "93.184.216.33/32",
	} {
		got, ok := EmbeddedIPv4Prefix(netip.MustParsePrefix(in))
		if !ok || got.String() != want {
			t.Errorf("EmbeddedIPv4Prefix(%s) = %v, %v; want %s", in, got, ok, want)
		}
	}
	for _, none := range []string{
		"64:ff9b::/32", // contains the whole NAT64 block
		"2001::/16",    // contains the whole Teredo block (and more)
		"2000::/3",     // contains 6to4 and Teredo
		"::/0",
		"2001::/32",             // shorter than Teredo's embedding offset
		"2001:0:5db8:d822::/64", // one server, every client
		"64:ff9b::/64",          // shorter than NAT64's offset
		"64:ff9b::/90",          // a few bits short of the offset
		"2001:0:5db8:d822::/92", // ...likewise for Teredo
		"64:ff9b:1::/48",        // local-use NAT64: layout unknown
		"64:ff9b:1::5d00:0/104", // ...however narrow
		"64:ff9b:1::c000:221/128",
		"2606:2800::/32",  // embeds nothing
		"93.184.216.0/24", // IPv4 embeds nothing
	} {
		if got, ok := EmbeddedIPv4Prefix(netip.MustParsePrefix(none)); ok {
			t.Errorf("EmbeddedIPv4Prefix(%s) = %v, want false", none, got)
		}
	}
	if _, ok := EmbeddedIPv4Prefix(netip.Prefix{}); ok {
		t.Error("the zero prefix embeds something")
	}
}
