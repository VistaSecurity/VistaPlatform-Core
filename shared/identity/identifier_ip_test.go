package identity

import "testing"

// TestNormalizeRejectsAnIPAsAName is gate 1 B11.
//
// `dnsAllowed` accepts digits and dots, so "192.0.2.10" passed every check and —
// having two labels — was accepted as an FQDN. Every builder that put "the
// host" into a DNS kind therefore produced a SECOND identifier row for an
// address that was already an ip_address: two rows, one host, and no proposal to
// say so. Worse, the two kinds sit at different points in the precedence list,
// so an fqdn spelled as an address could decide a match the identical
// ip_address was forbidden to decide inside a dynamic segment — the DHCP rule,
// evaded by choosing the other kind.
func TestNormalizeRejectsAnIPAsAName(t *testing.T) {
	for _, v := range []string{
		"192.0.2.10", "198.51.100.1", "203.0.113.255",
		"2001:db8::1", "::1", "fe80::1",
	} {
		for _, kind := range []Kind{KindFQDN, KindHostname} {
			if got, err := Normalize(kind, v); err == nil {
				t.Errorf("Normalize(%s, %q) = %q, nil — an IP address is not a name, and accepting one "+
					"here mints a second identifier row for a host that already has an ip_address",
					kind, v, got)
			}
		}
	}

	// The other polarity: names that merely LOOK numeric are still names.
	// Rejecting these would silently drop real identifiers, which is the same
	// bug pointed the other way.
	for _, v := range []string{"192-0-2-10.example.test", "0000.example.test", "10.example.test"} {
		if _, err := Normalize(KindFQDN, v); err != nil {
			t.Errorf("Normalize(fqdn, %q) = %v; a numeric-looking NAME is still a name", v, err)
		}
	}
	for _, v := range []string{"host1", "10-1-2-3", "printer-2"} {
		if _, err := Normalize(KindHostname, v); err != nil {
			t.Errorf("Normalize(hostname, %q) = %v; a numeric-looking NAME is still a name", v, err)
		}
	}
}
