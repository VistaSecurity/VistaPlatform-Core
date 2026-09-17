package postgres

import "testing"

// nullInet's job is to keep one bad address from failing a whole batch. It did
// not do that for a zoned IPv6 address, because Go and Postgres disagree about
// whether one is valid: netip parses `fe80::1%6`, `inet` rejects it (22P02),
// and the failure landed on the statement rather than on the value.
//
// The zoned cases below are the regression. They are unit-level because they
// pin the returned VALUE; that a Postgres inet column then accepts it is the
// separate claim, and TestIntegration_UpsertEndpoints_ZonedLinkLocalAddress
// makes it against a real database.
func TestNullInetStripsIPv6Zones(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want any
	}{
		{"windows interface index", "fe80::dd63:32d5:6809:dde3%6", "fe80::dd63:32d5:6809:dde3"},
		{"linux interface name", "fe80::1%eth0", "fe80::1"},
		{"plain v6 is untouched", "2001:db8::1", "2001:db8::1"},
		{"plain v4 is untouched", "192.0.2.10", "192.0.2.10"},
		{"prefix is kept as a prefix", "192.0.2.0/24", "192.0.2.0/24"},
		{"surrounding space", "  192.0.2.10  ", "192.0.2.10"},
		{"empty is null", "", nil},
		{"unparseable is null", "not-an-address", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nullInet(tc.in); got != tc.want {
				t.Errorf("nullInet(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
