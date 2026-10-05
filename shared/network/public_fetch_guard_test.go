package network

import (
	"net/netip"
	"testing"
)

// Both polarities: a public responder is fetchable, every internal shape —
// including an IPv6 form leading to one and a configured platform CIDR — is
// not.
func TestPublicFetchGuard(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "198.51.100.0/24")
	guard := PublicFetchGuard()

	for _, s := range []string{"203.0.113.7", "2001:db8::1", "8.8.8.8"} {
		if err := guard(netip.MustParseAddr(s)); err != nil {
			t.Errorf("guard(%s) = %v, want allowed", s, err)
		}
	}
	for _, s := range []string{
		"127.0.0.1", "::1", "0.0.0.0", "169.254.169.254", "fe80::1",
		"10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fd00::1", "224.0.0.1",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::",
		"198.51.100.20", // platform CIDR
	} {
		if err := guard(netip.MustParseAddr(s)); err == nil {
			t.Errorf("guard(%s) allowed, want refused", s)
		}
	}
}

// A malformed platform CIDR list must not quietly degrade to "no platform
// CIDRs": the guard refuses everything.
func TestPublicFetchGuard_MalformedPlatformCIDRsFailClosed(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "not-a-cidr")
	if err := PublicFetchGuard()(netip.MustParseAddr("203.0.113.7")); err == nil {
		t.Fatal("public address allowed under a malformed platform CIDR list, want refused")
	}
}
