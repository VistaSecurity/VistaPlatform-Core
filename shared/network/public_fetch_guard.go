package network

import (
	"fmt"
	"net"
	"net/netip"
)

// PublicFetchGuard returns the address rule for an HTTP fetch that a REMOTE
// PARTY'S DATA asks for — today the OCSP responder named in a probed server's
// certificate — as a func(netip.Addr) error, the shape of
// shared/discovery.AddressGuard.
//
// It is the public-targets policy of SafeDialer and SafeHTTPClient (no
// loopback, link-local/metadata, RFC 1918, ULA, carrier NAT, multicast, or the
// configured platform CIDRs; a malformed platform CIDR list refuses
// everything), plus the IPv6 forms that lead to a refused IPv4 address. A
// probed device does not get to point an outbound fetch at the network the
// prober runs in — which, for device interrogation, may be the platform's own
// cluster.
//
// The platform CIDRs are read once, when the guard is built.
func PublicFetchGuard() func(netip.Addr) error {
	policy := newTargetPolicy(false)
	var guard func(netip.Addr) error
	guard = func(addr netip.Addr) error {
		addr = addr.WithZone("")
		if !addr.IsValid() {
			return fmt.Errorf("ssrf guard: not an address")
		}
		if v4, ok := EmbeddedIPv4(addr); ok {
			if err := guard(v4); err != nil {
				return fmt.Errorf("%s carries %s: %w", addr, v4, err)
			}
		}
		return policy.checkIP(net.IP(addr.Unmap().AsSlice()))
	}
	return guard
}
