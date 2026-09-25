package dispatchguard

import (
	"fmt"
	"net/netip"

	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

// PlatformFetchGuard is the address guard for fetches a platform runtime makes
// because a SCANNED SERVER'S data asked for them — the OCSP responder named in
// a certificate (shared/discovery/outbound.go, W5.13b review B1).
//
// It allows only PUBLIC addresses: everything the manual scan path would call
// "external". Refused are the reserved prefixes and the platform's own
// addresses (the same lists, and the same 6to4/Teredo/mapped handling, as scan
// authorization — nothing is copied), and — unlike a scan a person asks for —
// RFC 1918 / ULA space too. Inside a cluster, private space IS the cluster:
// its Pod and Service CIDRs, which the process cannot discover and an operator
// may never have listed in DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS. A certificate
// does not get to point the platform at it. The cost is that a private PKI's
// OCSP responder is not queried from the platform (its status reads as "not
// checked"); a tenant sensor on that network still queries it.
func PlatformFetchGuard() func(netip.Addr) error {
	scope := TargetScope{excluded: append(append([]netip.Prefix{}, reservedPrefixes...), autoscan.PlatformExcludedPrefixes()...)}
	return scope.fetchGuard
}

func (s TargetScope) fetchGuard(addr netip.Addr) error {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return fmt.Errorf("not an address")
	}
	// An IPv6 form that leads to an IPv4 address (6to4, Teredo, ...) is only
	// as fetchable as that IPv4 address — private space included, which
	// classify alone does not check for the embedded address (review N5).
	if v4, ok := network.EmbeddedIPv4(addr); ok {
		if err := s.fetchGuard(v4); err != nil {
			return fmt.Errorf("%s carries %s: %w", addr, v4, err)
		}
	}
	switch class, why := s.classify(addr, addr); class {
	case classExternal:
		return nil
	case classExcluded:
		return fmt.Errorf("%s is never fetched from the platform: %s", addr, why)
	default:
		return fmt.Errorf("%s is private address space, which from inside the platform is the platform's own network", addr)
	}
}
