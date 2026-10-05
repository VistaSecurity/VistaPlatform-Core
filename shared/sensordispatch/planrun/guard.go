package planrun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// ErrForbiddenAddress wraps every refusal of the sensor's own rules.
var ErrForbiddenAddress = errors.New("address refused by the sensor's own rules")

// SensorRule is the standalone sensor's own judgement of an address a planned
// scan may touch, over the owned-network scope the platform delivers on every
// heartbeat (probeconsent; the scope the TLS enricher already decides by).
// The platform authorized every address before dispatch; this is the sensor
// refusing to be the tool that scans what its own view of the tenant says it
// must not, whatever a command says:
//
//   - never the reserved ranges a scan has no business in: unspecified,
//     loopback (the sensor's own host), link-local (cloud metadata lives
//     there), multicast, limited broadcast;
//   - never inside a prefix the tenant excluded (a sensitive or
//     probes-disabled segment, an automatic-scan exclusion) — an exclusion
//     beats everything;
//   - only an address the scope says is the tenant's: private space, or a
//     prefix the tenant declared. A dispatched scan never carries anything
//     else (external targets run from the platform only), so a refusal here
//     means the sensor's view and the command disagree, and the sensor's view
//     wins.
//
// scope is read on every call, so an exclusion delivered mid-scan stops the
// hosts not yet started.
func SensorRule(scope func() probeconsent.Scope) func(netip.Addr) error {
	return func(a netip.Addr) error {
		a = a.Unmap()
		switch {
		case !a.IsValid():
			return fmt.Errorf("%w: not an address", ErrForbiddenAddress)
		case a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
			a.IsInterfaceLocalMulticast(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
			return fmt.Errorf("%w: %s is a reserved address", ErrForbiddenAddress, a)
		}
		if !scope().Owns(a.String(), 0) {
			return fmt.Errorf("%w: %s is excluded from probing, or is not inside the networks this tenant owns as this sensor last heard them", ErrForbiddenAddress, a)
		}
		return nil
	}
}

// guardedDialer refuses, before any packet, a dial to an address allow
// refuses.
type guardedDialer struct {
	inner discovery.Dialer
	allow func(netip.Addr) error
}

// GuardedDialer wraps d so that every connection the engine opens — liveness,
// port scan, identification, UDP — is to an address allow accepts. The run
// also asks allow before each host; this is the backstop for a rule that
// changed while a host was in flight, and for any path that might dial
// something the run did not hand it.
func GuardedDialer(d discovery.Dialer, allow func(netip.Addr) error) discovery.Dialer {
	return &guardedDialer{inner: d, allow: allow}
}

func (g *guardedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a literal address", ErrForbiddenAddress, address)
	}
	if err := g.allow(ap.Addr()); err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	return g.inner.DialContext(ctx, network, address)
}
