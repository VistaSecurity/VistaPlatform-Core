package discovery

// Outbound fetches a probe makes because a SCANNED SERVER told it to.
//
// Certificate validation queries the OCSP responder named in the server's own
// certificate. That URL is attacker-controlled data: a host being scanned can
// name any address — or a public responder that redirects to one — and the
// prober will send it an HTTP request. From inside a platform cluster that
// reaches the cloud instance-metadata service, loopback and every in-cluster
// Service ( W5.13b, security review of, B1).
//
// This package stays free of platform code: it does not know which addresses
// are the platform's. A runtime that must not be steered inward — the in-cluster
// Platform Sensor, device interrogation — supplies an AddressGuard, and every
// such fetch then goes through GuardedHTTPClient:
//
//   - the guard is applied in the dialer's Control hook, to the address the
//     socket is ACTUALLY connecting to, after DNS — so a name that resolves (or
//     rebinds) to a refused address is refused, not just a literal;
//   - redirects are never followed (a 302 to an internal URL is the attack);
//   - no proxy from the environment, which would move the connect target out
//     of the guard's sight.
//
// The standalone sensor runs on the customer's own network and keeps the
// default client: its "inward" is the network it was deployed to scan.
//
// Audit of every other HTTP fetch a probe could make from cert- or
// server-supplied data (AIA caIssuers chasing, CRL distribution points, HTTP
// banner redirects): none exists in shared/discovery or cluster-sensor-service
// today — OCSP is the only one. A new one must take its client from
// Prober.OutboundHTTPClient.

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// AddressGuard returns a non-nil error for an address the caller's runtime must
// never open a connection to on a scanned server's say-so.
type AddressGuard func(netip.Addr) error

// OutboundFetchTimeout bounds one such fetch (an OCSP round-trip).
const OutboundFetchTimeout = ocspTimeout

// ErrOutboundAddressRefused wraps every guard refusal.
var ErrOutboundAddressRefused = errors.New("outbound fetch to this address is refused")

// GuardedHTTPClient is an http.Client that connects only to addresses guard
// allows and never follows a redirect.
func GuardedHTTPClient(guard AddressGuard, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrOutboundAddressRefused, err)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: %q is not an address", ErrOutboundAddressRefused, host)
			}
			if err := guard(addr.Unmap().WithZone("")); err != nil {
				return fmt.Errorf("%w: %v", ErrOutboundAddressRefused, err)
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
		MaxIdleConns:        1,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// WithOutboundAddressGuard returns a copy of p whose certificate-driven fetches
// (OCSP today) go through GuardedHTTPClient(guard). A platform runtime MUST use
// it; see the package comment above.
func (p *Prober) WithOutboundAddressGuard(guard AddressGuard) *Prober {
	c := *p
	c.outboundClient = GuardedHTTPClient(guard, ocspTimeout)
	return &c
}

// OutboundHTTPClient is the client for fetches a scanned server's data asks
// for. Nil means the default (unguarded) client — the standalone sensor.
func (p *Prober) OutboundHTTPClient() *http.Client { return p.outboundClient }
