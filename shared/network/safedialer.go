package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
)

// PlatformInternalCIDRsEnv is a comma-separated list of this installation's
// pod and Service CIDRs. On-premises dialers allow customer RFC1918 networks,
// so this explicit list is what keeps that narrow exception from also opening
// the platform's own cluster network.
const PlatformInternalCIDRsEnv = "VISTA_PLATFORM_INTERNAL_CIDRS"

// SSRF-hardened dialing. ValidateWebhookURL checks a URL up-front, but
// a pre-flight check has a TOCTOU gap: DNS can resolve to a public IP at
// validation time and a private/metadata IP at dial time (DNS rebinding). The
// dialer here closes that gap — its Control hook runs AFTER name resolution,
// on the concrete IP the kernel is about to connect to, and refuses any
// loopback / private / link-local / cloud-metadata address. Use it for every
// outbound request whose host is tenant-supplied (CMDB connectors, device
// probes).

// dialGuard rejects a resolved address that points at an internal IP. It is
// the net.Dialer.Control hook, invoked per candidate address right before the
// socket connects.
func dialGuard(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: unparseable address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: %q did not resolve to an IP", host)
	}
	if isPrivateIP(ip) {
		return fmt.Errorf("ssrf guard: refusing to connect to internal address %s", ip)
	}
	return nil
}

// ValidateDialAddr pre-checks a "host:port" target before a raw TCP dial,
// rejecting one that resolves to an internal IP. It gives callers a clean,
// early error for tenant-supplied probe targets; the dialer's Control hook
// still enforces the same rule at connect time (so DNS rebinding can't slip
// past this pre-flight).
func ValidateDialAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("refusing to connect to internal address %s", ip)
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("unable to resolve host %q: %w", host, err)
	}
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("host %q resolves to an internal address", host)
		}
	}
	return nil
}

// SafeDialer returns a net.Dialer that refuses connections to internal IPs at
// connect time. timeout bounds the whole dial (0 = no timeout).
func SafeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: dialGuard,
	}
}

// SafeDialContext is a DialContext function (net.Dialer.DialContext) that
// blocks internal IPs — drop-in for http.Transport.DialContext or any API
// taking a dial func.
func SafeDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return SafeDialer(timeout).DialContext
}

// SafeDialTimeout is an SSRF-guarded replacement for net.DialTimeout: it
// resolves and connects to addr but refuses internal IPs. Use it for raw TCP
// probes (e.g. the device SSH key probe) where there is no http.Client.
func SafeDialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	return SafeDialer(timeout).Dial(network, addr)
}

// SafeHTTPClient returns an *http.Client whose transport refuses connections to
// internal IPs at dial time. timeout bounds each request. Use it for outbound
// calls to tenant-supplied hosts (CMDB connectors). The transport is otherwise
// a clone of http.DefaultTransport (keep-alives, proxy-from-env, etc.).
func SafeHTTPClient(timeout time.Duration) *http.Client {
	return clientWithGuard(timeout, dialGuard)
}

// onPremDialGuard is dialGuard with the RFC1918 half lifted: an address in
// private unicast space is permitted, everything [IsNeverReachable] covers —
// loopback, link-local (and so the cloud metadata endpoints), unspecified,
// multicast — is still refused.
func onPremDialGuard(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf guard: unparseable address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf guard: %q did not resolve to an IP", host)
	}
	if IsNeverReachable(ip) {
		return fmt.Errorf("ssrf guard: refusing to connect to %s — loopback, link-local and "+
			"metadata addresses are never reachable, whatever the connector's private-endpoint setting says", ip)
	}
	return nil
}

// SafeHTTPClientAllowingPrivate returns a client for a connector whose target
// system is ON-PREMISES BY CONSTRUCTION — a NetBox, a CMDB appliance, an
// internal IPAM. It permits RFC1918/ULA/CGNAT targets and still refuses
// loopback, link-local and the cloud metadata endpoints.
//
// Use it ONLY behind a per-connection opt-in that the tenant set and that is
// recorded in the audit log. The distinction it draws matters: pointing us at
// 10.0.0.5 reaches the tenant's own network, which is the entire point of an
// on-premises connector; pointing us at 127.0.0.1 or 169.254.169.254 reaches
// OUR cluster, which is never the point.
func SafeHTTPClientAllowingPrivate(timeout time.Duration) *http.Client {
	return clientWithGuard(timeout, configuredOnPremDialGuard())
}

// OnPremDialContext is [SafeHTTPClientAllowingPrivate]'s guard as a bare
// DialContext function, for a caller that must build its own http.Transport
// rather than take the one above.
//
// Device interrogation is that caller: every appliance client sets a per-device
// TLSClientConfig (InsecureSkipVerify is a per-device opt-in for self-signed
// management certs), so it cannot use a prebuilt client — but it needs exactly
// the same address policy. Handing out the guard rather than a second copy of
// it means widening or narrowing [IsNeverReachable] moves both.
//
// The rule it carries is the one that makes an on-premises product possible at
// all: reaching 10.0.0.5 IS the job, reaching 127.0.0.1 or 169.254.169.254
// never is.
func OnPremDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: timeout, Control: configuredOnPremDialGuard()}).DialContext
}

func configuredOnPremDialGuard() func(string, string, syscall.RawConn) error {
	prefixes, configErr := platformInternalPrefixes(os.Getenv(PlatformInternalCIDRsEnv))
	return func(network, address string, rawConn syscall.RawConn) error {
		if configErr != nil {
			return configErr
		}
		if err := onPremDialGuard(network, address, rawConn); err != nil {
			return err
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("ssrf guard: unparseable address %q: %w", address, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("ssrf guard: %q did not resolve to an IP", host)
		}
		addr = addr.Unmap()
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				return fmt.Errorf("ssrf guard: refusing to connect to platform-internal address %s (matched %s)", addr, prefix)
			}
		}
		return nil
	}
}

func platformInternalPrefixes(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("ssrf guard: invalid %s entry %q: %w", PlatformInternalCIDRsEnv, raw, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func clientWithGuard(timeout time.Duration, guard func(string, string, syscall.RawConn) error) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	// NOTE: the transport keeps proxy-from-env, which is the behaviour every
	// existing caller has had since. It is worth knowing that an
	// HTTP(S)_PROXY in the environment makes the dialer connect to the PROXY,
	// so the Control hook then inspects the proxy's address rather than the
	// target's — the guard still runs, but on a different question. No
	// deployment sets one today; changing it here would change egress for five
	// shipped connectors, which is a decision of its own and not this one.
	base.DialContext = (&net.Dialer{Timeout: timeout, Control: guard}).DialContext
	return &http.Client{
		Timeout:   timeout,
		Transport: base,
	}
}
