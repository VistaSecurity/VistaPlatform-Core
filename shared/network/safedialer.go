package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

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
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = SafeDialContext(timeout)
	return &http.Client{
		Timeout:   timeout,
		Transport: base,
	}
}
