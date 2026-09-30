package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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

// SafeHTTPClient returns an *http.Client that refuses internal targets:
// loopback, link-local/metadata, RFC1918/ULA/CGNAT and the configured platform
// CIDRs (PlatformInternalCIDRsEnv). timeout bounds each request.
//
// It is NewEgressClient(timeout, EgressOptions{}) — public targets, system
// trust store — for the callers that predate the per-connection options. It
// honours HTTP(S)_PROXY / NO_PROXY and, behind a proxy, judges the TARGET
// rather than the proxy (see checkProxiedTarget). New integration code should
// call [NewEgressClient] so the tenant's private-endpoint and CA-bundle
// settings have somewhere to go.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	return buildEgressClient(timeout, newTargetPolicy(false), nil, egressDeps{})
}

// OnPremDialContext is the private-endpoint guard of [NewEgressClient]
// (EgressOptions.AllowPrivateEndpoint) as a bare DialContext function, for a
// caller that must build its own http.Transport rather than take that client.
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

// configuredOnPremDialGuard is the private-endpoint target policy, with the
// platform CIDRs read from PlatformInternalCIDRsEnv now, as a Control hook. It
// is the same targetPolicy the egress client uses, not a second copy of it.
func configuredOnPremDialGuard() func(string, string, syscall.RawConn) error {
	return newTargetPolicy(true).control
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
