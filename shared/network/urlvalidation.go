package network

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrUnresolvableHost reports that a URL's hostname could not be resolved.
//
// It is deliberately distinguishable from the policy rejections this validator
// also returns (bad scheme, private/internal address). Those are properties of
// the URL and stay true; a resolution failure may be a DNS blip. Callers that
// retry — notification-service's delivery retry queue — must not treat a
// transient DNS outage as a permanent "this webhook is invalid" verdict and
// drop the delivery.
var ErrUnresolvableHost = errors.New("unable to resolve hostname")

// ValidateWebhookURL checks that a URL is safe to make requests to,
// rejecting private/internal IP addresses to prevent SSRF attacks.
func ValidateWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow http and https schemes
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: %s", parsed.Scheme)
	}

	// Extract hostname (without port)
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL must contain a hostname")
	}

	// Block known internal hostnames
	lowerHost := strings.ToLower(hostname)
	blockedHosts := []string{
		"localhost",
		"host.docker.internal",
		"metadata.google.internal",
		"kubernetes.default",
		"kubernetes.default.svc",
	}
	for _, blocked := range blockedHosts {
		if lowerHost == blocked {
			return fmt.Errorf("URL hostname %q is not allowed", hostname)
		}
	}

	// Resolve hostname to IP addresses and check each one
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// If we can't resolve, check if hostname is already an IP
		if ip := net.ParseIP(hostname); ip != nil {
			if isPrivateIP(ip) {
				return fmt.Errorf("URL resolves to a private/internal IP address")
			}
			return nil
		}
		return fmt.Errorf("%w: %v", ErrUnresolvableHost, err)
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("URL resolves to a private/internal IP address")
		}
	}

	return nil
}

// IsPrivateAddressLiteral reports whether host is an IP LITERAL in a private,
// loopback, link-local or cloud-metadata range.
//
// It resolves nothing. That is the difference from [ValidateWebhookURL], and it
// is deliberate: the caller this exists for is validating a URL it will never
// fetch — the source URL an AI enrichment proposal cites (ADR-0008 D4.4) — where
// a DNS lookup would make a pure validator depend on the resolver, make its
// tests network-bound, and answer a question nobody asked. A hostname therefore
// returns false here and is judged by name; anything that is actually dialled
// must still go through [SafeHTTPClient], whose Control hook sees the concrete
// IP and is what closes the rebinding gap a pre-flight check cannot.
//
// It shares the single range list with the dialer's guard rather than restating
// it, so widening the list widens both.
func IsPrivateAddressLiteral(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return isPrivateIP(ip)
}

// isPrivateIP checks if an IP address is in a private, loopback,
// link-local, or otherwise internal range.
//
// It is the union of the two predicates below. They are separate because one
// class of caller — a connector to a system that is ON-PREMISES BY NATURE, a
// NetBox or a CMDB — must be allowed to reach an RFC1918 address while still
// being refused loopback, link-local and the cloud metadata endpoint. Those
// two halves protect against different things: the RFC1918 half stops a tenant
// pointing us at their neighbours' internal network, and the never-allowed
// half stops a tenant pointing us at OURSELVES. Only the first is ever
// negotiable. See [IsNeverReachable].
func isPrivateIP(ip net.IP) bool {
	return IsNeverReachable(ip) || isRFC1918OrULA(ip)
}

// IsNeverReachable reports whether an address is one no outbound request from
// this platform may ever target, regardless of any per-connector opt-in:
// loopback, the unspecified address, link-local (which carries the cloud
// metadata endpoints), and the multicast/broadcast shapes.
//
// This is the half of the SSRF guard that is NOT negotiable. `curl -k`
// validates nothing; an "allow private targets" flag that also opened
// 169.254.169.254 would be the same kind of check — one that looks like a
// control and is not.
func IsNeverReachable(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		// 169.254.0.0/16 and fe80::/10 — the cloud metadata endpoints
		// (169.254.169.254, fd00:ec2::254) live in here.
		return true
	}
	if ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	return false
}

// isRFC1918OrULA reports whether an address is in a private unicast range:
// 10/8, 172.16/12, 192.168/16, 100.64/10 (carrier NAT, which is private space
// from our side of it), and fc00::/7.
//
// This is the NEGOTIABLE half: a connector whose target system is on-premises
// by construction may opt into it, per connection and with an audit entry.
func isRFC1918OrULA(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() {
		// net.IP.IsPrivate covers 10/8, 172.16/12, 192.168/16 and fc00::/7.
		return true
	}
	// 100.64.0.0/10 (RFC 6598) is not IsPrivate but is equally not the public
	// internet; a name resolving into it is not a target we reach by accident.
	_, cgnat, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return false
	}
	return cgnat.Contains(ip)
}

// IsPrivateReachableWithOptIn reports whether host — an IP literal or a
// hostname — resolves ONLY into private unicast space, and so needs a
// connector's private-endpoint opt-in to be reachable.
//
// It is for telling a tenant WHY their URL was refused, and for deciding
// whether a saved connection needs the audit entry that records it points
// inside their own network. It is not itself a gate: the gate is the dialer's
// Control hook, which sees the concrete IP at connect time and is the only
// thing DNS rebinding cannot walk past.
func IsPrivateReachableWithOptIn(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return !IsNeverReachable(ip) && isRFC1918OrULA(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if IsNeverReachable(ip) || !isRFC1918OrULA(ip) {
			return false
		}
	}
	return true
}
