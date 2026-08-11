package network

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

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
		return fmt.Errorf("unable to resolve hostname: %w", err)
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("URL resolves to a private/internal IP address")
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is in a private, loopback,
// link-local, or otherwise internal range.
func isPrivateIP(ip net.IP) bool {
	// Loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Link-local (169.254.0.0/16, fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}

	// Private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		// AWS metadata endpoint
		"169.254.169.254/32",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
