package network

import (
	"fmt"
	"net"
	"strings"
)

// IsIPInCIDR checks if an IP address is within a CIDR block
func IsIPInCIDR(ip, cidr string) bool {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ipNet.Contains(ipAddr)
}

// IsIPInRange checks if an IP address is within an IP range (start-end)
func IsIPInRange(ip, startIP, endIP string) bool {
	ipAddr := net.ParseIP(ip)
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if ipAddr == nil || start == nil || end == nil {
		return false
	}

	// Only support IPv4 for now
	if ipAddr.To4() == nil || start.To4() == nil || end.To4() == nil {
		return false
	}

	// Check if IP is between start and end (inclusive)
	return compareIPs(ipAddr, start) >= 0 && compareIPs(ipAddr, end) <= 0
}

// compareIPs compares two IP addresses byte by byte
// Returns: -1 if ip1 < ip2, 0 if equal, 1 if ip1 > ip2
func compareIPs(ip1, ip2 net.IP) int {
	for i := 0; i < len(ip1) && i < len(ip2); i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

// MatchesDomainPattern checks if a hostname matches a domain pattern
// Supports wildcards: *.example.com matches subdomain.example.com
func MatchesDomainPattern(hostname, pattern string) bool {
	if hostname == "" || pattern == "" {
		return false
	}

	// Exact match
	if hostname == pattern {
		return true
	}

	// Wildcard pattern matching
	if strings.HasPrefix(pattern, "*.") {
		// Remove the *. prefix
		domain := pattern[2:]
		// Check if hostname ends with .domain
		if strings.HasSuffix(hostname, "."+domain) {
			return true
		}
		// Also check if hostname equals domain (for root domain)
		if hostname == domain {
			return true
		}
	}

	// Check if hostname ends with the pattern (subdomain matching)
	if strings.HasSuffix(hostname, "."+pattern) {
		return true
	}

	return false
}

// ParseIPRange parses an IP range string in the format "startIP-endIP"
// Returns startIP, endIP, and error
func ParseIPRange(rangeStr string) (string, string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid IP range format, expected start-end")
	}

	startIP := strings.TrimSpace(parts[0])
	endIP := strings.TrimSpace(parts[1])

	// Validate IPs
	if net.ParseIP(startIP) == nil {
		return "", "", fmt.Errorf("invalid start IP address")
	}
	if net.ParseIP(endIP) == nil {
		return "", "", fmt.Errorf("invalid end IP address")
	}

	return startIP, endIP, nil
}
