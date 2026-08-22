package discovery

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// maxSweepHosts caps target expansion so a wide CIDR (e.g. a /8) can't explode
// into millions of probes. Callers that need more should chunk their input.
const maxSweepHosts = 4096

// IsNetworkRange reports whether a target string is a CIDR block or an
// IPv4 start-end range (i.e. something that expands into many hosts), as
// opposed to a single host/IP.
func IsNetworkRange(target string) bool {
	if strings.Contains(target, "/") {
		return true
	}
	if strings.Contains(target, "-") {
		parts := strings.SplitN(target, "-", 2)
		return len(parts) == 2 && net.ParseIP(strings.TrimSpace(parts[0])) != nil
	}
	return false
}

// ExpandTargets expands a list of target strings (CIDR, IPv4 start-end range,
// hostname, or plain IP) into individual host addresses, deduplicated and
// capped at maxSweepHosts. Hostnames that fail to resolve are passed through
// unchanged. This is shared by the standalone sensor and the in-cluster service
// so both expand networks identically.
func ExpandTargets(inputs []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(h string) bool {
		if h == "" || seen[h] {
			return true
		}
		seen[h] = true
		out = append(out, h)
		return len(out) < maxSweepHosts
	}

	for _, in := range inputs {
		in = strings.TrimSpace(in)
		hosts, err := expandTarget(in)
		if err != nil {
			if !add(in) {
				return out
			}
			continue
		}
		for _, h := range hosts {
			if !add(h) {
				return out
			}
		}
	}
	return out
}

func expandTarget(input string) ([]string, error) {
	switch {
	case strings.Contains(input, "/"):
		return expandCIDR(input)
	case IsNetworkRange(input):
		return expandIPRange(input)
	case net.ParseIP(input) != nil:
		return []string{input}, nil
	default:
		ips, err := net.LookupIP(input)
		if err != nil {
			return []string{input}, nil
		}
		var v4, v6 []string
		for _, ip := range ips {
			if ip.To4() != nil {
				v4 = append(v4, ip.String())
			} else {
				v6 = append(v6, ip.String())
			}
		}
		if len(v4) > 0 {
			return v4, nil
		}
		return v6, nil
	}
}

func expandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}
	var ips []string
	for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
		if len(ips) >= maxSweepHosts {
			break
		}
	}
	return ips, nil
}

func expandIPRange(rangeStr string) ([]string, error) {
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format, expected start-end")
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP addresses in range")
	}
	if start.To4() == nil || end.To4() == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported")
	}
	var ips []string
	current := cloneIP(start)
	for {
		ips = append(ips, current.String())
		if current.Equal(end) || len(ips) >= maxSweepHosts {
			break
		}
		incrementIP(current)
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// cryptoPortProtocols maps well-known ports to the protocol(s) the active prober
// should attempt when an open listener is found, for crypto identification.
var cryptoPortProtocols = map[int][]string{
	443:   {"TLS"},
	8443:  {"TLS"},
	9443:  {"TLS"},
	10443: {"TLS"},
	636:   {"TLS"}, // LDAPS
	993:   {"TLS"}, // IMAPS
	995:   {"TLS"}, // POP3S
	465:   {"TLS"}, // SMTPS
	5671:  {"TLS"}, // AMQP/TLS
	8883:  {"TLS"}, // MQTT/TLS
	6379:  {"TLS"}, // Redis (TLS-enabled)
	22:    {"SSH"},
	2222:  {"SSH"},
	445:   {"SMB"},
	139:   {"SMB"},
	502:   {"Modbus"},
	4840:  {"OPC_UA"},
	44818: {"EtherNet_IP"},
	47808: {"BACnet"},
}

// DefaultCryptoPorts returns the curated set of ports a network sweep probes
// when the caller doesn't specify ports — the crypto/secure-protocol and OT/ICS
// ports the shared prober can identify.
func DefaultCryptoPorts() []int {
	ports := make([]int, 0, len(cryptoPortProtocols))
	for p := range cryptoPortProtocols {
		ports = append(ports, p)
	}
	return ports
}

// ProtocolsForPort returns the protocol(s) to probe on a given open port. Falls
// back to {"TLS"} for unknown ports (most crypto-bearing services speak TLS).
func ProtocolsForPort(port int) []string {
	if protos, ok := cryptoPortProtocols[port]; ok {
		return protos
	}
	return []string{"TLS"}
}

// WellKnownProtocolsForPort returns the curated protocol(s) for a port and
// whether the port is in the map at all. Unlike ProtocolsForPort it does not
// fall back, so callers can distinguish "this port is known to speak TLS" from
// "we have no idea, try TLS anyway".
func WellKnownProtocolsForPort(port int) ([]string, bool) {
	protos, ok := cryptoPortProtocols[port]
	return protos, ok
}

// PortSpeaks reports whether a port is a well-known port for the given
// protocol (case-insensitive, punctuation-insensitive).
func PortSpeaks(port int, protocol string) bool {
	protos, ok := cryptoPortProtocols[port]
	if !ok {
		return false
	}
	want := CanonicalProtocolName(protocol)
	for _, p := range protos {
		if CanonicalProtocolName(p) == want {
			return true
		}
	}
	return false
}

// ScanOpenPorts TCP-connects to each port on a host (concurrency-bounded by the
// given limit, default 50) and returns those that accept a connection. This is
// the cheap host/port-discovery pass before the (more expensive) protocol
// probes — "find listeners" before "identify the crypto."
func (p *Prober) ScanOpenPorts(host string, ports []int, concurrency int) []int {
	if concurrency <= 0 {
		concurrency = 50
	}
	connectTimeout := p.timeout
	if connectTimeout <= 0 || connectTimeout > 3*time.Second {
		// A connect probe should be quick even if the full-probe timeout is long.
		connectTimeout = 2 * time.Second
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var open []int

	for _, port := range ports {
		wg.Add(1)
		go func(pt int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", pt)), connectTimeout)
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, pt)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return open
}
