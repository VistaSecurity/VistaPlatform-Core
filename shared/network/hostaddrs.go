package network

import (
	"net"
	"net/url"
)

// InterfaceAddress is one IP bound to one interface on an agent host.
//
// Agents report the full set because a capture host is routinely multi-homed
// and may observe several segments at once — a single scalar address cannot
// describe what it can see. The prefix travels with the address so the platform
// can answer coverage questions ("which segments does the fleet reach, and
// which are blind?") without inferring anything from interface names.
type InterfaceAddress struct {
	InterfaceName string `json:"interface_name"`
	Address       string `json:"address"`
	// PrefixLength is the network prefix (24 for 192.0.2.173/24). Zero means
	// the agent could not determine one.
	PrefixLength int `json:"prefix_length,omitempty"`
	// IsPrimary marks the address the agent reaches the control plane from.
	// At most one address per agent carries it.
	IsPrimary bool `json:"is_primary,omitempty"`
}

// HostAddresses enumerates every usable IP bound on this host, marking the one
// matching primaryIP (pass "" to mark none).
//
// Loopback and link-local addresses are omitted: neither identifies the host to
// anything outside it, and including them would make every agent look like it
// covers 127.0.0.0/8 and fe80::/10.
func HostAddresses(primaryIP string) []InterfaceAddress {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []InterfaceAddress
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			if ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() || ipNet.IP.IsLinkLocalMulticast() {
				continue
			}

			prefix, _ := ipNet.Mask.Size()
			ip := ipNet.IP.String()
			out = append(out, InterfaceAddress{
				InterfaceName: iface.Name,
				Address:       ip,
				PrefixLength:  prefix,
				IsPrimary:     primaryIP != "" && ip == primaryIP,
			})
		}
	}
	return out
}

// PrimarySourceIPv4 returns the local address the kernel would use to reach
// controlPlaneURL — the address the platform actually sees this host as, modulo
// NAT, and therefore the one worth calling primary.
//
// This is deliberately not "the first non-loopback interface address". On a
// multi-homed host that ordering is OS-defined and, on Windows especially,
// routinely surfaces a Hyper-V, WSL, or VPN adapter instead of the NIC carrying
// platform traffic. Asking the routing table removes the guess.
//
// Returns "" when the address cannot be determined. Callers must send that as
// "unreported" rather than substituting a placeholder: the platform stores an
// unknown address as NULL, and a loopback stand-in would be a confident lie.
func PrimarySourceIPv4(controlPlaneURL string) string {
	if ip := routeSourceIPv4(controlPlaneURL); ip != "" {
		return ip
	}
	return firstNonLoopbackIPv4()
}

// routeSourceIPv4 performs a route lookup by "connecting" a UDP socket. No
// packets are sent, so this works offline and does not require the control plane
// to be reachable or even listening.
func routeSourceIPv4(controlPlaneURL string) string {
	host := controlPlaneHostPort(controlPlaneURL)
	if host == "" {
		return ""
	}

	conn, err := net.Dial("udp4", host)
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	if ipv4 := udpAddr.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() {
		return ipv4.String()
	}
	return ""
}

// controlPlaneHostPort normalises a control-plane URL into host:port for a route
// lookup, defaulting the port by scheme.
func controlPlaneHostPort(controlPlaneURL string) string {
	if controlPlaneURL == "" {
		return ""
	}

	u, err := url.Parse(controlPlaneURL)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}

	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// firstNonLoopbackIPv4 is the fallback when the routing table cannot answer (no
// control-plane URL yet, or an unresolvable host). Order is OS-defined, so this
// is a best guess rather than an answer.
func firstNonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				return ipv4.String()
			}
		}
	}

	return ""
}
