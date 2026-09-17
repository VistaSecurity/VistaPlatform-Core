package hostinventory

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// coalesceConnections validates, de-duplicates and caps peer observations.
// The key deliberately excludes process and any local port: the connection's
// stable identity is its local address plus remote peer, destination port and
// transport. Sorting before the cap makes the same socket set produce the same
// report regardless of command enumeration order.
func coalesceConnections(in []Connection, max int) []Connection {
	byKey := make(map[string]Connection, len(in))
	for _, c := range in {
		c.Proto = strings.ToLower(strings.TrimSpace(c.Proto))
		local, lerr := netip.ParseAddr(strings.TrimSpace(c.LocalAddress))
		remote, rerr := netip.ParseAddr(strings.TrimSpace(c.RemoteAddress))
		local = local.Unmap()
		remote = remote.Unmap()
		if lerr != nil || rerr != nil || local.IsUnspecified() || local.IsLoopback() || local.IsLinkLocalUnicast() || local.IsMulticast() ||
			remote.IsUnspecified() || remote.IsLoopback() || remote.IsLinkLocalUnicast() || remote.IsMulticast() || c.RemotePort < 1 || c.RemotePort > 65535 ||
			(c.Proto != "tcp" && c.Proto != "udp") {
			continue
		}
		c.LocalAddress = local.String()
		c.RemoteAddress = remote.String()
		key := fmt.Sprintf("%s|%s|%s|%d", c.Proto, c.LocalAddress, c.RemoteAddress, c.RemotePort)
		if prior, ok := byKey[key]; ok {
			if prior.Process == "" && c.Process != "" {
				prior.Process = c.Process
				prior.PID = c.PID
				byKey[key] = prior
			}
			continue
		}
		byKey[key] = c
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > defaultMaxConnections {
		keys = keys[:defaultMaxConnections]
	}
	if max > 0 && len(keys) > max {
		keys = keys[:max]
	}
	out := make([]Connection, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}

// excludeAcceptedConnections removes established TCP sockets whose local
// endpoint is also a measured listener. Kernel socket tables expose ESTABLISHED
// state, not direction; without this correlation an inbound client would be
// inverted into an outbound connection to the client's ephemeral port.
func excludeAcceptedConnections(in []Connection, listeners []Listener) []Connection {
	out := make([]Connection, 0, len(in))
	for _, c := range in {
		accepted := false
		for _, l := range listeners {
			if c.Proto != "tcp" || l.Proto != "tcp" || c.LocalPort != l.Port {
				continue
			}
			la, lerr := netip.ParseAddr(strings.TrimSpace(l.Address))
			ca, cerr := netip.ParseAddr(strings.TrimSpace(c.LocalAddress))
			if lerr == nil && cerr == nil && (la.IsUnspecified() || la.Unmap() == ca.Unmap()) {
				accepted = true
				break
			}
		}
		if !accepted {
			out = append(out, c)
		}
	}
	return out
}

func coalesceBoundUDP(in []BoundUDPSocket) []BoundUDPSocket {
	byKey := make(map[string]BoundUDPSocket, len(in))
	for _, s := range in {
		if s.Port < 1 || s.Port > 65535 {
			continue
		}
		addr := strings.TrimSpace(s.Address)
		if parsed, err := netip.ParseAddr(addr); err == nil {
			addr = parsed.Unmap().String()
		}
		s.Address = addr
		key := fmt.Sprintf("%s|%d", addr, s.Port)
		if prior, ok := byKey[key]; ok && prior.Process != "" {
			continue
		}
		byKey[key] = s
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > defaultMaxBoundUDP {
		keys = keys[:defaultMaxBoundUDP]
	}
	out := make([]BoundUDPSocket, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out
}
