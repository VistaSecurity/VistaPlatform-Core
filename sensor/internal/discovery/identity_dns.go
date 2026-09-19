package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"golang.org/x/net/ipv4"
)

// IdentityDNSResolver is scoped to the sensor's configured capture interfaces.
// Lookups never initiate endpoint probes and answers remain weak identity evidence.
type IdentityDNSResolver struct {
	Interfaces func() ([]net.Interface, error)
	Addresses  func(net.Interface) ([]net.Addr, error)
	Lookup     func(context.Context, string, net.IP) ([]net.IP, error)
	Multicast  func(context.Context, string, net.Interface, net.IP) ([]net.IP, error)
}

func NewIdentityDNSResolver() IdentityDNSResolver {
	return IdentityDNSResolver{net.Interfaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() }, lookupBoundDNS, lookupLocalMDNS}
}
func (r IdentityDNSResolver) Resolve(ctx context.Context, req sensordispatch.IdentityDNSRequest, allowed []string, version string) sensordispatch.IdentityDNSResult {
	out := sensordispatch.IdentityDNSResult{RequestID: req.RequestID, ObservationID: req.ObservationID, Hostname: req.Hostname, NetworkScope: req.NetworkScope, Addresses: []string{}, CollectorVersion: version}
	if req.Validate() != nil {
		out.ErrorCode = "invalid_request"
		return out
	}
	prefix, _ := netip.ParsePrefix(req.SegmentCIDR)
	interfaces, err := r.Interfaces()
	if err != nil {
		out.ErrorCode = "interface_unavailable"
		return out
	}
	permitted := map[string]bool{}
	for _, name := range allowed {
		permitted[name] = true
	}
	var selected *net.Interface
	var local net.IP
	for _, iface := range interfaces {
		if !permitted[iface.Name] || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, e := r.Addresses(iface)
		if e != nil {
			continue
		}
		for _, raw := range addrs {
			a, e := netip.ParsePrefix(raw.String())
			if e == nil && prefix.Contains(a.Addr()) && !a.Addr().IsLoopback() {
				copy := iface
				selected = &copy
				local = net.IP(a.Addr().AsSlice())
				break
			}
		}
		if selected != nil {
			break
		}
	}
	if selected == nil {
		out.ErrorCode = "network_scope_unreachable"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutMS)*time.Millisecond)
	defer cancel()
	var ips []net.IP
	name := strings.TrimSuffix(req.Hostname, ".")
	if strings.HasSuffix(name, ".local") {
		if local.To4() == nil || selected.Flags&net.FlagMulticast == 0 {
			out.ErrorCode = "scoped_mdns_unavailable"
			return out
		}
		ips, err = r.Multicast(ctx, name, *selected, local)
	} else {
		ips, err = r.Lookup(ctx, name, local)
	}
	out.ObservedAt = time.Now().UTC()
	if err != nil {
		out.ErrorCode = "resolution_failed"
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			out.ErrorCode = "resolution_timeout"
		}
		return out
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		a = a.Unmap()
		if prefix.Contains(a) && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() {
			seen[a.String()] = true
		}
	}
	for address := range seen {
		out.Addresses = append(out.Addresses, address)
	}
	sort.Strings(out.Addresses)
	if len(out.Addresses) > req.MaxAddresses {
		out.Addresses = out.Addresses[:req.MaxAddresses]
	}
	return out
}
func lookupBoundDNS(ctx context.Context, name string, local net.IP) ([]net.IP, error) {
	resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{}
		if strings.HasPrefix(network, "tcp") {
			d.LocalAddr = &net.TCPAddr{IP: local}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: local}
		}
		return d.DialContext(ctx, network, address)
	}}
	return resolver.LookupIP(ctx, "ip", name+".")
}

// mDNS uses a single interface-bound multicast request with a unicast-response
// question. It never falls back to the host's unicast/public DNS resolver.
func lookupLocalMDNS(ctx context.Context, name string, iface net.Interface, local net.IP) ([]net.IP, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local})
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	packet := ipv4.NewPacketConn(conn)
	if err = packet.SetMulticastInterface(&iface); err != nil {
		return nil, err
	}
	if err = packet.SetMulticastTTL(255); err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	query := layers.DNS{Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClass(0x8001)}, {Name: []byte(name), Type: layers.DNSTypeAAAA, Class: layers.DNSClass(0x8001)}}}
	buffer := gopacket.NewSerializeBuffer()
	if err = query.SerializeTo(buffer, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		return nil, err
	}
	if _, err = conn.WriteToUDP(buffer.Bytes(), &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}); err != nil {
		return nil, err
	}
	buf := make([]byte, 9000)
	ips := []net.IP{}
	// The byte and packet limits bound hostile or noisy responses independently of the deadline.
	for i := 0; i < 32; i++ {
		n, source, e := conn.ReadFromUDP(buf)
		if e != nil {
			if len(ips) > 0 {
				return ips, nil
			}
			return nil, e
		}
		if source.Port != 5353 {
			continue
		}
		var response layers.DNS
		if response.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback) != nil || !response.QR || response.ID != query.ID {
			continue
		}
		ips = append(ips, identityMDNSAnswers(name, response)...)
	}
	return ips, nil
}
func identityMDNSAnswers(name string, response layers.DNS) []net.IP {
	ips := []net.IP{}
	for _, answer := range response.Answers {
		if answer.TTL == 0 || !strings.EqualFold(strings.TrimSuffix(string(answer.Name), "."), name) {
			continue
		}
		if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
			ips = append(ips, append(net.IP(nil), answer.IP...))
		}
	}
	return ips
}
