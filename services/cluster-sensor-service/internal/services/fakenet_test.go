package services

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
)

// FakeNet is the scan engine's network in the work-unit tests. It is handed
// to the engine as its Dialer, so EVERY connection a scan-plan job makes — the
// liveness sweep, the port scan, identification and UDP — comes through here:
//
//   - it records each address it was asked for (Dials), which is how a test
//     proves an address the target-authorization guard refused was never
//     contacted, not even by a liveness probe;
//   - it stands in for the hosts: an address registered with Host is "up"
//     (a port mapped to a loopback listener connects there; any other port is
//     refused, as a real host's RST); an unregistered address gives no answer,
//     at once. Nothing is ever dialled off the loopback interface.
type FakeNet struct {
	mu    sync.Mutex
	dials []string
	hosts map[netip.Addr]*fakeHost
	// OnDial, when set, runs before each dial (outside the lock) and may block
	// it — a test holds one host's scan to observe the others.
	OnDial func(ctx context.Context, network string, ap netip.AddrPort)
}

type fakeHost struct {
	tcp map[uint16]string // port -> loopback "ip:port"
	udp map[uint16]string
}

func NewFakeNet() *FakeNet { return &FakeNet{hosts: map[netip.Addr]*fakeHost{}} }

// Host registers addr as up. tcp/udp map its ports to loopback listeners.
func (n *FakeNet) Host(addr string, tcp, udp map[uint16]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hosts[netip.MustParseAddr(addr)] = &fakeHost{tcp: tcp, udp: udp}
}

// Dials is every "network ip:port" asked for, in order.
func (n *FakeNet) Dials() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.dials...)
}

// DialedAddrs is the set of addresses asked for.
func (n *FakeNet) DialedAddrs() map[string]int {
	out := map[string]int{}
	for _, d := range n.Dials() {
		_, hostport, _ := cutSpace(d)
		ap, err := netip.ParseAddrPort(hostport)
		if err == nil {
			out[ap.Addr().String()]++
		}
	}
	return out
}

func cutSpace(s string) (string, string, bool) {
	for i := range s {
		if s[i] == ' ' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// timeoutErr is what an address that never answers produces: a timeout, so
// the engine classifies the port filtered and the UDP probe no-answer.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func refused(network, address string) error {
	return &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func (n *FakeNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, errors.New("FakeNet: not a literal address: " + address)
	}
	n.mu.Lock()
	n.dials = append(n.dials, network+" "+address)
	h := n.hosts[ap.Addr()]
	hook := n.OnDial
	n.mu.Unlock()
	if hook != nil {
		hook(ctx, network, ap)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h == nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: timeoutErr{}}
	}
	ports := h.tcp
	if network == "udp" {
		ports = h.udp
	}
	real, ok := ports[ap.Port()]
	if !ok {
		return nil, refused(network, address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, real)
}
