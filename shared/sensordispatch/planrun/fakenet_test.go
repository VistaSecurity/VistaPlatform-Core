package planrun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeNet is the engine's only network in these tests: every dial — liveness,
// port scan, identification, UDP — is recorded, an address registered with
// host answers (a mapped port connects to a loopback listener on an EPHEMERAL
// port, any other port is refused like a real RST), and every other address
// gives no answer at once. Nothing leaves loopback.
type fakeNet struct {
	mu     sync.Mutex
	dials  []netip.AddrPort
	hosts  map[netip.Addr]map[uint16]string
	onDial func(ctx context.Context, network string, ap netip.AddrPort)
}

func newFakeNet() *fakeNet { return &fakeNet{hosts: map[netip.Addr]map[uint16]string{}} }

func (n *fakeNet) host(addr string, tcp map[uint16]string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if tcp == nil {
		tcp = map[uint16]string{}
	}
	n.hosts[netip.MustParseAddr(addr)] = tcp
}

func (n *fakeNet) dialed() map[netip.Addr]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[netip.Addr]int{}
	for _, ap := range n.dials {
		out[ap.Addr()]++
	}
	return out
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func (n *fakeNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, errors.New("fakeNet: not a literal address: " + address)
	}
	n.mu.Lock()
	n.dials = append(n.dials, ap)
	ports, up := n.hosts[ap.Addr()]
	hook := n.onDial
	n.mu.Unlock()
	if hook != nil {
		hook(ctx, network, ap)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !up || network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: timeoutErr{}}
	}
	real, ok := ports[ap.Port()]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, real)
}

// serveBanner is a server-speaks-first listener on an ephemeral loopback port.
func serveBanner(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(banner))
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().String()
}
