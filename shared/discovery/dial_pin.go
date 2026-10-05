package discovery

import (
	"context"
	"net"
	"sync"
)

// PinToReachedAddress wraps dial for ONE ProbeTLSEndpoint call to a NAME:
// once a connection succeeds, every later dial goes to the address that
// connection actually reached, not to a fresh resolution of the name. A load
// balancer or CDN name resolves to many addresses, and the key-exchange support
// handshakes and the version enumeration must ask the server the main
// handshake measured — not whichever one the next lookup returns. Each dial
// still goes through dial, so the caller's guard judges the pinned address
// too.
//
// Use it only with a dialer that connects directly (net.Dialer, dialguard): a
// proxying dialer's RemoteAddr is the proxy, which is not the target. A fresh
// wrapper per probe; it is safe for concurrent use.
func PinToReachedAddress(dial ContextDialFunc) ContextDialFunc {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var (
		mu      sync.Mutex
		reached string
	)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		target := address
		if reached != "" {
			target = reached
		}
		mu.Unlock()
		conn, err := dial(ctx, network, target)
		if err != nil {
			return nil, err
		}
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr != nil {
			mu.Lock()
			if reached == "" {
				reached = addr.String()
			}
			mu.Unlock()
		}
		return conn, nil
	}
}
