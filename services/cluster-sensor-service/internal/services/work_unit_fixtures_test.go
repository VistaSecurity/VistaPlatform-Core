package services

// Loopback fixtures for the work-unit tests. Every listener binds an
// EPHEMERAL port on 127.0.0.1 (":0"), and is reached only through FakeNet,
// which maps a scanned address's port onto it. Exported so the handler-level
// tests in services_test can use them too.

import (
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// ServeTLSWithOCSP serves a leaf+CA chain whose leaf names ocspURL as its OCSP
// responder and returns the listener's address.
func ServeTLSWithOCSP(t *testing.T, ocspURL string) string {
	t.Helper()
	port := serveLeafWithOCSP(t, ocspURL)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// ServeBanner accepts connections and greets each with banner (a
// server-speaks-first service such as SMTP), then closes.
func ServeBanner(t *testing.T, banner string) string {
	t.Helper()
	return serveTCP(t, func(c net.Conn) {
		_, _ = c.Write([]byte(banner))
		time.Sleep(200 * time.Millisecond)
	})
}

// ServeSilent accepts connections, sends nothing, and closes once the client
// has sent anything (the one TLS ClientHello identification allows) — an open
// port nothing can name.
func ServeSilent(t *testing.T) string {
	t.Helper()
	return serveTCP(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
	})
}

func serveTCP(t *testing.T, onConn func(net.Conn)) string {
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
			go func() { defer func() { _ = c.Close() }(); onConn(c) }()
		}
	}()
	return ln.Addr().String()
}

// ServeDNSUDP answers every datagram as a DNS server would: the query echoed
// with the response bit set.
func ServeDNSUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 12 {
				reply := append([]byte(nil), buf[:n]...)
				reply[2] |= 0x80
				_, _ = pc.WriteTo(reply, from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// HTTPTrap is an HTTP listener that counts the requests that reached it — an
// address the platform must never be steered to.
type HTTPTrap struct {
	URL  string
	hits atomic.Int32
}

func (h *HTTPTrap) Hits() int32 { return h.hits.Load() }

func NewHTTPTrap(t *testing.T) *HTTPTrap {
	t.Helper()
	trap := &HTTPTrap{}
	rec := listenHTTP(t, "127.0.0.1", func(w http.ResponseWriter, _ *http.Request) {
		trap.hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	trap.URL = "http://" + rec.addr + "/ocsp"
	return trap
}
