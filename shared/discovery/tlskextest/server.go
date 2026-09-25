// Package tlskextest provides a loopback TLS server pinned to a chosen set of
// key-exchange groups, for testing every live-handshake site's key-exchange
// measurement against the same fixture.
//
// It lives in its own package so the shared prober, the device-interrogation
// prober and the standalone sensor's enricher (a different module) are all held
// to one server, rather than each carrying a copy that could be quietly
// weakened.
//
// The server listens on 127.0.0.1 only and presents a throwaway self-signed
// certificate for example.com; nothing here touches an external network.
package tlskextest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Case is one server configuration the key-exchange tests run against, and
// what every site must record for it.
type Case struct {
	Name   string
	Groups []tls.CurveID
	// MaxVersion caps the server's TLS version; 0 means the crypto/tls default.
	MaxVersion uint16

	WantGroup             string
	WantGroupRaw          uint16
	WantSupportsClassical bool
	WantSupportsPQCHybrid bool
	// WantPQCHybridGroup is the hybrid group the server was seen to accept —
	// the negotiated one when the main handshake was hybrid, otherwise the one
	// it chose from the hybrid-only offer. "" when hybrid support is not
	// proven.
	WantPQCHybridGroup string

	// WantExtraHandshakes is EXACTLY how many support handshakes a probe may
	// add beyond its main one: the main handshake answers one of the two
	// questions itself, so one for a TLS 1.3 server, and none for a TLS 1.2
	// server (whose answer to a TLS 1.3 offer already rules hybrid out).
	WantExtraHandshakes int
}

// WantConnections is the exact connection count the fixture server must see
// for one probe that makes the support handshakes.
func (c Case) WantConnections() int { return 1 + c.WantExtraHandshakes }

// Cases are the servers every live-handshake site is tested against: a
// hybrid-only server, the two classical groups a real server most often pins,
// a server that supports a hybrid group but prefers a classical one, and a
// TLS 1.2-only server (which cannot do hybrid key exchange at all).
var Cases = []Case{
	{
		Name: "X25519MLKEM768 only", Groups: []tls.CurveID{tls.X25519MLKEM768},
		WantGroup: "X25519MLKEM768", WantGroupRaw: uint16(tls.X25519MLKEM768),
		WantSupportsClassical: false, WantSupportsPQCHybrid: true, WantExtraHandshakes: 1,
		WantPQCHybridGroup: "X25519MLKEM768",
	},
	{
		// The configuration W1.9's hint exists for: the server can do hybrid
		// key exchange, but its own preference order puts X25519 first, so the
		// main handshake negotiates classical. Only the hybrid-only support
		// handshake reveals that a configuration change would be enough.
		Name: "X25519 preferred, hybrid supported", Groups: []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
		WantGroup: "X25519", WantGroupRaw: uint16(tls.X25519),
		WantSupportsClassical: true, WantSupportsPQCHybrid: true, WantExtraHandshakes: 1,
		WantPQCHybridGroup: "X25519MLKEM768",
	},
	{
		Name: "X25519 only", Groups: []tls.CurveID{tls.X25519},
		WantGroup: "X25519", WantGroupRaw: uint16(tls.X25519),
		WantSupportsClassical: true, WantSupportsPQCHybrid: false, WantExtraHandshakes: 1,
	},
	{
		Name: "P-256 only", Groups: []tls.CurveID{tls.CurveP256},
		WantGroup: "DH-ECP-256", WantGroupRaw: uint16(tls.CurveP256),
		WantSupportsClassical: true, WantSupportsPQCHybrid: false, WantExtraHandshakes: 1,
	},
	{
		Name: "TLS 1.2 X25519", Groups: []tls.CurveID{tls.X25519}, MaxVersion: tls.VersionTLS12,
		WantGroup: "X25519", WantGroupRaw: uint16(tls.X25519),
		WantSupportsClassical: true, WantSupportsPQCHybrid: false,
	},
}

// Server is a running loopback TLS server.
type Server struct {
	Addr string
	Host string
	Port int

	mu         sync.Mutex
	handshakes int
	hellos     []Hello
}

// Hello is what one ClientHello offered: its versions and its groups.
type Hello struct {
	Versions []uint16
	Groups   []tls.CurveID
}

// Handshakes returns how many connections the server has accepted, so a test
// can pin the probe's traffic exactly.
func (s *Server) Handshakes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handshakes
}

// Hellos returns every ClientHello the server received, in arrival order.
func (s *Server) Hellos() []Hello {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Hello(nil), s.hellos...)
}

// CheckConnections asserts the server saw exactly the connections a probe
// with the support handshakes makes for c: the main one plus
// c.WantExtraHandshakes. A retry, or a question asked twice, is extra traffic
// to a target and fails this.
func CheckConnections(t testing.TB, c Case, s *Server) {
	t.Helper()
	if n := s.Handshakes(); n != c.WantConnections() {
		t.Errorf("server saw %d connections, want exactly %d (main + %d support)", n, c.WantConnections(), c.WantExtraHandshakes)
	}
}

// StartSilent runs a listener on 127.0.0.1 that accepts connections and never
// answers — a peer that stalls a handshake until the client gives up. For
// testing that the support handshakes share one bounded deadline.
func StartSilent(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// Start runs a TLS server on 127.0.0.1 offering only groups, until the test
// ends.
//
// groups is the server's PREFERENCE order, and the server enforces it: of the
// groups a ClientHello offers, it negotiates the first one in groups. crypto/tls
// on its own prefers a hybrid group whenever the client sends a key share for
// one, whatever the server's list says, so without this a server configured
// "X25519 first, hybrid also allowed" — the configuration a real OpenSSL or
// nginx deployment has when its group list names the classical group first —
// could not be modelled.
func Start(t testing.TB, groups []tls.CurveID, maxVersion uint16) *Server {
	t.Helper()
	cert := selfSigned(t)
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: groups,
		MaxVersion:       maxVersion,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	s := &Server{Addr: ln.Addr().String(), Host: addr.IP.String(), Port: addr.Port}
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		s.hellos = append(s.hellos, Hello{
			Versions: append([]uint16(nil), h.SupportedVersions...),
			Groups:   append([]tls.CurveID(nil), h.SupportedCurves...),
		})
		s.mu.Unlock()
		for _, preferred := range groups {
			if slices.Contains(h.SupportedCurves, preferred) {
				c := cfg.Clone()
				c.GetConfigForClient = nil
				c.CurvePreferences = []tls.CurveID{preferred}
				return c, nil
			}
		}
		// No group in common: the full list, which crypto/tls refuses with a
		// handshake_failure alert — what a real server sends.
		return nil, nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				s.mu.Lock()
				s.handshakes++
				s.mu.Unlock()
				tc := tls.Server(conn, cfg)
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				if tc.Handshake() == nil {
					// Hold the connection until the client closes it, so a
					// client never races the close_notify.
					buf := make([]byte, 1)
					_, _ = tc.Read(buf)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return s
}

// PortString is Port as a string, for net.JoinHostPort.
func (s *Server) PortString() string { return strconv.Itoa(s.Port) }

func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Check asserts that meta carries exactly what c says every site must record.
func Check(t testing.TB, c Case, meta map[string]interface{}) {
	t.Helper()
	if got := meta["key_exchange_algorithm"]; got != c.WantGroup {
		t.Errorf("key_exchange_algorithm = %v, want %q", got, c.WantGroup)
	}
	if got := meta["key_exchange_group_raw"]; got != c.WantGroupRaw {
		t.Errorf("key_exchange_group_raw = %v (%T), want %d", got, got, c.WantGroupRaw)
	}
	checkFlag(t, meta, "tls_supports_classical_kex", c.WantSupportsClassical)
	checkFlag(t, meta, "tls_supports_pqc_hybrid_kex", c.WantSupportsPQCHybrid)
	got, present := meta["tls_pqc_hybrid_kex_group"]
	switch {
	case c.WantPQCHybridGroup == "" && present:
		t.Errorf("tls_pqc_hybrid_kex_group = %v, want absent — hybrid support is not proven", got)
	case c.WantPQCHybridGroup != "" && got != c.WantPQCHybridGroup:
		t.Errorf("tls_pqc_hybrid_kex_group = %v (present=%v), want %q", got, present, c.WantPQCHybridGroup)
	}
}

// CheckOnlyProvenFlags asserts the flags a probe that made NO support
// handshake may record for c: only what the main handshake proves on its own
// (a negotiated hybrid proves hybrid support, a negotiated classical group
// proves classical support, a TLS 1.2 answer rules hybrid out). The question
// that would need a support handshake must be absent — unknown, not false.
func CheckOnlyProvenFlags(t testing.TB, c Case, meta map[string]interface{}) {
	t.Helper()
	want := map[string]interface{}{}
	if c.WantSupportsPQCHybrid && !c.WantSupportsClassical {
		want["tls_supports_pqc_hybrid_kex"] = true
	} else {
		want["tls_supports_classical_kex"] = true
		if c.MaxVersion == tls.VersionTLS12 {
			want["tls_supports_pqc_hybrid_kex"] = false
		}
	}
	for _, key := range []string{"tls_supports_classical_kex", "tls_supports_pqc_hybrid_kex"} {
		got, present := meta[key]
		w, wantPresent := want[key]
		switch {
		case wantPresent && (!present || got != w):
			t.Errorf("%s = %v (present=%v), want %v", key, got, present, w)
		case !wantPresent && present:
			t.Errorf("%s = %v, want absent — answering it needs a support handshake", key, got)
		}
	}
}

func checkFlag(t testing.TB, meta map[string]interface{}, key string, want bool) {
	t.Helper()
	v, ok := meta[key]
	if !ok {
		t.Errorf("%s absent, want %v", key, want)
		return
	}
	if v != want {
		t.Errorf("%s = %v, want %v", key, v, want)
	}
}
