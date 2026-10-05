// Package tlsendpointtest holds the loopback TLS servers, the counting dialer
// and the golden-file helpers the characterization tests of every
// single-endpoint TLS prober share ( WP6): the standalone sensor's TLS
// enricher, the device-interrogation TLSProber and device-interrogation-
// service's cloud handshake.
//
// It lives in its own package, like tlskextest, so the three callers — two of
// them in other modules — are held to ONE set of servers and one output
// comparison, rather than each carrying a copy that could be quietly weakened.
//
// Everything listens on 127.0.0.1 at an ephemeral port. Callers are told they
// are talking to a documentation name or address (example.test, 192.0.2.0/24,
// or private space where a caller's own scope rule needs it) and the Dialer
// maps that one address onto the listener, recording every dial. Nothing here
// touches an external network.
//
// The certificates are generated per process, but every field a prober reports
// is fixed — subject, issuer, serial, validity, SANs, key usage, key type and
// size — so a golden file records them literally. The fields that depend on the
// freshly generated key (PEM, fingerprints) are replaced by stable tokens
// before comparison (Fixture.Tokens).
package tlsendpointtest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // fingerprint token only, not a security primitive
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Name is the identity every leaf but the wrong-hostname one is issued for.
const Name = "device.example.test"

// OtherName is the identity of the wrong-hostname leaf.
const OtherName = "other.example.test"

var (
	validFrom    = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	validTo      = time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredFrom  = time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredUntil = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
)

type issued struct {
	name string
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

// Fixture is the process-wide set of fixture certificates.
type Fixture struct {
	rsaCA, rsaLeaf, ecCA, ecLeaf, otherLeaf, expired *issued
}

var (
	fixtureOnce sync.Once
	fixture     *Fixture
	fixtureErr  error
)

// Certs returns the fixture certificates, generating them on first use.
func Certs(t testing.TB) *Fixture {
	t.Helper()
	fixtureOnce.Do(func() { fixture, fixtureErr = generate() })
	if fixtureErr != nil {
		t.Fatalf("tlsendpointtest: generating fixture certificates: %v", fixtureErr)
	}
	return fixture
}

func generate() (*Fixture, error) {
	rsaKey := func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }
	ecKey := func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

	f := &Fixture{}
	var err error
	if f.rsaCA, err = issue("rsa_ca", rsaKey, nil, &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "Example Test RSA CA", Organization: []string{"Example Test"}},
		NotBefore:             validFrom,
		NotAfter:              validTo,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}); err != nil {
		return nil, err
	}
	if f.rsaLeaf, err = issue("rsa_leaf", rsaKey, f.rsaCA, &x509.Certificate{
		SerialNumber: big.NewInt(1002),
		Subject:      pkix.Name{CommonName: Name, Organization: []string{"Example Test"}},
		DNSNames:     []string{Name},
		NotBefore:    validFrom,
		NotAfter:     validTo,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, err
	}
	if f.ecCA, err = issue("ecdsa_ca", ecKey, nil, &x509.Certificate{
		SerialNumber:          big.NewInt(2001),
		Subject:               pkix.Name{CommonName: "Example Test ECDSA CA", Organization: []string{"Example Test"}},
		NotBefore:             validFrom,
		NotAfter:              validTo,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}); err != nil {
		return nil, err
	}
	// The ECDSA leaf also carries the two legacy server-gated-crypto EKUs, so
	// a prober's extended-key-usage naming is exercised beyond ServerAuth.
	if f.ecLeaf, err = issue("ecdsa_leaf", ecKey, f.ecCA, &x509.Certificate{
		SerialNumber: big.NewInt(2002),
		Subject:      pkix.Name{CommonName: Name, Organization: []string{"Example Test"}},
		DNSNames:     []string{Name, "www." + Name},
		NotBefore:    validFrom,
		NotAfter:     validTo,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto, x509.ExtKeyUsageNetscapeServerGatedCrypto,
		},
	}); err != nil {
		return nil, err
	}
	if f.otherLeaf, err = issue("other_leaf", ecKey, f.ecCA, &x509.Certificate{
		SerialNumber: big.NewInt(2003),
		Subject:      pkix.Name{CommonName: OtherName},
		DNSNames:     []string{OtherName},
		NotBefore:    validFrom,
		NotAfter:     validTo,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, err
	}
	if f.expired, err = issue("expired_self_signed", rsaKey, nil, &x509.Certificate{
		SerialNumber:          big.NewInt(3001),
		Subject:               pkix.Name{CommonName: Name},
		DNSNames:              []string{Name},
		NotBefore:             expiredFrom,
		NotAfter:              expiredUntil,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, err
	}
	return f, nil
}

// issue signs tmpl with parent's key (or self-signs when parent is nil).
func issue(name string, newKey func() (crypto.Signer, error), parent *issued, tmpl *x509.Certificate) (*issued, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &issued{name: name, der: der, cert: cert, key: key}, nil
}

func chain(leaf *issued, rest ...*issued) tls.Certificate {
	c := tls.Certificate{PrivateKey: leaf.key, Certificate: [][]byte{leaf.der}}
	for _, r := range rest {
		c.Certificate = append(c.Certificate, r.der)
	}
	return c
}

// Tokens maps every key-dependent value a prober can report for a fixture
// certificate — its PEM and its SHA-256 / SHA-1 fingerprints — to a stable
// token, so a golden file can name it.
func (f *Fixture) Tokens() map[string]string {
	out := map[string]string{}
	for _, c := range []*issued{f.rsaCA, f.rsaLeaf, f.ecCA, f.ecLeaf, f.otherLeaf, f.expired} {
		s256 := sha256.Sum256(c.der)
		s1 := sha1.Sum(c.der) //nolint:gosec // token only
		out[string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der}))] = "{{" + c.name + ".pem}}"
		out[hex.EncodeToString(s256[:])] = "{{" + c.name + ".sha256}}"
		out[hex.EncodeToString(s1[:])] = "{{" + c.name + ".sha1}}"
	}
	return out
}

// Scenario is one server every single-endpoint TLS prober is characterized
// against.
type Scenario struct {
	Name string
	// Target is the name a caller is told the endpoint has: the SNI it
	// presents and, for a caller that dials by name, the name it dials. ""
	// means the caller knows only an address (no SNI).
	Target string
	// Version is the only TLS version the server accepts.
	Version uint16
	config  func(*Fixture) *tls.Config
}

// SupportHandshakes is how many key-exchange support handshakes a probe that
// makes them adds for this server: every fixture pins one classical group, so
// the main handshake proves classical support, and only a TLS 1.3 server
// leaves hybrid support to ask (a TLS 1.2 answer already rules it out).
func (sc Scenario) SupportHandshakes() int {
	if sc.Version == tls.VersionTLS13 {
		return 1
	}
	return 0
}

// RefusedVersions is how many forced-version handshakes a version enumeration
// that skips the negotiated version makes: the other three of TLS 1.0–1.3.
const RefusedVersions = 3

// Scenarios are the servers the characterization covers: TLS 1.2 with RSA and
// with ECDSA (the latter on an ECDHE-ECDSA CBC suite), TLS 1.3, a server that
// asks for a client certificate, an expired self-signed certificate, a
// certificate for the wrong name, and an endpoint known only by address whose
// certificate names a host.
var Scenarios = []Scenario{
	{Name: "tls12-rsa", Target: Name, Version: tls.VersionTLS12, config: func(f *Fixture) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{chain(f.rsaLeaf, f.rsaCA)},
			MaxVersion:   tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519},
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		}
	}},
	{Name: "tls12-ecdsa-cbc", Target: Name, Version: tls.VersionTLS12, config: func(f *Fixture) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{chain(f.ecLeaf, f.ecCA)},
			MaxVersion:   tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256},
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		}
	}},
	{Name: "tls13-ecdsa", Target: Name, Version: tls.VersionTLS13, config: func(f *Fixture) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{chain(f.ecLeaf, f.ecCA)},
			MinVersion:   tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
		}
	}},
	{Name: "tls13-client-cert-requested", Target: Name, Version: tls.VersionTLS13, config: func(f *Fixture) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{chain(f.ecLeaf, f.ecCA)},
			MinVersion:   tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
			ClientAuth: tls.RequestClientCert,
		}
	}},
	{Name: "expired-self-signed", Target: Name, Version: tls.VersionTLS12, config: func(f *Fixture) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{chain(f.expired)},
			MaxVersion:   tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519},
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		}
	}},
	{Name: "wrong-hostname", Target: Name, Version: tls.VersionTLS13, config: func(f *Fixture) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{chain(f.otherLeaf, f.ecCA)},
			MinVersion:   tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
		}
	}},
	{Name: "address-only", Target: "", Version: tls.VersionTLS13, config: func(f *Fixture) *tls.Config {
		return &tls.Config{
			Certificates: []tls.Certificate{chain(f.rsaLeaf, f.rsaCA)},
			MinVersion:   tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
		}
	}},
}

// PeerCertificates is the chain sc's server presents, leaf first.
func (sc Scenario) PeerCertificates(t testing.TB) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, der := range sc.config(Certs(t)).Certificates[0].Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// Server is a running loopback TLS server.
type Server struct {
	Addr string
	Port int

	mu       sync.Mutex
	accepted int
}

// Accepted is how many TCP connections the server has accepted.
func (s *Server) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// Start runs sc's server on 127.0.0.1 until the test ends.
func Start(t testing.TB, sc Scenario) *Server {
	t.Helper()
	cfg := sc.config(Certs(t))
	return serve(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if tc.Handshake() == nil {
			// Read until the client closes, so the client's handshake is
			// never cut short by our close.
			_, _ = tc.Read(make([]byte, 1))
		}
	})
}

// StartWithOCSPResponder runs a TLS 1.3 server whose leaf names ocspURL as its
// OCSP responder and which presents its issuer too — so a validating prober
// with no OCSP staple goes on to query ocspURL. For testing that the query is
// guarded: point ocspURL at a loopback listener and count what reaches it.
func StartWithOCSPResponder(t testing.TB, ocspURL string) *Server {
	t.Helper()
	f := Certs(t)
	leaf, err := issue("ocsp_leaf", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }, f.ecCA, &x509.Certificate{
		SerialNumber: big.NewInt(2004),
		Subject:      pkix.Name{CommonName: Name},
		DNSNames:     []string{Name},
		NotBefore:    validFrom,
		NotAfter:     validTo,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer:   []string{ocspURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{chain(leaf, f.ecCA)},
		MinVersion:   tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
	}
	return serve(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if tc.Handshake() == nil {
			_, _ = tc.Read(make([]byte, 1))
		}
	})
}

// StartGarbage runs a listener that answers every connection with bytes that
// are not TLS, so a handshake fails after a successful connect.
func StartGarbage(t testing.TB) *Server {
	t.Helper()
	return serve(t, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
	})
}

func serve(t testing.TB, onConn func(net.Conn)) *Server {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &Server{Addr: ln.Addr().String(), Port: ln.Addr().(*net.TCPAddr).Port}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.accepted++
			s.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				onConn(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	return s
}

// Dialer maps requested addresses onto a real listener and records every dial.
// A requested address it was not told about is refused — and recorded — so a
// prober that dials somewhere unexpected fails loudly rather than reaching the
// network.
type Dialer struct {
	real  string
	alias map[string]bool

	mu         sync.Mutex
	dials      []string
	unexpected []string
}

// NewDialer returns a Dialer that sends every dial of one of aliases
// ("host:port") to real.
func NewDialer(real string, aliases ...string) *Dialer {
	d := &Dialer{real: real, alias: map[string]bool{}}
	for _, a := range aliases {
		d.alias[a] = true
	}
	return d
}

// DialContext has the shape of net.Dialer.DialContext.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, address)
	ok := d.alias[address]
	if !ok {
		d.unexpected = append(d.unexpected, address)
	}
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("tlsendpointtest: unexpected dial to %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.real)
}

// Dial has the shape of a (address, timeout) dial seam.
func (d *Dialer) Dial(address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, "tcp", address)
}

// Dials returns every address the dialer was asked for, in order.
func (d *Dialer) Dials() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dials...)
}

// Unexpected returns the requested addresses the dialer refused.
func (d *Dialer) Unexpected() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.unexpected...)
}

// CheckEveryConnectionDialed asserts that the injected dialer made exactly want
// connections, that every connection srv accepted came through it, and that it
// refused nothing. A prober that dials around the injected dialer either
// reaches no server at all (the address it was given is a documentation one),
// which loses a measurement and the exact count, or reaches the server
// uncounted, which breaks the dials == accepted equality.
func CheckEveryConnectionDialed(t testing.TB, d *Dialer, srv *Server, want int) {
	t.Helper()
	if u := d.Unexpected(); len(u) > 0 {
		t.Errorf("dialer was asked for unexpected addresses %v", u)
	}
	dials, accepted := len(d.Dials()), srv.Accepted()
	if dials != accepted {
		t.Errorf("server accepted %d connections but the injected dialer made %d — a connection bypassed the dialer", accepted, dials)
	}
	if dials != want {
		t.Errorf("injected dialer made %d connections, want exactly %d", dials, want)
	}
}

// HostPort joins host and port.
func HostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
