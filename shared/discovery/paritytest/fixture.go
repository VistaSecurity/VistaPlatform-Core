// Package paritytest is a TEST-ONLY harness for the shared scan engine
// (shared/discovery UnitEngine + shared/jobunits): it starts ONE set of real
// loopback listeners whose truth it controls (Start), runs the engine against
// them (RunEngine), normalizes the persisted rows into one field namespace
// (Persisted, Normalize), and holds them to that ground truth (Golden,
// CompareGolden): the certificate chain each listener serves, the TLS
// versions it accepts, the SSH host key it holds, whether it asks for a
// client certificate.
//
// It began (one-scan-path WP0) as the harness that compared the engine with
// the two legacy protocols × ports executors, field by field, before they were
// deleted. They were deleted in WP5, so only the engine-against-ground-
// truth half remains, as an engine regression test.
//
// Every difference must be named in KnownGaps or the test fails, and every
// named gap must still occur or the test fails — so a gap that closes forces
// its entry out, and a new difference cannot slip in unnoticed.
//
// Nothing here is used by production code. It ships in the public export
// because shared/ does; it binds only loopback addresses.
package paritytest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The harness binds its OWN loopback address. The fixture binds two fixed
// well-known ports (8443, 2222) to exercise the port-keyed branches of the
// engine's identification, and `make test-parallel` runs other suites at
// once: on a shared address one suite's probes could be answered by another's
// listener. 127.0.0.21 is used by no other suite (see shared/testdb's loopback
// fixture guard for the rule).
const EngineSuiteAddr = "127.0.0.21"

// The fixed ports the fixture tries for the "well-known port" cases. Both are
// unprivileged and in the curated port map (shared/discovery cryptoPortProtocols):
// 8443 → TLS, 2222 → SSH.
const (
	WellKnownTLSPort = 8443
	WellKnownSSHPort = 2222
)

// SSHServerVersion is the identification string the fixture's SSH servers send.
const SSHServerVersion = "SSH-2.0-ParityFixture_1.0"

// CertDNSName is the only name in the fixture's leaf certificates. The paths
// probe an IP address, so every one of them should report a validation status
// for an untrusted chain, not a hostname mismatch.
const CertDNSName = "parity.example"

// Case names. Exported so gap entries and per-module assertions refer to the
// same strings.
const (
	CaseTLS13Only      = "tls13-only"
	CaseTLS13Classical = "tls13-classical-kex-only"
	CaseTLS10To13      = "tls10-to-13"
	CaseTLS12RSA       = "tls12-rsa"
	CaseTLS12ECDSA     = "tls12-ecdsa"
	CaseTLSMTLSRequest = "tls-client-cert-requested"
	CaseTLSMTLSRequire = "tls-client-cert-required"
	CaseTLSWellKnown   = "tls-wellknown-port-8443"
	CaseTLSNonStandard = "tls-nonstandard-port"
	CaseSSHWellKnown   = "ssh-wellknown-port-2222"
	CaseSSHNonStandard = "ssh-nonstandard-port"
	CaseClosed         = "closed-port"
	CaseSilent         = "silent-port"
)

// Kind is what a case's listener speaks.
type Kind string

// Listener kinds.
const (
	KindTLS    Kind = "tls"
	KindSSH    Kind = "ssh"
	KindClosed Kind = "closed"
	KindSilent Kind = "silent"
)

// Case is one listener of the fixture network.
type Case struct {
	Name string
	Kind Kind
	Port int
	// Unavailable is set when the case could not be bound (a fixed port in use
	// on this machine). Such a case has no port and is left out of Ports(); its
	// comparisons are skipped, visibly.
	Unavailable string

	// Ground truth, for KindTLS.
	TLSMin, TLSMax  uint16
	CipherSuite     uint16 // 0 when the server's choice is not pinned (TLS 1.3)
	ChainSHA256     []string
	ClientCertAsked bool
	// ClassicalKexOnly: the server offers no hybrid post-quantum group.
	ClassicalKexOnly bool
	// Ground truth, for KindSSH.
	HostKeyType        string
	HostKeyFingerprint string
}

// Network is the fixture: one loopback address, a listener per case.
type Network struct {
	Addr  string
	Cases []*Case

	mu      sync.Mutex
	closers []io.Closer
	wg      sync.WaitGroup
}

// Ports returns every bound case's port, in case order.
func (n *Network) Ports() []int {
	var out []int
	for _, c := range n.Cases {
		if c.Unavailable == "" {
			out = append(out, c.Port)
		}
	}
	return out
}

// CaseForPort returns the case bound to port, or nil.
func (n *Network) CaseForPort(port int) *Case {
	for _, c := range n.Cases {
		if c.Unavailable == "" && c.Port == port {
			return c
		}
	}
	return nil
}

// Case returns the named case, or nil.
func (n *Network) Case(name string) *Case {
	for _, c := range n.Cases {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// RanCases is the set of case names that were bound.
func (n *Network) RanCases() map[string]bool {
	out := map[string]bool{}
	for _, c := range n.Cases {
		if c.Unavailable == "" {
			out[c.Name] = true
		}
	}
	return out
}

func (n *Network) track(c io.Closer) {
	n.mu.Lock()
	n.closers = append(n.closers, c)
	n.mu.Unlock()
}

func (n *Network) close() {
	n.mu.Lock()
	cs := n.closers
	n.closers = nil
	n.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
	n.wg.Wait()
}

// pki is the fixture's certificate hierarchy: root → intermediate → leaves.
// Servers present leaf + intermediate, the shape nearly every real endpoint
// serves, so chain order is exercised.
type pki struct {
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
}

func newPKI(t testing.TB) *pki {
	t.Helper()
	rootKey := mustECDSA(t)
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Parity Fixture Root CA", Organization: []string{"Parity Fixture"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	interKey := mustECDSA(t)
	inter := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Parity Fixture Intermediate CA", Organization: []string{"Parity Fixture"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, inter, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate cert: %v", err)
	}
	interCert, _ := x509.ParseCertificate(interDER)
	return &pki{interCert: interCert, interKey: interKey}
}

func mustECDSA(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	return k
}

// leaf issues a server certificate for CertDNSName with an RSA-2048 or ECDSA
// P-256 key, and returns it with the SHA-256 fingerprints of the chain it is
// served with (leaf, intermediate).
func (p *pki) leaf(t testing.TB, serial int64, useRSA bool) (tls.Certificate, []string) {
	t.Helper()
	var pub, priv any
	if useRSA {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa key: %v", err)
		}
		pub, priv = &k.PublicKey, k
	} else {
		k := mustECDSA(t)
		pub, priv = &k.PublicKey, k
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: CertDNSName, Organization: []string{"Parity Fixture"}},
		DNSNames:     []string{CertDNSName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.interCert, pub, p.interKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, p.interCert.Raw}, PrivateKey: priv},
		[]string{sha256Hex(der), sha256Hex(p.interCert.Raw)}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Start binds the fixture network on addr (one of the *SuiteAddr constants)
// and tears it down when t ends. It skips t when addr cannot be bound at all
// (a platform whose loopback is only 127.0.0.1); a single fixed well-known
// port already in use marks only that case Unavailable. That also happens,
// by design, when one module's tests run twice at once on the same address
// (the shared/ CI leg runs its plain and ambient-DB passes concurrently): the
// second run logs the two fixed-port cases NOT RUN and never scans them, so
// neither run's probes reach the other's listener.
func Start(t testing.TB, addr string) *Network {
	t.Helper()
	probe, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	_ = probe.Close()

	n := &Network{Addr: addr}
	t.Cleanup(n.close)
	p := newPKI(t)

	type tlsSpec struct {
		name     string
		port     int
		min, max uint16
		suite    uint16
		rsa      bool
		auth     tls.ClientAuthType
		curves   []tls.CurveID
	}
	specs := []tlsSpec{
		{name: CaseTLS13Only, min: tls.VersionTLS13, max: tls.VersionTLS13},
		// TLS 1.3 without the hybrid ML-KEM group Go offers by default: the
		// one case where "does the server support PQC hybrid key exchange?"
		// is answered NO, which only a dedicated support handshake can learn.
		{name: CaseTLS13Classical, min: tls.VersionTLS13, max: tls.VersionTLS13, curves: []tls.CurveID{tls.X25519, tls.CurveP256}},
		{name: CaseTLS10To13, min: tls.VersionTLS10, max: tls.VersionTLS13, rsa: true},
		{name: CaseTLS12RSA, min: tls.VersionTLS12, max: tls.VersionTLS12, suite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, rsa: true},
		{name: CaseTLS12ECDSA, min: tls.VersionTLS12, max: tls.VersionTLS12, suite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{name: CaseTLSMTLSRequest, min: tls.VersionTLS12, max: tls.VersionTLS13, auth: tls.RequestClientCert},
		// Required, and TLS 1.2 only, so the refusal happens INSIDE the
		// handshake every path runs (under TLS 1.3 the client's handshake
		// completes before the server rejects the empty certificate).
		{name: CaseTLSMTLSRequire, min: tls.VersionTLS12, max: tls.VersionTLS12, suite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, auth: tls.RequireAnyClientCert},
		{name: CaseTLSWellKnown, port: WellKnownTLSPort, min: tls.VersionTLS12, max: tls.VersionTLS13},
		{name: CaseTLSNonStandard, min: tls.VersionTLS12, max: tls.VersionTLS13},
	}
	for i, s := range specs {
		cert, chain := p.leaf(t, int64(100+i), s.rsa)
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   s.min, //nolint:gosec // the fixture deliberately accepts legacy TLS
			MaxVersion:   s.max,
			ClientAuth:   s.auth,
		}
		if s.suite != 0 {
			cfg.CipherSuites = []uint16{s.suite}
		}
		if s.curves != nil {
			cfg.CurvePreferences = s.curves
		}
		c := &Case{
			Name: s.name, Kind: KindTLS, TLSMin: s.min, TLSMax: s.max, CipherSuite: s.suite,
			ChainSHA256: chain, ClientCertAsked: s.auth != tls.NoClientCert, ClassicalKexOnly: s.curves != nil,
		}
		ln, why := n.listen(addr, s.port)
		if ln == nil {
			c.Unavailable = why
		} else {
			c.Port = ln.Addr().(*net.TCPAddr).Port
			n.serveTLS(ln, cfg)
		}
		n.Cases = append(n.Cases, c)
	}

	for _, s := range []struct {
		name string
		port int
	}{{CaseSSHWellKnown, WellKnownSSHPort}, {CaseSSHNonStandard, 0}} {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ssh host key: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("ssh signer: %v", err)
		}
		fp := sha256.Sum256(signer.PublicKey().Marshal())
		c := &Case{
			Name: s.name, Kind: KindSSH, HostKeyType: signer.PublicKey().Type(),
			HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(fp[:]),
		}
		ln, why := n.listen(addr, s.port)
		if ln == nil {
			c.Unavailable = why
		} else {
			c.Port = ln.Addr().(*net.TCPAddr).Port
			n.serveSSH(ln, signer)
		}
		n.Cases = append(n.Cases, c)
	}

	closed := &Case{Name: CaseClosed, Kind: KindClosed, Port: FreedPorts(t, addr, 1)[0]}
	silent := &Case{Name: CaseSilent, Kind: KindSilent}
	ln, why := n.listen(addr, 0)
	if ln == nil {
		silent.Unavailable = why
	} else {
		silent.Port = ln.Addr().(*net.TCPAddr).Port
		n.serveSilent(ln)
	}
	n.Cases = append(n.Cases, closed, silent)
	return n
}

func (n *Network) listen(addr string, port int) (net.Listener, string) {
	ln, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return nil, err.Error()
	}
	n.track(ln)
	return ln, ""
}

// acceptLoop runs handle on every accepted connection until the listener is
// closed; each connection is closed when handle returns or the network shuts.
func (n *Network) acceptLoop(ln net.Listener, handle func(net.Conn)) {
	n.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.track(c)
			n.wg.Go(func() {
				defer func() { _ = c.Close() }()
				// Bounded: no fixture connection outlives a minute even if a
				// path under test never closes its side.
				_ = c.SetDeadline(time.Now().Add(time.Minute))
				handle(c)
			})
		}
	})
}

func (n *Network) serveTLS(ln net.Listener, cfg *tls.Config) {
	n.acceptLoop(ln, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, tc)
	})
}

func (n *Network) serveSSH(ln net.Listener, signer ssh.Signer) {
	cfg := &ssh.ServerConfig{
		ServerVersion: SSHServerVersion,
		// Every authentication attempt is refused; the paths under test only
		// complete the key exchange and never authenticate.
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, errRefused
		},
	}
	cfg.AddHostKey(signer)
	n.acceptLoop(ln, func(c net.Conn) {
		sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "parity fixture")
		}
		_ = sc.Close()
	})
}

// serveSilent accepts and never writes: a client-speaks-first service that
// does not answer anything the probes send.
func (n *Network) serveSilent(ln net.Listener) {
	n.acceptLoop(ln, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
}

type refusedErr struct{}

func (refusedErr) Error() string { return "parity fixture refuses authentication" }

var errRefused error = refusedErr{}

// FreedPorts returns n ports that were just bound on addr and released, so a
// connect to them is refused.
func FreedPorts(t testing.TB, addr string, n int) []int {
	t.Helper()
	var lns []net.Listener
	var out []int
	for range n {
		ln, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
		if err != nil {
			t.Fatalf("listen %s: %v", addr, err)
		}
		lns = append(lns, ln)
		out = append(out, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return out
}

// TimingNetwork is a target for the wall-clock measurement: closed closed
// ports and silent silent ports, nothing that answers. It is the shape that
// made the legacy sensor slow — every requested protocol probed on every port,
// serially, each waiting out its timeout.
func TimingNetwork(t testing.TB, addr string, closed, silent int) []int {
	t.Helper()
	probe, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	_ = probe.Close()
	n := &Network{Addr: addr}
	t.Cleanup(n.close)
	ports := FreedPorts(t, addr, closed)
	for range silent {
		ln, why := n.listen(addr, 0)
		if ln == nil {
			t.Fatalf("listen %s: %s", addr, why)
		}
		n.serveSilent(ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

// The timing target's shape: several ports that refuse and several that
// accept and stay silent.
const (
	TimingClosedPorts = 4
	TimingSilentPorts = 2
)
