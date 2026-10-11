package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Trust from an organisation's decisions (TrustedRoots) and distrust that
// overrides even the system store (DistrustedFingerprintsSHA256), plus the
// credential-free chain capture behind "Trust this CA".

// intermediate issues a CA certificate signed by parent.
func (ca testCA) intermediate(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key}
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// chainedBackend serves leaf + intermediate, the way a real server presents
// a chain, and counts the HTTP requests that reach it.
func chainedBackend(t *testing.T, root testCA, host string) (addr string, inter testCA, leaf tls.Certificate, hits *atomic.Int32) {
	t.Helper()
	inter = root.intermediate(t, "Example Issuing CA")
	leaf = inter.issue(t, host)
	leaf.Certificate = append(leaf.Certificate, inter.cert.Raw)
	hits = &atomic.Int32{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), inter, leaf, hits
}

func viaProxy(t *testing.T, host, backend string) egressDeps {
	t.Helper()
	proxy := newTestProxy(t)
	proxy.tunnels[host+":443"] = backend
	return egressDeps{
		proxy:       alwaysVia(proxy.url()),
		lookup:      fakeDNS(nil),
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
	}
}

// An organisation's trusted CA reaches the pool; without it the same server
// is an unknown authority. MUTATION: drop TrustedRoots from trustConfig's
// `extra` and the first assertion fails.
func TestEgress_TrustedRootsAreTrusted(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	root := newTestCA(t, "Example Private Root")
	addr, _, _, _ := chainedBackend(t, root, "cmdb.example.com")
	deps := viaProxy(t, "cmdb.example.com", addr)

	with := egressClient(t, EgressOptions{TrustedRoots: []*x509.Certificate{root.cert}}, deps)
	if _, err := get(with, "https://cmdb.example.com/"); err != nil {
		t.Fatalf("with the trusted root: %v", err)
	}
	without := egressClient(t, EgressOptions{}, deps)
	var unknown x509.UnknownAuthorityError
	if _, err := get(without, "https://cmdb.example.com/"); !errors.As(err, &unknown) {
		t.Fatalf("without the trusted root = %v; want x509.UnknownAuthorityError", err)
	}
}

// A distrusted INTERMEDIATE fails the handshake although its root is trusted —
// by the system store, here, which is the case CertPool cannot express.
// MUTATION: remove the VerifyConnection assignment in trustConfig and this
// connects.
func TestEgress_DistrustedIntermediateFailsTheHandshake(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	root := newTestCA(t, "Example Root The OS Trusts")
	addr, inter, _, hits := chainedBackend(t, root, "netbox.example.com")
	deps := viaProxy(t, "netbox.example.com", addr)
	system := x509.NewCertPool()
	system.AddCert(root.cert)
	deps.systemRoots = func() (*x509.CertPool, error) { return system, nil }

	// Control: distrusting some UNRELATED certificate leaves the system-trusted
	// chain verifying (and builds the pool from deps.systemRoots, as below).
	trusted := egressClient(t, EgressOptions{DistrustedFingerprintsSHA256: []string{strings.Repeat("ab", 32)}}, deps)
	if _, err := get(trusted, "https://netbox.example.com/"); err != nil {
		t.Fatalf("control: the system-trusted chain should verify: %v", err)
	}
	before := hits.Load()

	distrust := egressClient(t, EgressOptions{DistrustedFingerprintsSHA256: []string{strings.ToUpper(fingerprint(inter.cert))}}, deps)
	_, err := get(distrust, "https://netbox.example.com/")
	var d *DistrustedCAError
	if !errors.As(err, &d) {
		t.Fatalf("distrusted intermediate = %v; want *DistrustedCAError", err)
	}
	if d.FingerprintSHA256 != fingerprint(inter.cert) {
		t.Errorf("error names %s; want the intermediate %s", d.FingerprintSHA256, fingerprint(inter.cert))
	}
	if hits.Load() != before {
		t.Error("a request reached the server through a distrusted chain")
	}
}

// Distrust wins over an explicit trust of the same root, too.
func TestEgress_DistrustOverridesTrustedRoots(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	root := newTestCA(t, "Example Retiring Root")
	addr, _, _, _ := chainedBackend(t, root, "cmdb.example.com")
	deps := viaProxy(t, "cmdb.example.com", addr)
	c := egressClient(t, EgressOptions{
		TrustedRoots:                 []*x509.Certificate{root.cert},
		DistrustedFingerprintsSHA256: []string{fingerprint(root.cert)},
	}, deps)
	var d *DistrustedCAError
	if _, err := get(c, "https://cmdb.example.com/"); !errors.As(err, &d) {
		t.Fatalf("= %v; want *DistrustedCAError", err)
	}
}

func TestNewEgressClient_RefusesAMalformedDistrustFingerprint(t *testing.T) {
	for _, fp := range []string{"abc", "zz" + strings.Repeat("0", 62), strings.Repeat("0", 62)} {
		if _, err := NewEgressClient(time.Second, EgressOptions{DistrustedFingerprintsSHA256: []string{fp}}); err == nil {
			t.Errorf("fingerprint %q accepted; distrust that cannot match must not pass silently", fp)
		}
	}
	colons := strings.ToUpper(strings.Join(splitPairs(strings.Repeat("ab", 32)), ":"))
	if _, err := NewEgressClient(time.Second, EgressOptions{DistrustedFingerprintsSHA256: []string{colons}}); err != nil {
		t.Errorf("a colon-separated upper-case fingerprint was refused: %v", err)
	}
}

func splitPairs(s string) []string {
	var out []string
	for i := 0; i+2 <= len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return out
}

// The trust settings reach BOTH transports.
func TestEgress_TrustSettingsReachBothTransports(t *testing.T) {
	root := newTestCA(t, "Example Private Root")
	c := egressClient(t, EgressOptions{
		TrustedRoots:                 []*x509.Certificate{root.cert},
		DistrustedFingerprintsSHA256: []string{strings.Repeat("ab", 32)},
	}, egressDeps{})
	tr := c.Transport.(*egressTransport)
	for name, inner := range map[string]*http.Transport{"direct": tr.direct, "proxied": tr.proxied} {
		cfg := inner.TLSClientConfig
		if cfg == nil || cfg.RootCAs == nil || cfg.VerifyConnection == nil {
			t.Fatalf("%s transport lacks the trust settings", name)
		}
		if _, err := root.cert.Verify(x509.VerifyOptions{Roots: cfg.RootCAs}); err != nil {
			t.Errorf("%s transport does not trust the root: %v", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// CapturePresentedChain
// ---------------------------------------------------------------------------

// The chain is read leaf first, through the operator's proxy, and NO request
// reaches the server. MUTATION: return nil from the probe's VerifyConnection
// and the handshake completes, the HEAD reaches the handler, and this fails.
func TestCapturePresentedChain_ReadsTheChainAndSendsNothing(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	root := newTestCA(t, "Example Private Root")
	addr, inter, leaf, hits := chainedBackend(t, root, "netbox.example.com")
	deps := viaProxy(t, "netbox.example.com", addr)

	chain, err := capturePresentedChain(context.Background(), "https://netbox.example.com/api/?q=x",
		5*time.Second, EgressOptions{}, deps)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("captured %d certificates; want leaf + intermediate", len(chain))
	}
	if fingerprint(chain[0]) != fingerprint(mustParse(t, leaf.Certificate[0])) || fingerprint(chain[1]) != fingerprint(inter.cert) {
		t.Error("captured chain is not leaf-first as presented")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d request(s) reached the server; the capture must send nothing", n)
	}
}

// The guard is the real client's: a target the options do not allow is
// refused before any handshake.
func TestCapturePresentedChain_AppliesTheEgressGuard(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	root := newTestCA(t, "Example Private Root")
	addr, _, _, hits := chainedBackend(t, root, "netbox.example.com")

	// Direct to loopback: never reachable, opt-in or not.
	if _, err := capturePresentedChain(context.Background(), "https://"+addr+"/", time.Second,
		EgressOptions{AllowPrivateEndpoint: true}, egressDeps{proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}); err == nil {
		t.Error("capture reached a loopback address")
	}
	// Proxied to a private address without the opt-in.
	deps := viaProxy(t, "nb.example.com", addr)
	deps.lookup = fakeDNS(map[string]string{"nb.example.com": "10.1.2.3"})
	if _, err := capturePresentedChain(context.Background(), "https://nb.example.com/", time.Second,
		EgressOptions{}, deps); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Errorf("capture of a private target without the opt-in = %v; want the guard's refusal", err)
	}
	if _, err := capturePresentedChain(context.Background(), "http://nb.example.com/", time.Second,
		EgressOptions{}, deps); err == nil {
		t.Error("an http:// URL was accepted")
	}
	if hits.Load() != 0 {
		t.Error("a refused capture reached the server")
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
