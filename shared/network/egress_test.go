package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests pin the egress primitive in BOTH polarities. The bug it fixes
// (B12) was the over-strict one — a proxy on a private address was refused, so
// every guarded client failed behind HTTPS_PROXY — and the obvious fix for it
// (trust the proxy, stop looking) is the under-strict one. Each allow below has
// a refusal next to it that fails if the target stops being judged.

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// testProxy is a minimal forward proxy: absolute-form HTTP requests are
// answered by the proxy itself (it never goes on to the network), and CONNECT
// is tunnelled to a local backend chosen by the requested host:port.
type testProxy struct {
	srv     *httptest.Server
	mu      sync.Mutex
	seen    []string
	tunnels map[string]string
}

func newTestProxy(t *testing.T) *testProxy {
	t.Helper()
	p := &testProxy{tunnels: map[string]string{}}
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *testProxy) url() *url.URL {
	u, _ := url.Parse(p.srv.URL)
	return u
}

func (p *testProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func (p *testProxy) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	if r.Method == http.MethodConnect {
		p.seen = append(p.seen, "CONNECT "+r.Host)
	} else {
		p.seen = append(p.seen, r.Method+" "+r.URL.String())
	}
	backend := p.tunnels[r.Host]
	p.mu.Unlock()

	if r.Method != http.MethodConnect {
		if r.URL.Path == "/redirect-to-metadata" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		_, _ = fmt.Fprintf(w, "proxied %s", r.URL.String())
		return
	}
	if backend == "" {
		http.Error(w, "no tunnel configured", http.StatusBadGateway)
		return
	}
	upstream, err := net.Dial("tcp", backend)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() {
		_, _ = io.Copy(upstream, buf)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
}

func alwaysVia(proxy *url.URL) func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) { return proxy, nil }
}

// fakeDNS answers from a fixed table and fails for anything else, so the
// tests never depend on the resolver of the machine running them.
func fakeDNS(table map[string]string) func(context.Context, string) ([]net.IP, error) {
	return func(_ context.Context, host string) ([]net.IP, error) {
		if ip, ok := table[host]; ok {
			return []net.IP{net.ParseIP(ip)}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
}

func egressClient(t *testing.T, opts EgressOptions, deps egressDeps) *http.Client {
	t.Helper()
	c, err := newEgressClient(5*time.Second, opts, deps)
	if err != nil {
		t.Fatalf("newEgressClient: %v", err)
	}
	return c
}

// privateEgressClient is the production constructor with the private-endpoint
// opt-in on and the operator switch left at its default.
func privateEgressClient(t *testing.T, timeout time.Duration) *http.Client {
	t.Helper()
	t.Setenv(ConnectorAllowPrivateEndpointsEnv, "")
	c, err := NewEgressClient(timeout, EgressOptions{AllowPrivateEndpoint: true})
	if err != nil {
		t.Fatalf("NewEgressClient: %v", err)
	}
	return c
}

func get(c *http.Client, target string) (string, error) {
	resp, err := c.Get(target)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return string(body), fmt.Errorf("status %d", resp.StatusCode)
	}
	return string(body), nil
}

// ---------------------------------------------------------------------------
// B12: behind a proxy, judge the target — not the proxy
// ---------------------------------------------------------------------------

// The reported failure, reproduced: the proxy listens on loopback (as a
// sidecar or node-local proxy does, and as any RFC1918 proxy would fail the
// same way). Before the fix this returned
// "proxyconnect tcp: … ssrf guard: refusing to connect to internal address".
func TestEgress_ProxiedPublicTargetIsAllowed(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	proxy := newTestProxy(t)
	for _, allowPrivate := range []bool{false, true} {
		c := egressClient(t, EgressOptions{AllowPrivateEndpoint: allowPrivate}, egressDeps{
			proxy:  alwaysVia(proxy.url()),
			lookup: fakeDNS(map[string]string{"collector.example.com": "203.0.113.10"}),
		})
		for _, target := range []string{"http://203.0.113.10/events", "http://collector.example.com/events"} {
			body, err := get(c, target)
			if err != nil {
				t.Fatalf("allowPrivate=%v: proxied request to public %s failed: %v", allowPrivate, target, err)
			}
			if body != "proxied "+target {
				t.Errorf("allowPrivate=%v: body = %q; the request did not go through the proxy", allowPrivate, body)
			}
		}
	}
}

// The other polarity: going through the proxy must not stop the target being
// judged. Nothing here may reach the proxy at all.
func TestEgress_ProxiedNeverReachableTargetsAreRefused(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	t.Setenv(ConnectorAllowPrivateEndpointsEnv, "")
	for _, allowPrivate := range []bool{false, true} {
		proxy := newTestProxy(t)
		c := egressClient(t, EgressOptions{AllowPrivateEndpoint: allowPrivate}, egressDeps{
			proxy: alwaysVia(proxy.url()),
			lookup: fakeDNS(map[string]string{
				"rebind.example.com": "169.254.169.254",
				"loop.example.com":   "127.0.0.1",
			}),
		})
		for _, target := range []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://[fd00:ec2::254]/latest/meta-data/", // AWS IPv6 IMDS — ULA, so private-only
			"http://127.0.0.1:8080/",
			"http://[::1]/",
			"http://0.0.0.0/",
			"http://localhost:8080/",
			"http://metadata.google.internal/computeMetadata/v1/",
			"http://kubernetes.default.svc/api",
			"http://postgres.vista.svc.cluster.local:5432/",
			"http://rebind.example.com/",
			"http://loop.example.com/",
		} {
			if strings.Contains(target, "fd00:ec2") && allowPrivate {
				continue // ULA is the private half; covered by the private-target test
			}
			if _, err := get(c, target); err == nil || !strings.Contains(err.Error(), "ssrf guard") {
				t.Errorf("allowPrivate=%v: proxied %s = %v; want an ssrf guard refusal", allowPrivate, target, err)
			}
		}
		if seen := proxy.requests(); len(seen) != 0 {
			t.Errorf("allowPrivate=%v: refused targets still reached the proxy: %v", allowPrivate, seen)
		}
	}
}

func TestEgress_ProxiedPlatformInternalCIDRIsRefused(t *testing.T) {
	// A non-RFC1918 range, so the refusal can only come from the CIDR list and
	// not from the private-address rule.
	t.Setenv(PlatformInternalCIDRsEnv, "198.51.100.0/24")
	t.Setenv(ConnectorAllowPrivateEndpointsEnv, "")
	for _, allowPrivate := range []bool{false, true} {
		proxy := newTestProxy(t)
		c := egressClient(t, EgressOptions{AllowPrivateEndpoint: allowPrivate}, egressDeps{
			proxy:  alwaysVia(proxy.url()),
			lookup: fakeDNS(map[string]string{"svc.example.com": "198.51.100.7"}),
		})
		for _, target := range []string{"http://198.51.100.7/", "http://svc.example.com/"} {
			if _, err := get(c, target); err == nil || !strings.Contains(err.Error(), "platform-internal") {
				t.Errorf("allowPrivate=%v: proxied %s = %v; want a platform-internal refusal", allowPrivate, target, err)
			}
		}
		// Polarity: the CIDR list refuses what it lists and nothing else.
		if _, err := get(c, "http://203.0.113.10/"); err != nil {
			t.Errorf("allowPrivate=%v: a public target outside the CIDR list was refused: %v", allowPrivate, err)
		}
	}
}

func TestEgress_ProxiedPrivateTargetNeedsTheOptIn(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	const target = "http://10.20.30.40/api/"
	proxy := newTestProxy(t)
	deps := egressDeps{proxy: alwaysVia(proxy.url()), lookup: fakeDNS(nil)}

	t.Setenv(ConnectorAllowPrivateEndpointsEnv, "")
	if _, err := get(egressClient(t, EgressOptions{}, deps), target); err == nil ||
		!strings.Contains(err.Error(), "internal address") {
		t.Errorf("without the opt-in a proxied RFC1918 target = %v; want refusal", err)
	}
	if _, err := get(egressClient(t, EgressOptions{AllowPrivateEndpoint: true}, deps), target); err != nil {
		t.Errorf("with the opt-in a proxied RFC1918 target was refused: %v", err)
	}
	// The operator's switch wins over the tenant's opt-in.
	t.Setenv(ConnectorAllowPrivateEndpointsEnv, "false")
	if _, err := get(egressClient(t, EgressOptions{AllowPrivateEndpoint: true}, deps), target); err == nil {
		t.Error("CONNECTOR_ALLOW_PRIVATE_ENDPOINTS=false did not override the per-connection opt-in")
	}
}

// Egress-restricted clusters often cannot resolve public names — that is the
// proxy's job. A name we cannot resolve is handed to the proxy rather than
// refused (see checkProxiedTarget for why, and for what that concedes).
func TestEgress_UnresolvableProxiedNameIsDeferredToTheProxy(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	proxy := newTestProxy(t)
	c := egressClient(t, EgressOptions{}, egressDeps{proxy: alwaysVia(proxy.url()), lookup: fakeDNS(nil)})
	if _, err := get(c, "http://only-the-proxy-resolves.example.com/"); err != nil {
		t.Fatalf("a name only the proxy can resolve was refused: %v", err)
	}
}

// Every redirect hop goes back through RoundTrip and is judged again.
func TestEgress_RedirectThroughProxyIsJudgedAgain(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	proxy := newTestProxy(t)
	c := egressClient(t, EgressOptions{AllowPrivateEndpoint: true}, egressDeps{
		proxy: alwaysVia(proxy.url()), lookup: fakeDNS(nil),
	})
	_, err := get(c, "http://203.0.113.10/redirect-to-metadata")
	if err == nil || !strings.Contains(err.Error(), "never reachable") {
		t.Fatalf("a redirect to the metadata endpoint = %v; want the guard to refuse the second hop", err)
	}
	if seen := proxy.requests(); len(seen) != 1 {
		t.Errorf("proxy saw %v; only the first hop should have reached it", seen)
	}
}

// ---------------------------------------------------------------------------
// direct path: unchanged
// ---------------------------------------------------------------------------

func TestEgress_DirectPathIsStillGuardedAtDialTime(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	noProxy := func(*http.Request) (*url.URL, error) { return nil, nil }

	for _, allowPrivate := range []bool{false, true} {
		c := egressClient(t, EgressOptions{AllowPrivateEndpoint: allowPrivate}, egressDeps{proxy: noProxy})
		if _, err := get(c, srv.URL); err == nil || !strings.Contains(err.Error(), "ssrf guard") {
			t.Errorf("allowPrivate=%v: direct request to a loopback server = %v; want refusal", allowPrivate, err)
		}
	}
}

// The proxy is trusted because a request was ROUTED to it, never because of
// the address being dialled. A tenant URL naming the proxy's own host:port is
// sent direct by NO_PROXY or Go's loopback rule; it must not inherit the
// proxy's exemption.
func TestEgress_ProxyTrustIsNotKeyedOnItsAddress(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	t.Setenv(ConnectorAllowPrivateEndpointsEnv, "")
	proxy := newTestProxy(t)
	proxyURL := proxy.url()
	// Proxy everything except the proxy's own address, as NO_PROXY would.
	selective := func(req *http.Request) (*url.URL, error) {
		if req.URL.Host == proxyURL.Host {
			return nil, nil
		}
		return proxyURL, nil
	}
	for _, allowPrivate := range []bool{false, true} {
		c := egressClient(t, EgressOptions{AllowPrivateEndpoint: allowPrivate}, egressDeps{proxy: selective})
		if _, err := get(c, proxy.srv.URL+"/"); err == nil || !strings.Contains(err.Error(), "ssrf guard") {
			t.Errorf("allowPrivate=%v: a direct request to the proxy's own address = %v; want refusal", allowPrivate, err)
		}
	}
	if seen := proxy.requests(); len(seen) != 0 {
		t.Errorf("the proxy was reached directly: %v", seen)
	}
}

// End to end through the real proxy selection — http.ProxyFromEnvironment
// reading HTTP_PROXY — in a child process, because that function caches the
// environment once per process.
func TestEgress_HonoursHTTPProxyFromTheEnvironment(t *testing.T) {
	if os.Getenv("EGRESS_ENV_PROXY_CHILD") == "1" {
		opts, err := NewEgressClient(5*time.Second, EgressOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]*http.Client{"NewEgressClient": opts, "SafeHTTPClient": SafeHTTPClient(5 * time.Second)} {
			if body, err := get(c, "http://203.0.113.10/from-env"); err != nil || !strings.HasPrefix(body, "proxied ") {
				t.Fatalf("%s behind HTTP_PROXY: body=%q err=%v", name, body, err)
			}
		}
		return
	}
	proxy := newTestProxy(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestEgress_HonoursHTTPProxyFromTheEnvironment$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		"EGRESS_ENV_PROXY_CHILD=1",
		"HTTP_PROXY="+proxy.srv.URL, "http_proxy="+proxy.srv.URL,
		"NO_PROXY=", "no_proxy=", "REQUEST_METHOD=",
		PlatformInternalCIDRsEnv+"=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if seen := proxy.requests(); len(seen) != 2 {
		t.Errorf("proxy saw %v; want one request from each client", seen)
	}
}

// ---------------------------------------------------------------------------
// CA bundle
// ---------------------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T, name string) testCA {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca testCA) issue(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsBackend starts an HTTPS server presenting cert and returns its address.
func tlsBackend(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// An on-prem receiver whose certificate an internal CA issued: reachable with
// that CA's bundle, refused without it. The request goes through the proxy
// (CONNECT) because a loopback backend could not otherwise be reached past the
// guard — which also proves the bundle applies on the proxied path.
func TestEgress_CABundleTrustsAnInternalCA(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	ca := newTestCA(t, "Example Internal Root")
	proxy := newTestProxy(t)
	proxy.tunnels["netbox.example.com:443"] = tlsBackend(t, ca.issue(t, "netbox.example.com"))
	deps := egressDeps{
		proxy:  alwaysVia(proxy.url()),
		lookup: fakeDNS(map[string]string{"netbox.example.com": "203.0.113.20"}),
	}

	with := egressClient(t, EgressOptions{CABundlePEM: ca.pem}, deps)
	if body, err := get(with, "https://netbox.example.com/api/"); err != nil || body != "ok" {
		t.Fatalf("with the CA bundle: body=%q err=%v; want the internal-CA server to verify", body, err)
	}

	without := egressClient(t, EgressOptions{}, deps)
	var unknown x509.UnknownAuthorityError
	if _, err := get(without, "https://netbox.example.com/api/"); err == nil || !errors.As(err, &unknown) {
		t.Fatalf("without the CA bundle = %v; want x509.UnknownAuthorityError — verification must not be skipped", err)
	}
}

// The bundle is APPENDED to the system trust store. A replacement would make
// the connection unable to reach a publicly-signed endpoint.
func TestEgress_CABundleIsAddedToTheSystemRootsNotSubstituted(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "")
	public := newTestCA(t, "Stand-in Public Root")
	internal := newTestCA(t, "Example Internal Root")
	proxy := newTestProxy(t)
	proxy.tunnels["saas.example.com:443"] = tlsBackend(t, public.issue(t, "saas.example.com"))
	proxy.tunnels["cmdb.example.com:443"] = tlsBackend(t, internal.issue(t, "cmdb.example.com"))

	system := x509.NewCertPool()
	system.AddCert(public.cert)
	c := egressClient(t, EgressOptions{CABundlePEM: internal.pem}, egressDeps{
		proxy:       alwaysVia(proxy.url()),
		lookup:      fakeDNS(nil),
		systemRoots: func() (*x509.CertPool, error) { return system, nil },
	})
	for _, target := range []string{"https://saas.example.com/", "https://cmdb.example.com/"} {
		if _, err := get(c, target); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
	// And the system pool itself was not mutated by the append.
	if _, err := internal.cert.Verify(x509.VerifyOptions{Roots: system}); err == nil {
		t.Error("the shared system pool gained the tenant's CA; the bundle must be added to a clone")
	}
}

func TestEgress_DirectTransportCarriesTheBundle(t *testing.T) {
	ca := newTestCA(t, "Example Internal Root")
	c := egressClient(t, EgressOptions{CABundlePEM: ca.pem}, egressDeps{})
	tr := c.Transport.(*egressTransport)
	for name, inner := range map[string]*http.Transport{"direct": tr.direct, "proxied": tr.proxied} {
		if inner.TLSClientConfig == nil || inner.TLSClientConfig.RootCAs == nil {
			t.Errorf("%s transport has no RootCAs; the bundle would apply on one path only", name)
			continue
		}
		if _, err := ca.cert.Verify(x509.VerifyOptions{Roots: inner.TLSClientConfig.RootCAs}); err != nil {
			t.Errorf("%s transport does not trust the bundle's CA: %v", name, err)
		}
	}
	// No bundle: the transports keep Go's defaults rather than a custom config.
	plain := egressClient(t, EgressOptions{}, egressDeps{}).Transport.(*egressTransport)
	if plain.direct.TLSClientConfig != nil || plain.proxied.TLSClientConfig != nil {
		t.Error("a connection without a bundle should use the default TLS configuration")
	}
}

func TestValidateCABundlePEM(t *testing.T) {
	a := newTestCA(t, "A")
	b := newTestCA(t, "B")
	keyDER, _ := x509.MarshalECPrivateKey(a.key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	pubDER, _ := x509.MarshalPKIXPublicKey(&a.key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	broken := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))

	for _, ok := range []struct{ name, pem string }{
		{"empty", ""},
		{"whitespace", "  \n\t"},
		{"one certificate", a.pem},
		{"a chain of two", a.pem + b.pem},
		{"surrounding whitespace", "\n\n" + a.pem + "\n"},
	} {
		if err := ValidateCABundlePEM(ok.pem); err != nil {
			t.Errorf("%s: rejected a valid bundle: %v", ok.name, err)
		}
	}
	for _, bad := range []struct{ name, pem, mention string }{
		{"not PEM", "hello, this is not a certificate", "not PEM"},
		{"a private key", keyPEM, "private key"},
		{"a certificate and its key", a.pem + keyPEM, "private key"},
		{"a public key", pubPEM, "PUBLIC KEY"},
		{"undecodable certificate", broken, "does not parse"},
		{"trailing garbage", a.pem + "oops", "after its last certificate"},
		{"truncated paste", a.pem[:len(a.pem)-40], "not PEM"},
		{"oversized", strings.Repeat(a.pem, maxCABundleBytes/len(a.pem)+1), "limit"},
	} {
		err := ValidateCABundlePEM(bad.pem)
		if err == nil {
			t.Errorf("%s: accepted", bad.name)
			continue
		}
		if !strings.Contains(err.Error(), bad.mention) {
			t.Errorf("%s: error %q does not say %q", bad.name, err, bad.mention)
		}
	}
}

func TestNewEgressClient_RefusesToBuildWithAMalformedBundle(t *testing.T) {
	if _, err := NewEgressClient(time.Second, EgressOptions{CABundlePEM: "-----BEGIN CERTIFICATE-----\nnope\n"}); err == nil {
		t.Fatal("a client was built from a malformed CA bundle")
	}
}

func TestNewEgressClient_FailsClosedOnAMalformedPlatformCIDR(t *testing.T) {
	t.Setenv(PlatformInternalCIDRsEnv, "10.42.0.0/not-a-prefix")
	if _, err := NewEgressClient(time.Second, EgressOptions{}); err == nil ||
		!strings.Contains(err.Error(), PlatformInternalCIDRsEnv) {
		t.Fatalf("NewEgressClient = %v; want a configuration error", err)
	}
	// SafeHTTPClient cannot return an error, so its client refuses every request.
	proxy := newTestProxy(t)
	c := buildEgressClient(time.Second, newTargetPolicy(false), nil, egressDeps{proxy: alwaysVia(proxy.url())})
	if _, err := get(c, "http://203.0.113.10/"); err == nil || !strings.Contains(err.Error(), PlatformInternalCIDRsEnv) {
		t.Errorf("SafeHTTPClient with a malformed CIDR list = %v; want every request refused", err)
	}
}
