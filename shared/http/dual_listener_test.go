package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCertBundle holds a self-signed CA plus a leaf certificate signed by
// it, written to PEM files on disk (mirroring the cert-manager-mounted
// layout every service reads at SERVICE_CERT_PATH/SERVICE_KEY_PATH/
// PLATFORM_CA_CERT_PATH).
type testCertBundle struct {
	caCertPath   string
	leafCertPath string
	leafKeyPath  string
	// tlsCert is the leaf cert+key as a tls.Certificate, usable as either
	// the server identity or a client identity — both are signed by the
	// same CA, which is exactly what the mesh's single Platform CA does.
	tlsCert tls.Certificate
	caPool  *x509.CertPool
}

func newTestCertBundle(t *testing.T) testCertBundle {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-platform-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-service"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})

	caCertPath := filepath.Join(dir, "ca.crt")
	leafCertPath := filepath.Join(dir, "tls.crt")
	leafKeyPath := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(caCertPath, caPEM, 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	if err := os.WriteFile(leafCertPath, leafCertPEM, 0o600); err != nil {
		t.Fatalf("write tls.crt: %v", err)
	}
	if err := os.WriteFile(leafKeyPath, leafKeyPEM, 0o600); err != nil {
		t.Fatalf("write tls.key: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		t.Fatalf("build tls.Certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return testCertBundle{
		caCertPath:   caCertPath,
		leafCertPath: leafCertPath,
		leafKeyPath:  leafKeyPath,
		tlsCert:      tlsCert,
		caPool:       pool,
	}
}

// freePort asks the OS for an ephemeral port and immediately releases it.
// There's an inherent (tiny) TOCTOU race, but it's the standard pattern for
// tests that need a real listener on a real port rather than :0 (StartDual-
// Listeners takes a port string, not a net.Listener).
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener at %s did not come up in time", addr)
}

// TestStartDualListeners_MTLSSelectsTwoListeners is the load-bearing
// regression test for M-14: pcap-processor and tenant-health-service ran
// with USE_MTLS=true but never called StartDualListeners (or any
// equivalent), so they only ever bound :8080. This pins that, when
// UseMTLS is true, StartDualListeners actually brings up BOTH a plaintext
// probe listener (what kubelet needs) and an mTLS-only API listener (what
// monitoring-service's version aggregator and S2S callers using PeerURL()
// need) — and that the mTLS listener genuinely rejects a client with no
// certificate, and genuinely serves a client presenting one signed by the
// configured CA.
func TestStartDualListeners_MTLSSelectsTwoListeners(t *testing.T) {
	bundle := newTestCertBundle(t)
	apiPort := freePort(t)
	probePort := freePort(t)

	apiHandler := http.NewServeMux()
	apiHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"healthy"}`)
	})
	probeHandler := http.NewServeMux()
	probeHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"healthy"}`)
	})

	dl, err := StartDualListeners(DualListenerConfig{
		APIHandler:   apiHandler,
		ProbeHandler: probeHandler,
		UseMTLS:      true,
		APIPort:      apiPort,
		ProbePort:    probePort,
		CertPath:     bundle.leafCertPath,
		KeyPath:      bundle.leafKeyPath,
		CACertPath:   bundle.caCertPath,
	})
	if err != nil {
		t.Fatalf("StartDualListeners: %v", err)
	}
	t.Cleanup(func() {
		_ = dl.Shutdown(context.Background())
	})

	waitForListener(t, "127.0.0.1:"+apiPort)
	waitForListener(t, "127.0.0.1:"+probePort)

	// Probe listener: plain HTTP, no client cert needed — this is what
	// kubelet's liveness/readiness probes rely on.
	probeResp, err := http.Get("http://127.0.0.1:" + probePort + "/health")
	if err != nil {
		t.Fatalf("plain probe request failed: %v", err)
	}
	defer func() { _ = probeResp.Body.Close() }()
	if probeResp.StatusCode != http.StatusOK {
		t.Fatalf("probe listener status = %d, want 200", probeResp.StatusCode)
	}

	// API listener without a client cert must be REJECTED — this is the
	// property that makes it an mTLS listener at all, not just TLS.
	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: bundle.caPool},
		},
		Timeout: 3 * time.Second,
	}
	if _, err := noCertClient.Get("https://127.0.0.1:" + apiPort + "/health"); err == nil {
		t.Fatalf("expected mTLS API listener to reject a request with no client certificate, it succeeded")
	}

	// API listener WITH a client cert signed by the configured CA must
	// succeed — this is the S2S / PeerURL() path (and the same call
	// monitoring-service's version aggregator makes).
	withCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      bundle.caPool,
				Certificates: []tls.Certificate{bundle.tlsCert},
			},
		},
		Timeout: 3 * time.Second,
	}
	apiResp, err := withCertClient.Get("https://127.0.0.1:" + apiPort + "/health")
	if err != nil {
		t.Fatalf("mTLS request with valid client cert failed: %v", err)
	}
	defer func() { _ = apiResp.Body.Close() }()
	if apiResp.StatusCode != http.StatusOK {
		t.Fatalf("mTLS API listener status = %d, want 200", apiResp.StatusCode)
	}
}

// TestStartDualListeners_PlainHTTPSingleListener pins the UseMTLS=false
// branch: a single plaintext listener on APIPort serving APIHandler, and
// no separate probe listener is started (ProbeHandler is ignored).
func TestStartDualListeners_PlainHTTPSingleListener(t *testing.T) {
	port := freePort(t)

	apiHandler := http.NewServeMux()
	apiHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"healthy"}`)
	})

	dl, err := StartDualListeners(DualListenerConfig{
		APIHandler: apiHandler,
		UseMTLS:    false,
		APIPort:    port,
	})
	if err != nil {
		t.Fatalf("StartDualListeners: %v", err)
	}
	t.Cleanup(func() {
		_ = dl.Shutdown(context.Background())
	})

	waitForListener(t, "127.0.0.1:"+port)

	if dl.probeServer != nil {
		t.Fatalf("expected no probe server when UseMTLS is false")
	}

	resp, err := http.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		t.Fatalf("plain HTTP request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestStartDualListeners_MTLSRequiresProbeHandler pins the fail-fast guard:
// UseMTLS=true with no ProbeHandler must error out at startup rather than
// silently never binding the plaintext port kubelet needs — that silent
// gap is exactly the M-14 bug in a different shape.
func TestStartDualListeners_MTLSRequiresProbeHandler(t *testing.T) {
	bundle := newTestCertBundle(t)
	apiHandler := http.NewServeMux()

	_, err := StartDualListeners(DualListenerConfig{
		APIHandler: apiHandler,
		UseMTLS:    true,
		APIPort:    freePort(t),
		ProbePort:  freePort(t),
		CertPath:   bundle.leafCertPath,
		KeyPath:    bundle.leafKeyPath,
		CACertPath: bundle.caCertPath,
	})
	if err == nil {
		t.Fatal("expected error when UseMTLS=true and ProbeHandler is nil, got nil")
	}
}

// TestStartDualListeners_MTLSRequiresCertPaths pins the other fail-fast
// guard: UseMTLS=true with any cert path missing must error rather than
// panic or silently fall back to plaintext.
func TestStartDualListeners_MTLSRequiresCertPaths(t *testing.T) {
	apiHandler := http.NewServeMux()
	probeHandler := http.NewServeMux()

	_, err := StartDualListeners(DualListenerConfig{
		APIHandler:   apiHandler,
		ProbeHandler: probeHandler,
		UseMTLS:      true,
		APIPort:      freePort(t),
		ProbePort:    freePort(t),
		// CertPath/KeyPath/CACertPath deliberately omitted.
	})
	if err == nil {
		t.Fatal("expected error when UseMTLS=true and cert paths are empty, got nil")
	}
}
