package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The job logger used to hand-roll a bare &http.Client{}. Under
// serviceMtls.enabled every peer URL derives to https://<svc>:8443 and the
// listener presents a certificate from the chart's private Platform CA, which
// nothing in the system trust store signs. The result was that every
// job-execution log written by the platform agent worker failed with
// "certificate signed by unknown authority" — and because the caller only logs
// the error, the jobs ran with no execution log at all.
//
// These tests exercise the real handshake against a server presenting a
// Platform-CA-style certificate. A client without the CA cannot pass them.

// mtlsFixture is a running TLS server plus the on-disk cert paths a client needs
// to reach it, mirroring what the chart mounts at /app/certs.
type mtlsFixture struct {
	server   *httptest.Server
	certPath string
	keyPath  string
	caPath   string
}

func newMTLSFixture(t *testing.T, handler http.Handler) *mtlsFixture {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Platform CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// One leaf, used as both the server's identity and the client's — the same
	// shape as the chart's per-service <svc>-mtls Secret.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "audit-service"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"audit-service", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	f := &mtlsFixture{
		certPath: filepath.Join(dir, "tls.crt"),
		keyPath:  filepath.Join(dir, "tls.key"),
		caPath:   filepath.Join(dir, "ca.crt"),
	}
	writePEM(t, f.certPath, "CERTIFICATE", leafDER)
	writePEM(t, f.keyPath, "EC PRIVATE KEY", leafKeyDER)
	writePEM(t, f.caPath, "CERTIFICATE", caDER)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.server = srv
	return f
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestNewJobLogger_ReachesMTLSAuditService is the regression guard: with the
// mesh env the chart injects, a job logger must complete the handshake against
// an audit-service presenting a Platform CA certificate.
func TestNewJobLogger_ReachesMTLSAuditService(t *testing.T) {
	var gotStart bool
	fx := newMTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/audit-service/job-execution-logs/start" {
			gotStart = true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.New().String() + `"}`))
	}))

	t.Setenv("USE_MTLS", "true")
	t.Setenv("CLIENT_CERT_PATH", fx.certPath)
	t.Setenv("CLIENT_KEY_PATH", fx.keyPath)
	t.Setenv("PLATFORM_CA_CERT_PATH", fx.caPath)

	tenantID := uuid.New()
	jl := NewJobLogger(fx.server.URL, uuid.New(), "device_interrogation", "device_interrogation", &tenantID, nil)

	if _, err := jl.LogStart(context.Background(), map[string]interface{}{"device_id": uuid.New().String()}); err != nil {
		t.Fatalf("LogStart against an mTLS audit-service failed — the client cannot verify the Platform CA: %v", err)
	}
	if !gotStart {
		t.Error("audit-service never saw the job-execution-logs/start request")
	}
}

// TestNewClientForEnv_PlaintextWhenMeshOff is the other polarity: with mTLS off
// the transport must stay the plain client it always was, and the peer URL must
// not be rewritten onto the mTLS listener.
func TestNewClientForEnv_PlaintextWhenMeshOff(t *testing.T) {
	t.Setenv("USE_MTLS", "false")
	t.Setenv("CLIENT_CERT_PATH", "")
	t.Setenv("CLIENT_KEY_PATH", "")
	t.Setenv("PLATFORM_CA_CERT_PATH", "")

	c := NewClientForEnv("http://audit-service:8080", 5*time.Second, 3, nil, false, "", "", "")
	if c.baseURL != "http://audit-service:8080" {
		t.Errorf("baseURL = %q, want the plaintext URL unchanged", c.baseURL)
	}
	if c.httpClient.Transport != nil {
		t.Errorf("expected the default transport with mTLS off, got %T", c.httpClient.Transport)
	}
}

// TestNewClientForEnv_RewritesPeerURLForMesh pins the URL half of the
// selection: under mTLS the audit peer is https://audit-service:8443, since
// :8080 is reduced to the kubelet health probe.
func TestNewClientForEnv_RewritesPeerURLForMesh(t *testing.T) {
	fx := newMTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Setenv("USE_MTLS", "true")

	c := NewClientForEnv("http://audit-service:8080", 5*time.Second, 3, nil, false, fx.certPath, fx.keyPath, fx.caPath)
	if c.baseURL != "https://audit-service:8443" {
		t.Errorf("baseURL = %q, want https://audit-service:8443", c.baseURL)
	}
	if c.httpClient.Transport == nil {
		t.Error("expected an mTLS transport, got the default one")
	}
}
