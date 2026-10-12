package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

func selfSignedPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func assertUsesProxyEnvironment(t *testing.T, name string, rt http.RoundTripper) {
	t.Helper()
	tr, ok := rt.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("%s: transport is %T, want *http.Transport", name, rt)
	}
	if tr.Proxy == nil {
		t.Fatalf("%s: transport has nil Proxy; HTTPS_PROXY is ignored", name)
	}
}

// http.ProxyFromEnvironment caches the environment for the life of the
// process, so this asserts the transport is proxy-aware (non-nil Proxy); the
// behaviour of the function itself is covered in shared/httpclient.
//
// After enrolment the agent's transport is an mTLS transport; it must still
// honour HTTPS_PROXY.
func TestMTLSTransportsHonourProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	certPEM, keyPEM := selfSignedPair(t)
	cfg := &config.Config{
		PlatformURL: "https://platform.example.test",
		Security:    config.SecurityConfig{UseTLS: true, ClientCert: certPEM, ClientKey: keyPEM, ServerCACert: certPEM},
	}

	t.Run("at construction", func(t *testing.T) {
		assertUsesProxyEnvironment(t, "NewOutboundClient", NewOutboundClient(cfg).httpClient.Transport)
	})
	t.Run("after rotation", func(t *testing.T) {
		c := NewOutboundClient(cfg)
		c.httpClient.Transport = &http.Transport{}
		if err := c.reconfigureTLS(); err != nil {
			t.Fatal(err)
		}
		assertUsesProxyEnvironment(t, "reconfigureTLS", c.httpClient.Transport)
	})
}
