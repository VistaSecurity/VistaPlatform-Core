package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

// selfSignedPEM returns a throwaway ECDSA cert+key PEM pair for exercising the
// TLS transport wiring (no chain validation happens in these tests).
func selfSignedPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sensor-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// TestActivateMTLS_WiresClientCertAfterRegistration pins the sensor fix: the
// OutboundClient is constructed before registration (plain HTTP), and registration
// via SensorManagerClient stores certs on the shared config without touching this
// client's transport. ActivateMTLS must promote the transport to mTLS so the first
// post-registration session presents the client cert. Regression guard: before the
// fix the transport stayed nil (plain HTTP) and fail-closed sensor mTLS 401'd every
// call until a restart.
func TestActivateMTLS_WiresClientCertAfterRegistration(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)

	// Construct the client the way main does — BEFORE any cert is held.
	cfg := &config.Config{ControlPlaneURL: "https://cp.example.test"}
	c := NewOutboundClient(cfg)
	if c.httpClient.Transport != nil {
		t.Fatal("pre-registration transport should be default (plain HTTP), got a custom transport")
	}

	// Registration stores cert material on the shared config (as SensorManagerClient does).
	cfg.Security.ClientCert = certPEM
	cfg.Security.ClientKey = keyPEM
	cfg.Security.ServerCACert = certPEM // stand-in server anchor

	c.ActivateMTLS()

	if !cfg.Security.UseTLS {
		t.Fatal("ActivateMTLS did not set UseTLS")
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("ActivateMTLS did not install a TLS transport; got %T", c.httpClient.Transport)
	}
	if len(tr.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("client certificate not presented: got %d certs, want 1", len(tr.TLSClientConfig.Certificates))
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("server CA (RootCAs) not configured for platform-cert verification")
	}
	// Sanity: the presented keypair actually loads.
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		t.Fatalf("test keypair invalid: %v", err)
	}
}

// TestActivateMTLS_NoCertStaysPlain verifies ActivateMTLS is a safe no-op when no
// cert is held (dev / pre-registration / mTLS disabled) — it must not enable TLS
// or swap in a broken transport.
func TestActivateMTLS_NoCertStaysPlain(t *testing.T) {
	cfg := &config.Config{ControlPlaneURL: "http://cp.example.test"}
	c := NewOutboundClient(cfg)
	c.ActivateMTLS()
	if cfg.Security.UseTLS {
		t.Fatal("ActivateMTLS enabled UseTLS with no cert material")
	}
	if c.httpClient.Transport != nil {
		t.Fatal("ActivateMTLS installed a transport with no cert material")
	}
}

// TestServerCAAppliesBeforeClientCertExists is the regression guard for the
// trust-bootstrap fix. Both clients used to gate their whole TLS transport on
// already holding a client certificate, which made a pinned ServerCACert
// unreachable at the one moment it was needed: registration is itself an HTTPS
// call, and it is what ISSUES the client cert. Against a control plane whose
// edge cert is signed by a private CA, that circularity meant an operator could
// supply the correct CA and still never get past x509.
//
// Both clients must therefore build a verifying transport from a server CA
// alone. Mutation check: restore either `ClientCert == "" -> return nil` guard
// and this fails.
func TestServerCAAppliesBeforeClientCertExists(t *testing.T) {
	caPEM, _ := selfSignedPEM(t)

	cfg := &config.Config{
		ControlPlaneURL: "https://cp.example.test",
		// Pre-registration state: a CA to trust, and no client identity yet.
		Security: config.SecurityConfig{ServerCACert: caPEM},
	}

	t.Run("OutboundClient", func(t *testing.T) {
		c := NewOutboundClient(cfg)
		tr, ok := c.httpClient.Transport.(*http.Transport)
		if !ok || tr.TLSClientConfig == nil {
			t.Fatalf("no TLS transport built from a server CA alone; got %T", c.httpClient.Transport)
		}
		if tr.TLSClientConfig.RootCAs == nil {
			t.Fatal("pinned server CA was ignored — registration would fail x509")
		}
		if len(tr.TLSClientConfig.Certificates) != 0 {
			t.Error("presented a client certificate before registration issued one")
		}
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("verification disabled; the pin exists precisely so it stays on")
		}
	})

	// The registration client matters most: it makes the call that needs the pin.
	t.Run("SensorManagerClient", func(t *testing.T) {
		c := NewSensorManagerClient(cfg)
		tr, ok := c.httpClient.Transport.(*http.Transport)
		if !ok || tr.TLSClientConfig == nil {
			t.Fatalf("no TLS transport built from a server CA alone; got %T", c.httpClient.Transport)
		}
		if tr.TLSClientConfig.RootCAs == nil {
			t.Fatal("pinned server CA was ignored on the client that performs registration")
		}
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("verification disabled on the registration client")
		}
	})
}

// TestNoTrustMaterialLeavesDefaultTransport keeps the fix from over-reaching:
// with neither a CA nor a client cert the agent must fall through to the system
// trust store, which is correct for a platform holding a public certificate.
func TestNoTrustMaterialLeavesDefaultTransport(t *testing.T) {
	cfg := &config.Config{ControlPlaneURL: "https://cp.example.test"}
	if tr := NewOutboundClient(cfg).httpClient.Transport; tr != nil {
		t.Fatalf("custom transport installed with no trust material: %T", tr)
	}
	if tr := NewSensorManagerClient(cfg).httpClient.Transport; tr != nil {
		t.Fatalf("custom transport installed with no trust material: %T", tr)
	}
}
