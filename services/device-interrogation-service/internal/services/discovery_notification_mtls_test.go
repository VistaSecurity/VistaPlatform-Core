package services

// The HTTP fallback to notification-service must speak mTLS when the process
// does. It runs exactly when NATS is down; under USE_MTLS the peer
// (https://notification-service:8443) demands a client certificate, and a bare
// http.Client fails the handshake — so on an mTLS deployment the notification
// was silently lost. These tests stand up a receiver that REQUIRES a client
// certificate and drive the real SendDiscoveryNotification against it.

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type testPKI struct {
	caPath, clientCertPath, clientKeyPath string
	caPool                                *x509.CertPool
	serverCert                            tls.Certificate
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Platform CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage) (der []byte, key *ecdsa.PrivateKey) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err = x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, k
	}
	serverDER, serverKey := issue(2, "notification-service", x509.ExtKeyUsageServerAuth)
	clientDER, clientKey := issue(3, "device-interrogation-service", x509.ExtKeyUsageClientAuth)

	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	p := testPKI{
		caPath:         filepath.Join(dir, "ca.pem"),
		clientCertPath: filepath.Join(dir, "client.pem"),
		clientKeyPath:  filepath.Join(dir, "client-key.pem"),
		caPool:         pool,
		serverCert:     tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey},
	}
	writePEM(t, p.caPath, "CERTIFICATE", caDER)
	writePEM(t, p.clientCertPath, "CERTIFICATE", clientDER)
	writePEM(t, p.clientKeyPath, "EC PRIVATE KEY", clientKeyDER)
	return p
}

// mtlsReceiver is a notification-service stand-in that refuses any caller
// without a client certificate signed by the platform CA.
func mtlsReceiver(t *testing.T, pki testPKI, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client certificate", http.StatusUnauthorized)
			return
		}
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func sendOneDiscoveryNotification(s *DiscoveryIntegrationService) {
	// No NATS client: SendDiscoveryNotification goes straight to the HTTP fallback.
	s.SendDiscoveryNotification(context.Background(), uuid.New(), "job_completed", "Cloud discovery completed", uuid.New(), nil)
}

func TestDiscoveryNotificationFallback_PresentsAClientCertificateUnderMTLS(t *testing.T) {
	pki := newTestPKI(t)
	var hits atomic.Int32
	srv := mtlsReceiver(t, pki, &hits)

	t.Setenv("USE_MTLS", "true")
	t.Setenv("NOTIFICATION_SERVICE_URL", srv.URL)
	t.Setenv("CLIENT_CERT_PATH", pki.clientCertPath)
	t.Setenv("CLIENT_KEY_PATH", pki.clientKeyPath)
	t.Setenv("PLATFORM_CA_CERT_PATH", pki.caPath)

	sendOneDiscoveryNotification(&DiscoveryIntegrationService{})

	if got := hits.Load(); got != 1 {
		t.Fatalf("the mTLS receiver accepted %d request(s), want 1: the fallback did not present a client certificate", got)
	}
}

// Without mTLS the same fallback stays a plain HTTP client (dev / compose).
func TestDiscoveryNotificationFallback_PlainHTTPWhenMTLSIsOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("USE_MTLS", "false")
	t.Setenv("NOTIFICATION_SERVICE_URL", srv.URL)

	sendOneDiscoveryNotification(&DiscoveryIntegrationService{})
	if got := hits.Load(); got != 1 {
		t.Fatalf("plain receiver saw %d request(s), want 1", got)
	}
}

// A missing certificate under mTLS is reported, not papered over with a client
// that can never complete the handshake.
func TestNotificationHTTPClient_MTLSWithoutCertsIsAnError(t *testing.T) {
	t.Setenv("USE_MTLS", "true")
	t.Setenv("CLIENT_CERT_PATH", filepath.Join(t.TempDir(), "missing.pem"))
	t.Setenv("CLIENT_KEY_PATH", filepath.Join(t.TempDir(), "missing-key.pem"))
	if _, err := (&DiscoveryIntegrationService{}).notificationHTTPClient(); err == nil {
		t.Fatal("expected an error building an mTLS client with no certificates")
	}
}
