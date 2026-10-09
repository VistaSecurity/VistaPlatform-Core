package processor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/config"
)

// The result callback goes to https://sensor-manager:8443 under the service
// mesh, which presents a Platform-CA certificate and demands a client
// certificate. A plain http.Client failed it on every job ("certificate signed
// by unknown authority") and only the direct-DB fallback hid that.

type testPKI struct {
	caPool                     *x509.CertPool
	serverCert                 tls.Certificate
	caPath, clientCert, client string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Platform CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("issue %s: %v", cn, err)
		}
		return der, key
	}

	writePEM := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	keyDER := func(k *ecdsa.PrivateKey) []byte {
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		return b
	}

	srvDER, srvKey := issue(2, "sensor-manager", x509.ExtKeyUsageServerAuth)
	cliDER, cliKey := issue(3, "pcap-processor", x509.ExtKeyUsageClientAuth)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return testPKI{
		caPool:     pool,
		serverCert: tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey},
		caPath:     writePEM("ca.pem", "CERTIFICATE", caDER),
		clientCert: writePEM("client.pem", "CERTIFICATE", cliDER),
		client:     writePEM("client-key.pem", "EC PRIVATE KEY", keyDER(cliKey)),
	}
}

// meshServer stands in for sensor-manager's mTLS listener and records the
// callback body it receives.
func meshServer(t *testing.T, pki testPKI, got *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(got)
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

func TestSubmitResultsUsesTheMeshClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	var body map[string]any
	srv := meshServer(t, pki, &body)

	p := New(nil, &config.Config{
		MaxConcurrentJobs:  1,
		SensorManagerURL:   srv.URL,
		UseMTLS:            true,
		ClientCertPath:     pki.clientCert,
		ClientKeyPath:      pki.client,
		PlatformCACertPath: pki.caPath,
	}, nil, nil)

	result := &PcapResult{
		Discoveries:      []CryptoDiscovery{{Protocol: "QUIC"}, {Protocol: "QUIC"}, {Protocol: "HOST"}},
		DiscoveryCount:   3,
		PacketsProcessed: 22572,
		TruncatedPackets: 17972,
		SnapshotLength:   128,
	}
	if err := p.submitResults(context.Background(), uuid.New(), uuid.New(), result); err != nil {
		t.Fatalf("submitResults over mTLS: %v", err)
	}

	if body["truncated_packet_count"] != float64(17972) || body["snapshot_length"] != float64(128) {
		t.Errorf("truncation not reported: truncated_packet_count=%v snapshot_length=%v",
			body["truncated_packet_count"], body["snapshot_length"])
	}
	protocols, _ := body["protocols_found"].(map[string]any)
	if protocols["QUIC"] != float64(2) || protocols["HOST"] != float64(1) {
		t.Errorf("protocols_found = %v, want discoveries per protocol (QUIC:2 HOST:1)", protocols)
	}
}

// TestSubmitResultsWithoutMeshClientIsRefused proves the server above really
// demands the client certificate, so the test before it is not passing on a
// listener that would have accepted the old plain client too.
func TestSubmitResultsWithoutMeshClientIsRefused(t *testing.T) {
	pki := newTestPKI(t)
	var body map[string]any
	srv := meshServer(t, pki, &body)

	p := New(nil, &config.Config{MaxConcurrentJobs: 1, SensorManagerURL: srv.URL}, nil, nil)
	if err := p.submitResults(context.Background(), uuid.New(), uuid.New(), &PcapResult{}); err == nil {
		t.Fatal("a client without the mesh certificate reached the mTLS listener")
	}
}
