package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

func signSensorCSR(t *testing.T, csrPEM string) (certPEM, caPEM string) {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("registration request did not include a PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sensor-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

func TestSensorManagerRegisterSwitchesAdvertisedURLAndEnablesMTLS(t *testing.T) {
	var sawRegistration bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sensor-manager/sensors/register" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		sawRegistration = true

		var req models.SensorRegistration
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode registration request: %v", err)
		}
		certPEM, caPEM := signSensorCSR(t, req.CSR)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"sensor_id":         req.SensorID,
			"client_cert":       certPEM,
			"server_ca_cert":    caPEM,
			"control_plane_url": "https://sensors.example.test:8444",
			"config":            map[string]any{},
		}); err != nil {
			t.Fatalf("encode registration response: %v", err)
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		ControlPlaneURL:   server.URL,
		RegistrationKey:   "registration-key",
		Name:              "test-sensor",
		ReportingInterval: time.Minute,
	}
	client := NewSensorManagerClient(cfg)

	if _, err := client.Register(); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !sawRegistration {
		t.Fatal("registration endpoint was not called")
	}
	if cfg.ControlPlaneURL != "https://sensors.example.test:8444" {
		t.Fatalf("ControlPlaneURL = %q, want advertised passthrough URL", cfg.ControlPlaneURL)
	}
	if client.baseURL != "https://sensors.example.test:8444" {
		t.Fatalf("client baseURL = %q, want advertised passthrough URL", client.baseURL)
	}
	if !cfg.Security.UseTLS {
		t.Fatal("Register() did not enable TLS after receiving cert material")
	}
	tr, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("Register() did not install TLS transport; got %T", client.httpClient.Transport)
	}
	if len(tr.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("TLS transport has %d client certs, want 1", len(tr.TLSClientConfig.Certificates))
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("TLS transport did not trust the returned server CA")
	}
}
