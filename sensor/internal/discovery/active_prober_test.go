package discovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

func TestEnumerateTLSVersionsUsesFirstTLSFindingPerPort(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	ip, portStr, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatalf("failed to parse host/port: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port: %v", err)
	}

	prober := NewActiveProber(2 * time.Second)
	findings := []models.DiscoveryFinding{
		{Protocol: "TLS", Port: port},
		{Protocol: "TLS", Port: port},
	}

	got := prober.enumerateTLSVersions("localhost", []string{ip, "203.0.113.10"}, []int{port}, findings)

	if len(got[0].TLSVersions) == 0 {
		t.Fatalf("expected first finding to receive TLS version data, got none")
	}

	wantFirst := []string{"TLS 1.2"}
	if !reflect.DeepEqual(got[0].TLSVersions, wantFirst) {
		t.Fatalf("expected first finding TLS versions %v, got %v", wantFirst, got[0].TLSVersions)
	}

	if len(got[1].TLSVersions) != 0 {
		t.Fatalf("expected second finding to remain unchanged, got %v", got[1].TLSVersions)
	}
}

func TestClassifyCertValidationError(t *testing.T) {
	t.Parallel()

	selfSignedCert := mustCreateSelfSignedCertificate(t)
	caSignedLeaf := mustCreateCASignedLeafCertificate(t)

	tests := []struct {
		name       string
		err        error
		wantStatus string
	}{
		{
			name:       "nil error is valid",
			err:        nil,
			wantStatus: "valid",
		},
		{
			name:       "expired certificate",
			err:        errors.New("x509: certificate has expired or is not yet valid"),
			wantStatus: "expired",
		},
		{
			name:       "hostname mismatch",
			err:        errors.New("x509: certificate is valid for app.internal, not api.internal"),
			wantStatus: "hostname_mismatch",
		},
		{
			name:       "self-signed certificate reported as unknown authority",
			err:        x509.UnknownAuthorityError{Cert: selfSignedCert},
			wantStatus: "self_signed",
		},
		{
			name:       "self-signed fallback message",
			err:        errors.New("x509: certificate is self-signed"),
			wantStatus: "self_signed",
		},
		{
			name:       "non self-signed unknown authority",
			err:        x509.UnknownAuthorityError{Cert: caSignedLeaf},
			wantStatus: "untrusted_ca",
		},
		{
			name:       "incomplete chain",
			err:        errors.New("x509: certificate chain is incomplete"),
			wantStatus: "incomplete_chain",
		},
		{
			name:       "unknown authority mentioning authority key identifier is untrusted_ca",
			err:        errors.New("x509: certificate signed by unknown authority; authority key identifier mismatch"),
			wantStatus: "untrusted_ca",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotStatus, gotDetail := ClassifyCertValidationError(tt.err)
			if gotStatus != tt.wantStatus {
				t.Fatalf("ClassifyCertValidationError() status = %q, want %q", gotStatus, tt.wantStatus)
			}

			if tt.err == nil {
				if gotDetail != "" {
					t.Fatalf("ClassifyCertValidationError() detail = %q, want empty detail for nil error", gotDetail)
				}
				return
			}

			if gotDetail == "" {
				t.Fatalf("ClassifyCertValidationError() detail is empty for non-nil error")
			}
		})
	}
}

func mustCreateSelfSignedCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "self-signed.local"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"self-signed.local"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("create self-signed certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse self-signed certificate: %v", err)
	}

	return cert
}

func mustCreateCASignedLeafCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2001),
		Subject:               pkix.Name{CommonName: "test-root-ca.local"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("create root certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}

	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2002),
		Subject:               pkix.Name{CommonName: "leaf.local"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.local"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafPub, caPriv)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	return leafCert
}
