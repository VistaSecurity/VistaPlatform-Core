package services

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// buildElevationFinding must reshape an external_connections leaf-cert snapshot
// into exactly the RawData["certificates"] shape extractCertificatesFromFinding
// reads — otherwise an elevated vendor cert silently fails to materialize. This
// test pins that contract end-to-end through the real canonical extractor.
func TestBuildElevationFinding_RoundTripsThroughCanonicalExtractor(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	size := 2048
	conn := &models.ExternalConnection{
		DestHostname:           ptrString("www.yahoo.com"),
		DestIP:                 "68.180.135.251",
		DestPort:               443,
		Protocol:               "TLS",
		CertSubject:            ptrString("CN=www.yahoo.com"),
		CertIssuer:             ptrString("CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1"),
		CertFingerprintSHA256:  ptrString("abc123def456"),
		CertPEM:                ptrString("-----BEGIN CERTIFICATE-----\nMIIabc\n-----END CERTIFICATE-----"),
		CertPublicKeyAlgorithm: ptrString("RSA"),
		CertPublicKeySize:      &size,
		CertSignatureAlgorithm: ptrString("SHA256-RSA"),
		CertNotBefore:          &nb,
		CertNotAfter:           &na,
		CertSAN:                []string{"www.yahoo.com", "yahoo.com"},
	}

	f := buildElevationFinding(conn)

	if f.Hostname == nil || *f.Hostname != "www.yahoo.com" {
		t.Fatalf("hostname not carried: %+v", f.Hostname)
	}
	if f.IPAddress == nil || *f.IPAddress != "68.180.135.251" {
		t.Fatalf("ip not carried: %+v", f.IPAddress)
	}
	if f.Port == nil || *f.Port != 443 {
		t.Fatalf("port not carried: %+v", f.Port)
	}

	// The load-bearing assertion: the real extractor must read the snapshot back
	// into a CertificateData with all fields intact.
	certs := (&AssetService{}).extractCertificatesFromFinding(f)
	if len(certs) != 1 {
		t.Fatalf("expected exactly 1 certificate, got %d", len(certs))
	}
	c := certs[0]
	if c.SubjectDN != "CN=www.yahoo.com" {
		t.Errorf("subject_dn = %q", c.SubjectDN)
	}
	if c.IssuerDN != "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1" {
		t.Errorf("issuer_dn = %q", c.IssuerDN)
	}
	if c.FingerprintSHA256 != "abc123def456" {
		t.Errorf("fingerprint_sha256 = %q", c.FingerprintSHA256)
	}
	if c.PublicKeyAlgorithm != "RSA" {
		t.Errorf("public_key_algorithm = %q", c.PublicKeyAlgorithm)
	}
	if c.PublicKeySize != 2048 {
		t.Errorf("public_key_size = %d", c.PublicKeySize)
	}
	if c.SignatureAlgorithm != "SHA256-RSA" {
		t.Errorf("signature_algorithm = %q", c.SignatureAlgorithm)
	}
	if c.CertificatePEM == "" {
		t.Error("certificate_pem not carried")
	}
	if !c.NotBefore.Equal(nb) {
		t.Errorf("not_before = %v, want %v", c.NotBefore, nb)
	}
	if !c.NotAfter.Equal(na) {
		t.Errorf("not_after = %v, want %v", c.NotAfter, na)
	}
	if len(c.SubjectAlternativeNames) != 2 {
		t.Errorf("SANs = %v", c.SubjectAlternativeNames)
	}
}

// A connection with no captured certificate still yields a usable finding (the
// elevation path skips cert materialization but still creates the managed asset).
func TestBuildElevationFinding_NoCertProducesNoCertificates(t *testing.T) {
	conn := &models.ExternalConnection{
		DestHostname: ptrString("vendor.example.com"),
		DestIP:       "203.0.113.10",
		DestPort:     443,
		Protocol:     "TLS",
	}
	f := buildElevationFinding(conn)
	certs := (&AssetService{}).extractCertificatesFromFinding(f)
	if len(certs) != 0 {
		t.Fatalf("expected 0 certificates for a connection with no cert snapshot, got %d", len(certs))
	}
}
