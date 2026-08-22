package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// DISC-2 regression tests for the in-cluster Platform Sensor's TLS probe.
//
// The bespoke prober this replaced had three defects, all exercised here
// against a real local TLS listener:
//
//	(a) it verified the chain with no Intermediates pool, so any server
//	    presenting leaf+intermediate classified as untrusted_ca;
//	(b) it passed the raw dial target (usually an IP) as x509 DNSName, so
//	    DNS-SAN certificates classified as hostname_mismatch;
//	(c) it emitted a private metadata dialect (tls_version, quality flags
//	    nested under cert_quality_flags, subject/issuer/public_key_algorithm)
//	    that no downstream consumer reads.

// startTestTLSServer serves a leaf+intermediate+root chain on 127.0.0.1 with a
// DNS-SAN-only leaf, and returns its port.
func startTestTLSServer(t *testing.T) int {
	t.Helper()

	mkKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		return k
	}
	sign := func(tmpl, parent *x509.Certificate, pub, priv interface{}) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
		if err != nil {
			t.Fatalf("create certificate: %v", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		return c
	}

	now := time.Now()
	rootKey := mkKey()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Cluster Probe Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	root := sign(rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

	interKey := mkKey()
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Cluster Probe Test Intermediate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	intermediate := sign(interTmpl, root, &interKey.PublicKey, rootKey)

	leafKey := mkKey()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "probe.cluster.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// DNS SANs only — deliberately NO IP SAN, which is what made the old
		// prober report hostname_mismatch when dialing by address.
		DNSNames: []string{"probe.cluster.test"},
	}
	leaf := sign(leafTmpl, intermediate, &leafKey.PublicKey, interKey)

	serverCert := tls.Certificate{
		Certificate: [][]byte{leaf.Raw, intermediate.Raw, root.Raw},
		PrivateKey:  leafKey,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
				_ = c.Close()
			}(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

func TestProbeTLSEmitsCanonicalMetadata(t *testing.T) {
	port := startTestTLSServer(t)

	// Dial by IP — the common case for scan job targets.
	data, err := NewTLSProber(5*time.Second).ProbeTLS("127.0.0.1", port, true)
	if err != nil {
		t.Fatalf("ProbeTLS: %v", err)
	}

	// (b) A DNS-SAN-only certificate probed by IP must not be reported as a
	// hostname mismatch.
	status, _ := data["cert_validation_status"].(string)
	if status == "hostname_mismatch" {
		t.Errorf("cert_validation_status = hostname_mismatch: the dial IP was passed straight through as x509 DNSName")
	}
	// (a) With the intermediates pool built, chain building reaches the
	// self-signed test root. untrusted_ca means it stopped at the leaf.
	if status != "self_signed" {
		t.Errorf("cert_validation_status = %q, want %q (chain must be walked to the self-signed root via the intermediates pool)", status, "self_signed")
	}

	// (c) Canonical top-level keys.
	if got, _ := data["version"].(string); got != "TLS 1.3" && got != "TLS 1.2" {
		t.Errorf("version = %v, want a canonical TLS version string under the key %q", data["version"], "version")
	}
	if got, _ := data["cipher_suite"].(string); got == "" {
		t.Errorf("cipher_suite = %v, want a cipher-suite name string", data["cipher_suite"])
	}
	if _, nested := data["cert_quality_flags"]; nested {
		t.Error("quality flags must be top-level, not nested under cert_quality_flags")
	}
	if _, ok := data["cert_has_sct"]; !ok {
		t.Error("cert_has_sct missing: quality flags were not merged at the top level")
	}

	// Canonical certificate array.
	certs, ok := data["certificates"].([]map[string]interface{})
	if !ok || len(certs) == 0 {
		t.Fatalf("certificates = %T (%v), want a non-empty []map", data["certificates"], data["certificates"])
	}
	leaf := certs[0]
	for _, key := range []string{"subject_dn", "issuer_dn", "key_algorithm", "signature_alg", "fingerprint_sha256", "certificate_pem", "not_before", "not_after", "chain_order"} {
		if v, ok := leaf[key]; !ok || v == "" {
			t.Errorf("leaf certificate missing canonical field %q", key)
		}
	}
	for _, key := range []string{"subject", "issuer", "public_key_algorithm", "signature_algorithm"} {
		if _, present := leaf[key]; present {
			t.Errorf("leaf certificate still carries non-canonical field %q", key)
		}
	}
	if got := leaf["subject_dn"]; got != "CN=probe.cluster.test" {
		t.Errorf("subject_dn = %v, want CN=probe.cluster.test", got)
	}
	// The server presented leaf + intermediate + root.
	if len(certs) != 3 {
		t.Errorf("certificate count = %d, want 3 (full presented chain)", len(certs))
	}
	if data["certificate_count"] != 3 {
		t.Errorf("certificate_count = %v, want 3", data["certificate_count"])
	}
}

func TestProbeTLSUnreachable(t *testing.T) {
	// Port 1 on loopback: nothing listens there.
	if _, err := NewTLSProber(2*time.Second).ProbeTLS("127.0.0.1", 1, true); err == nil {
		t.Error("expected an error probing a closed port")
	}
}
