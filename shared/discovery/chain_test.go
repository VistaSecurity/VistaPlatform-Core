package discovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

// testChain builds a root → intermediate → leaf certificate chain. The root is
// self-signed and (obviously) not in the system trust store.
func testChain(t *testing.T, dnsNames []string, ipSANs []net.IP) (leaf, intermediate, root *x509.Certificate) {
	t.Helper()

	mkKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		return k
	}
	sign := func(tmpl, parent *x509.Certificate, pub interface{}, priv interface{}) *x509.Certificate {
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
		Subject:               pkix.Name{CommonName: "Discovery Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	root = sign(rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

	interKey := mkKey()
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Discovery Test Intermediate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	intermediate = sign(interTmpl, root, &interKey.PublicKey, rootKey)

	leafKey := mkKey()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.discovery.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipSANs,
	}
	leaf = sign(leafTmpl, intermediate, &leafKey.PublicKey, interKey)
	return leaf, intermediate, root
}

// TestValidateAndClassifyCertChainBuildsIntermediatesPool pins DISC-2(a): the
// validator must feed every non-leaf certificate the server presented into an
// Intermediates pool. Without it, chain building stops dead at the leaf and
// every endpoint serving leaf+intermediate — nearly all of them — is reported
// as untrusted_ca. With the pool, the search walks up to the self-signed root
// and the failure is correctly attributed there.
func TestValidateAndClassifyCertChainBuildsIntermediatesPool(t *testing.T) {
	leaf, intermediate, root := testChain(t, []string{"leaf.discovery.test"}, nil)

	withPool := ValidateAndClassifyCertChainPassive([]*x509.Certificate{leaf, intermediate, root}, "leaf.discovery.test")
	if withPool.ValidationStatus != "self_signed" {
		t.Errorf("full chain: status = %q, want %q (chain building must reach the self-signed root; %q means the intermediates pool was not built)",
			withPool.ValidationStatus, "self_signed", withPool.ValidationStatus)
	}

	// Leaf alone (no intermediates sent) is a genuinely incomplete chain and
	// must NOT be reported as self-signed.
	leafOnly := ValidateAndClassifyCertChainPassive([]*x509.Certificate{leaf}, "leaf.discovery.test")
	if leafOnly.ValidationStatus == "self_signed" {
		t.Errorf("leaf alone: status = %q, want a non-self_signed classification", leafOnly.ValidationStatus)
	}
	if flag, ok := leafOnly.QualityFlags["cert_incomplete_chain"].(bool); !ok || !flag {
		t.Errorf("leaf alone: cert_incomplete_chain = %v, want true", leafOnly.QualityFlags["cert_incomplete_chain"])
	}
}

// TestValidateAndClassifyCertChainHostname pins that a DNS-SAN-only cert is not
// reported as a hostname mismatch when verified against a name it does carry,
// and IS when verified against one it does not.
func TestValidateAndClassifyCertChainHostname(t *testing.T) {
	leaf, intermediate, root := testChain(t, []string{"leaf.discovery.test"}, nil)
	chain := []*x509.Certificate{leaf, intermediate, root}

	if got := ValidateAndClassifyCertChainPassive(chain, "leaf.discovery.test"); got.ValidationStatus == "hostname_mismatch" {
		t.Error("matching hostname classified as hostname_mismatch")
	}
	if got := ValidateAndClassifyCertChainPassive(chain, "other.discovery.test"); got.ValidationStatus != "hostname_mismatch" {
		t.Errorf("non-matching hostname: status = %q, want hostname_mismatch", got.ValidationStatus)
	}
}

// TestVerifyDNSName pins DISC-2(b): a raw IP dial target must not be handed to
// x509 as a DNSName unless the certificate actually carries that IP SAN.
func TestVerifyDNSName(t *testing.T) {
	dnsOnly, _, _ := testChain(t, []string{"*.wild.test", "leaf.discovery.test"}, nil)
	withIP, _, _ := testChain(t, []string{"leaf.discovery.test"}, []net.IP{net.ParseIP("192.0.2.10")})
	wildcardOnly, _, _ := testChain(t, []string{"*.wild.test"}, nil)
	bare, _, _ := testChain(t, nil, nil)

	tests := []struct {
		name string
		leaf *x509.Certificate
		host string
		want string
	}{
		{"ip target, cert has matching IP SAN", withIP, "192.0.2.10", "192.0.2.10"},
		{"ip target, DNS-SAN-only cert falls back to a concrete SAN", dnsOnly, "192.0.2.99", "leaf.discovery.test"},
		{"ip target, wildcard-only cert falls back to the wildcard", wildcardOnly, "192.0.2.99", "*.wild.test"},
		{"ip target, no SANs falls back to a dotted CN", bare, "192.0.2.99", "leaf.discovery.test"},
		{"nil leaf", nil, "192.0.2.99", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyDNSName(tt.leaf, tt.host); got != tt.want {
				t.Errorf("VerifyDNSName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestResolveVerifyHost pins that a real hostname is verified as-is (so the
// identity check stays genuine) while an IP literal falls back to the cert.
func TestResolveVerifyHost(t *testing.T) {
	leaf, _, _ := testChain(t, []string{"leaf.discovery.test"}, nil)
	chain := []*x509.Certificate{leaf}

	if got := ResolveVerifyHost("some.other.host", chain); got != "some.other.host" {
		t.Errorf("hostname identity = %q, want it passed through unchanged", got)
	}
	if got := ResolveVerifyHost("192.0.2.99", chain); got != "leaf.discovery.test" {
		t.Errorf("IP identity = %q, want the cert's SAN", got)
	}
	if got := ResolveVerifyHost("192.0.2.99", nil); got != "" {
		t.Errorf("IP identity with no certs = %q, want empty", got)
	}
}

// TestEVPolicyOIDs pins DISC-9.
func TestEVPolicyOIDs(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{"CA/Browser Forum umbrella EV OID", asn1.ObjectIdentifier{2, 23, 140, 1, 1}, true},
		{"DigiCert EV", asn1.ObjectIdentifier{2, 16, 840, 1, 114412, 2, 1}, true},
		// 2.16.840.1.101.2.1 is the US DoD infosec arc, not an EV policy —
		// it was mislabelled "GlobalSign" and flagged DoD PKI certs as EV.
		{"US DoD arc is not EV", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 2, 1}, false},
		{"CA/B domain-validated is not EV", asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEVPolicyOID(tt.oid); got != tt.want {
				t.Errorf("isEVPolicyOID(%s) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}
