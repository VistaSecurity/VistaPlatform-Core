package discovery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// makeSCTTestCert builds a minimal self-signed RSA-2048 certificate. When
// withEmbeddedSCT is true, an (empty-payload) SCT list extension is attached
// at the RFC 6962 embedded-SCT OID — the classifier only checks for the
// extension's presence, not its contents, so a dummy value is sufficient.
func makeSCTTestCert(t *testing.T, commonName string, withEmbeddedSCT bool) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if withEmbeddedSCT {
		tmpl.ExtraExtensions = []pkix.Extension{
			{Id: sctOID, Critical: false, Value: []byte{0x04, 0x02, 0x00, 0x00}},
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// makeSCTOCSPResponse builds a DER-encoded OCSP response, self-signed by a
// freshly generated issuer, carrying an SCT extension at the RFC 6962
// OCSP-delivery OID when withSCT is true. Returns the response bytes and the
// issuer certificate (needed to parse the response back).
func makeSCTOCSPResponse(t *testing.T, withSCT bool) (respDER []byte, issuer *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-ocsp-issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate (issuer): %v", err)
	}
	issuerCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate (issuer): %v", err)
	}

	respTemplate := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: big.NewInt(3),
		ThisUpdate:   time.Now().Add(-time.Minute),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	if withSCT {
		respTemplate.ExtraExtensions = []pkix.Extension{
			{Id: ocspSCTOID, Critical: false, Value: []byte{0x04, 0x02, 0x00, 0x00}},
		}
	}
	respDER, err = ocsp.CreateResponse(issuerCert, issuerCert, respTemplate, key)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	return respDER, issuerCert
}

func TestHasEmbeddedSCT(t *testing.T) {
	t.Parallel()

	withSCT := makeSCTTestCert(t, "with-sct.example.com", true)
	if !hasEmbeddedSCT(withSCT) {
		t.Error("expected hasEmbeddedSCT to find the embedded SCT extension")
	}

	withoutSCT := makeSCTTestCert(t, "without-sct.example.com", false)
	if hasEmbeddedSCT(withoutSCT) {
		t.Error("expected hasEmbeddedSCT to be false when no SCT extension is present")
	}
}

// TestClassifyCertificateFlags_SCT_Embedded confirms ClassifyCertificateFlags
// sets both cert_has_sct=true and cert_sct_source="embedded" when the leaf
// carries an embedded SCT.
func TestClassifyCertificateFlags_SCT_Embedded(t *testing.T) {
	t.Parallel()
	leaf := makeSCTTestCert(t, "embedded.example.com", true)
	flags := ClassifyCertificateFlags(leaf, []*x509.Certificate{leaf})

	if got, _ := flags["cert_has_sct"].(bool); !got {
		t.Errorf("cert_has_sct = %#v, want true", flags["cert_has_sct"])
	}
	if got, _ := flags["cert_sct_source"].(string); got != SCTSourceEmbedded {
		t.Errorf("cert_sct_source = %#v, want %q", flags["cert_sct_source"], SCTSourceEmbedded)
	}
}

// TestClassifyCertificateFlags_SCT_AbsentLeavesSourceUnset is the crux of the
// "nil/absent, never a false" rule: ClassifyCertificateFlags only has
// visibility into the embedded route (it's handed certificate bytes, not a
// live handshake), so when no embedded SCT is found it must record
// cert_has_sct=false (a real "we looked, found nothing" measurement) but
// leave cert_sct_source ABSENT — not "none", which would assert the TLS
// extension and OCSP routes were also checked when they were not.
func TestClassifyCertificateFlags_SCT_AbsentLeavesSourceUnset(t *testing.T) {
	t.Parallel()
	leaf := makeSCTTestCert(t, "no-sct.example.com", false)
	flags := ClassifyCertificateFlags(leaf, []*x509.Certificate{leaf})

	got, ok := flags["cert_has_sct"].(bool)
	if !ok || got {
		t.Errorf("cert_has_sct = %#v, want explicit false", flags["cert_has_sct"])
	}
	if v, present := flags["cert_sct_source"]; present {
		t.Errorf("cert_sct_source should be absent (route not observable), got %#v", v)
	}
}

// TestRefineSCTFlags_TLSExtension covers the second RFC 6962 delivery route:
// a live handshake that saw no embedded SCT but did receive the TLS
// "signed_certificate_timestamp" extension.
func TestRefineSCTFlags_TLSExtension(t *testing.T) {
	t.Parallel()
	flags := map[string]interface{}{"cert_has_sct": false}
	RefineSCTFlags(flags, [][]byte{{0x01, 0x02, 0x03}}, nil, nil)

	if got, _ := flags["cert_has_sct"].(bool); !got {
		t.Errorf("cert_has_sct = %#v, want true", flags["cert_has_sct"])
	}
	if got, _ := flags["cert_sct_source"].(string); got != SCTSourceTLSExtension {
		t.Errorf("cert_sct_source = %#v, want %q", flags["cert_sct_source"], SCTSourceTLSExtension)
	}
}

// TestRefineSCTFlags_OCSP covers the third RFC 6962 delivery route: no
// embedded SCT, no TLS-extension SCT, but the OCSP response carries the SCT
// extension.
func TestRefineSCTFlags_OCSP(t *testing.T) {
	t.Parallel()
	respDER, issuer := makeSCTOCSPResponse(t, true)

	flags := map[string]interface{}{"cert_has_sct": false}
	RefineSCTFlags(flags, nil, respDER, issuer)

	if got, _ := flags["cert_has_sct"].(bool); !got {
		t.Errorf("cert_has_sct = %#v, want true", flags["cert_has_sct"])
	}
	if got, _ := flags["cert_sct_source"].(string); got != SCTSourceOCSP {
		t.Errorf("cert_sct_source = %#v, want %q", flags["cert_sct_source"], SCTSourceOCSP)
	}
}

// TestRefineSCTFlags_NoneWhenAllRoutesChecked is the only case where a
// definite "none" is correct: a live handshake observed no embedded SCT, no
// TLS-extension SCT, and either no OCSP staple or a staple without the SCT
// extension.
func TestRefineSCTFlags_NoneWhenAllRoutesChecked(t *testing.T) {
	t.Parallel()

	t.Run("no OCSP staple at all", func(t *testing.T) {
		t.Parallel()
		flags := map[string]interface{}{"cert_has_sct": false}
		RefineSCTFlags(flags, nil, nil, nil)

		if got, _ := flags["cert_has_sct"].(bool); got {
			t.Errorf("cert_has_sct = %#v, want false", flags["cert_has_sct"])
		}
		if got, _ := flags["cert_sct_source"].(string); got != SCTSourceNone {
			t.Errorf("cert_sct_source = %#v, want %q", flags["cert_sct_source"], SCTSourceNone)
		}
	})

	t.Run("OCSP staple present but carries no SCT extension", func(t *testing.T) {
		t.Parallel()
		respDER, issuer := makeSCTOCSPResponse(t, false)
		flags := map[string]interface{}{"cert_has_sct": false}
		RefineSCTFlags(flags, nil, respDER, issuer)

		if got, _ := flags["cert_has_sct"].(bool); got {
			t.Errorf("cert_has_sct = %#v, want false", flags["cert_has_sct"])
		}
		if got, _ := flags["cert_sct_source"].(string); got != SCTSourceNone {
			t.Errorf("cert_sct_source = %#v, want %q", flags["cert_sct_source"], SCTSourceNone)
		}
	})
}

// TestRefineSCTFlags_EmbeddedAlreadyFoundIsUnchanged asserts RefineSCTFlags
// is purely additive: it must never downgrade an embedded-route "true" even
// if (implausibly) called with conflicting TLS-extension/OCSP data.
func TestRefineSCTFlags_EmbeddedAlreadyFoundIsUnchanged(t *testing.T) {
	t.Parallel()
	flags := map[string]interface{}{"cert_has_sct": true, "cert_sct_source": SCTSourceEmbedded}
	RefineSCTFlags(flags, [][]byte{{0x01}}, nil, nil)

	if got, _ := flags["cert_has_sct"].(bool); !got {
		t.Errorf("cert_has_sct = %#v, want true (unchanged)", flags["cert_has_sct"])
	}
	if got, _ := flags["cert_sct_source"].(string); got != SCTSourceEmbedded {
		t.Errorf("cert_sct_source = %#v, want %q (unchanged)", flags["cert_sct_source"], SCTSourceEmbedded)
	}
}

// TestRefineSCTFlags_NilFlagsMapNoop guards against a nil QualityFlags map
// (e.g. the "no certificates presented" branch of validateAndClassifyCertChain)
// reaching RefineSCTFlags and panicking on assignment to a nil map.
func TestRefineSCTFlags_NilFlagsMapNoop(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RefineSCTFlags panicked on a nil flags map: %v", r)
		}
	}()
	RefineSCTFlags(nil, [][]byte{{0x01}}, nil, nil)
}

// asn1Length is a tiny sanity check that ocspSCTOID/sctOID are distinct OIDs —
// a copy-paste that reused one for the other would make RefineSCTFlags and
// ClassifyCertificateFlags indistinguishable in their source attribution.
func TestSCTOIDsAreDistinct(t *testing.T) {
	t.Parallel()
	if sctOID.Equal(ocspSCTOID) {
		t.Fatalf("sctOID and ocspSCTOID must differ: got %v == %v", sctOID, ocspSCTOID)
	}
	var _ = asn1.ObjectIdentifier{} // keep encoding/asn1 import meaningful if OIDs above are ever inlined
}
