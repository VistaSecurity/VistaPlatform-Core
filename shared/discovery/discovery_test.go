package discovery

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
		0x0000:           "Unknown",
	}
	for in, want := range cases {
		if got := TLSVersionName(in); got != want {
			t.Errorf("TLSVersionName(0x%04x) = %q, want %q", in, got, want)
		}
	}
}

func TestCipherSuiteName(t *testing.T) {
	// Known IANA suite.
	if got := CipherSuiteName(tls.TLS_AES_128_GCM_SHA256); got != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("CipherSuiteName(TLS_AES_128_GCM_SHA256) = %q", got)
	}
	// The 0x003D case that the cluster-sensor copy was missing (drift the merge fixed).
	if got := CipherSuiteName(0x003D); got != "TLS_RSA_WITH_AES_256_CBC_SHA256" {
		t.Errorf("CipherSuiteName(0x003D) = %q, want TLS_RSA_WITH_AES_256_CBC_SHA256", got)
	}
	// Unknown suites preserve the raw id.
	if got := CipherSuiteName(0xABCD); got != "Unknown-0xABCD" {
		t.Errorf("CipherSuiteName(0xABCD) = %q, want Unknown-0xABCD", got)
	}
}

func TestClassifyValidationError(t *testing.T) {
	if status, _ := ClassifyValidationError(nil); status != "valid" {
		t.Errorf("nil error classified as %q, want valid", status)
	}
	// The incomplete_chain case the cluster-sensor copy was missing.
	if status, _ := ClassifyValidationError(errString("certificate chain is incomplete")); status != "incomplete_chain" {
		t.Errorf("incomplete chain classified as %q, want incomplete_chain", status)
	}
	if status, _ := ClassifyValidationError(errString("x509: certificate has expired or is not yet valid")); status != "expired" {
		t.Errorf("expired classified as %q, want expired", status)
	}
}

func TestIsSelfSignedNil(t *testing.T) {
	if IsSelfSigned(nil) {
		t.Error("IsSelfSigned(nil) = true, want false")
	}
}

// errString is a trivial error type for table-driven classification tests.
type errString string

func (e errString) Error() string { return string(e) }
