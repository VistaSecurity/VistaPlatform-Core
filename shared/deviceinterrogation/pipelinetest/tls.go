package pipelinetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The fake appliances' TLS, pinned.
//
// The UniFi collector probes the controller's management plane with the real
// TLS prober, and what that probe records ends up in hop 1's golden: the
// negotiated version, suite and key-exchange group, the accepted version set,
// the classical and hybrid support flags, and the certificate. httptest's
// defaults decide every one of those if nothing pins them, and none of them is
// a property of this repository:
//
//   - the groups a Go server supports, and the order it prefers them in, are
//     crypto/tls defaults that have changed between releases (X25519MLKEM768
//     became a default in Go 1.24);
//   - the versions it accepts are a default too (TLS 1.0/1.1 were dropped
//     from the server's default range in Go 1.22);
//   - httptest's certificate is the standard library's internal test
//     certificate, which Go has regenerated before.
//
// So the server side is pinned here: exactly TLS 1.2 and 1.3, exactly the
// hybrid group X25519MLKEM768 and the classical X25519 (hybrid preferred), and
// a certificate derived from a fixed seed. What the probe can then learn has
// one right answer: a TLS 1.3 handshake on X25519MLKEM768, the versions
// {1.3, 1.2}, classical support true (the X25519-only offer succeeds) and
// hybrid support true (the main handshake proves it).
//
// Two inputs cannot be pinned from a test, because they are the CLIENT's, and
// the client is the product's prober: whether the process has disabled the
// hybrid group (GODEBUG=tlsmlkem=0), and which TLS 1.3 suite this CPU prefers
// (Go puts ChaCha20-Poly1305 first on hardware without AES-GCM acceleration).
// RequireDeterministicTLS checks both and fails with the reason, rather than
// letting them surface as a golden diff that looks like a flaky test.

// applianceCertSeed derives the appliance's Ed25519 key. It is a test fixture,
// exactly like the SSH fake's host_key_seed: public, and only ever used for a
// loopback listener inside a test.
const applianceCertSeed = "vendor-pipeline-appliance-tls-certificate"

// Ed25519 because it is the one key type whose certificate is deterministic
// end to end: the key comes from the seed, and the signature over a fixed
// template is itself deterministic. An RSA or ECDSA certificate would get a
// new fingerprint every run.
func applianceCertificate(t testing.TB) tls.Certificate {
	t.Helper()
	seed := sha256.Sum256([]byte(applianceCertSeed))
	key := ed25519.NewKeyFromSeed(seed[:])
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(20140002),
		Subject:               pkix.Name{CommonName: "appliance.example.test", Organization: []string{"Example Appliance Vendor"}},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// A CA, as appliance self-signed certificates (and httptest's, which
		// this replaces) are, so the prober classifies it self_signed.
		IsCA:        true,
		DNSNames:    []string{"appliance.example.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(nil, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("appliance certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ApplianceTLSConfig is the fake appliances' server configuration.
func ApplianceTLSConfig(t testing.TB) *tls.Config {
	t.Helper()
	return &tls.Config{
		Certificates:     []tls.Certificate{applianceCertificate(t)},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

// RequireDeterministicTLS fails the test when this process's TLS CLIENT would
// negotiate something other than what the goldens record against the pinned
// appliance: TLS 1.3, X25519MLKEM768, TLS_AES_128_GCM_SHA256. It handshakes the
// way the product's prober does (a default client configuration) against a
// throwaway server with ApplianceTLSConfig, so it measures the environment and
// nothing else.
func RequireDeterministicTLS(t testing.TB) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = ApplianceTLSConfig(t)
	srv.StartTLS()
	defer srv.Close()

	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the prober's own setting
	if err != nil {
		t.Fatalf("TLS environment check: handshake with the pinned appliance failed: %v", err)
	}
	state := conn.ConnectionState()
	_ = conn.Close()

	var problems []string
	if state.Version != tls.VersionTLS13 {
		problems = append(problems, "negotiated "+tls.VersionName(state.Version)+", not TLS 1.3")
	}
	if state.CurveID != tls.X25519MLKEM768 {
		problems = append(problems, "negotiated group "+state.CurveID.String()+", not X25519MLKEM768 — "+
			"is GODEBUG disabling the hybrid group (GODEBUG="+os.Getenv("GODEBUG")+")?")
	}
	if state.CipherSuite != tls.TLS_AES_128_GCM_SHA256 {
		problems = append(problems, "negotiated "+tls.CipherSuiteName(state.CipherSuite)+
			", not TLS_AES_128_GCM_SHA256 — Go prefers ChaCha20-Poly1305 on CPUs without AES-GCM acceleration")
	}
	if len(problems) > 0 {
		t.Fatalf("this environment's TLS client does not match the one the pipeline goldens were recorded with, "+
			"so the UniFi management-plane rows would differ for a reason that is not the pipeline:\n  %s",
			strings.Join(problems, "\n  "))
	}
}
