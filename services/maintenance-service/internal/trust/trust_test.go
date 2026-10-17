package trust

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// privateCAServer is a TLS server whose certificate chains to a CA the
// system trust store has never heard of — what a mirror behind an internal
// CA looks like. Returns the server and the PEM of that CA.
func privateCAServer(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	cert := srv.Certificate()
	return srv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func writePEM(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_EmptyPathIsNoExtraCA(t *testing.T) {
	b, err := Load("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if b.Configured() || b.Transport() != nil || b.Env() != nil || b.TLSConfig() != nil {
		t.Fatalf("zero bundle must mean defaults, got %+v", b)
	}
	if _, err := LoadEnv(func(string) string { return "" }, t.TempDir()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("LoadEnv without the variable: %v", err)
	}
}

func TestLoad_RejectsMissingOrGarbage(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.crt"), t.TempDir()); err == nil {
		t.Fatal("a missing file must be an error, not a silent default")
	}
	if _, err := Load(writePEM(t, []byte("not a certificate")), t.TempDir()); err == nil || !strings.Contains(err.Error(), "no usable PEM") {
		t.Fatalf("garbage must be refused: %v", err)
	}
}

// The behaviour the package exists for: a client built from the bundle
// verifies a server signed by the extra CA, and a client without it does not.
func TestLoad_TrustsThePrivateCAAndOnlyWithIt(t *testing.T) {
	srv, caPEM := privateCAServer(t)
	b, err := Load(writePEM(t, caPEM), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !b.Configured() {
		t.Fatal("expected a configured bundle")
	}

	// Without the extra CA: the default client refuses the server.
	plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if _, err := plain.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "x509") {
		t.Fatalf("a client without the extra CA must fail with an x509 error, got %v", err)
	}

	// With it: the handshake succeeds.
	withCA := &http.Client{Transport: b.Transport()}
	resp, err := withCA.Get(srv.URL)
	if err != nil {
		t.Fatalf("client built from the bundle must verify the private CA: %v", err)
	}
	_ = resp.Body.Close()

	// The pool still carries the system roots (it is the system pool plus
	// one), so a public registry keeps verifying: the extra CA must not be
	// the only subject in it. Compare against a pool of the extra CA alone.
	only := x509.NewCertPool()
	only.AppendCertsFromPEM(caPEM)
	if b.Pool.Equal(only) {
		t.Fatal("the pool must be the system pool plus the extra CA, not the extra CA alone")
	}
}

// Subprocesses (cosign) get SSL_CERT_FILE pointing at a bundle that ends with
// the extra CA and starts with the system bundle when the image has one.
func TestLoad_EnvBundleFileHoldsTheExtraCA(t *testing.T) {
	_, caPEM := privateCAServer(t)
	dir := t.TempDir()
	b, err := Load(writePEM(t, caPEM), dir)
	if err != nil {
		t.Fatal(err)
	}
	env := b.Env()
	if len(env) != 1 || !strings.HasPrefix(env[0], "SSL_CERT_FILE="+dir+string(os.PathSeparator)) {
		t.Fatalf("Env must name a bundle under the temp dir, got %v", env)
	}
	raw, err := os.ReadFile(strings.TrimPrefix(env[0], "SSL_CERT_FILE="))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), string(caPEM)) {
		t.Fatal("the bundle file must end with the extra CA's PEM")
	}
	// Everything in the file parses as certificates (a corrupt join would
	// make SSL_CERT_FILE consumers trust nothing).
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		t.Fatal("the bundle file must parse as PEM certificates")
	}
	for _, p := range systemBundles {
		if sys, err := os.ReadFile(p); err == nil && len(sys) > 0 {
			if !strings.HasPrefix(string(raw), string(sys)) {
				t.Fatalf("the bundle must start with the system bundle %s", p)
			}
			break
		}
	}
}
