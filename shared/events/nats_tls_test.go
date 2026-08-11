package events

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSTLSOptionsFromEnv_DisabledWhenUnset(t *testing.T) {
	clearNATSTLSEnv(t)

	if opts := natsTLSOptionsFromEnv(); opts != nil {
		t.Fatalf("expected no TLS options when NATS_TLS_* env vars are unset, got %d", len(opts))
	}
}

func TestNATSTLSOptionsFromEnv_DisabledForPartialConfig(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "cert only",
			env: map[string]string{
				"NATS_TLS_CERT_PATH": "/tmp/client.crt",
			},
			want: "NATS_TLS_CERT_PATH:set NATS_TLS_KEY_PATH:unset NATS_TLS_CA_PATH:unset",
		},
		{
			name: "cert and key without ca",
			env: map[string]string{
				"NATS_TLS_CERT_PATH": "/tmp/client.crt",
				"NATS_TLS_KEY_PATH":  "/tmp/client.key",
			},
			want: "NATS_TLS_CERT_PATH:set NATS_TLS_KEY_PATH:set NATS_TLS_CA_PATH:unset",
		},
		{
			name: "ca only",
			env: map[string]string{
				"NATS_TLS_CA_PATH": "/tmp/ca.crt",
			},
			want: "NATS_TLS_CERT_PATH:unset NATS_TLS_KEY_PATH:unset NATS_TLS_CA_PATH:set",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearNATSTLSEnv(t)
			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			var logs bytes.Buffer
			originalOutput := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(originalOutput) })

			if opts := natsTLSOptionsFromEnv(); opts != nil {
				t.Fatalf("expected partial NATS_TLS_* config to disable TLS options, got %d", len(opts))
			}
			if got := logs.String(); !strings.Contains(got, tc.want) {
				t.Fatalf("expected warning to include %q, got %q", tc.want, got)
			}
		})
	}
}

func TestNATSTLSOptionsFromEnv_CompleteConfigEnablesClientCertAndRootCA(t *testing.T) {
	clearNATSTLSEnv(t)

	certPath, keyPath, caPath := writeNATSTLSTestMaterial(t)
	t.Setenv("NATS_TLS_CERT_PATH", certPath)
	t.Setenv("NATS_TLS_KEY_PATH", keyPath)
	t.Setenv("NATS_TLS_CA_PATH", caPath)

	opts := natsTLSOptionsFromEnv()
	if len(opts) != 2 {
		t.Fatalf("expected client-cert and root-CA options, got %d", len(opts))
	}

	natsOpts := nats.GetDefaultOptions()
	for _, opt := range opts {
		if err := opt(&natsOpts); err != nil {
			t.Fatalf("applying TLS option failed: %v", err)
		}
	}

	if !natsOpts.Secure {
		t.Fatal("expected NATS options to enable secure TLS mode")
	}
	if natsOpts.TLSCertCB == nil {
		t.Fatal("expected client certificate callback to be configured")
	}
	if natsOpts.RootCAsCB == nil {
		t.Fatal("expected root CA callback to be configured")
	}
	if _, err := natsOpts.TLSCertCB(); err != nil {
		t.Fatalf("client certificate callback failed: %v", err)
	}
	rootCAs, err := natsOpts.RootCAsCB()
	if err != nil {
		t.Fatalf("root CA callback failed: %v", err)
	}
	expectedRoots := x509.NewCertPool()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA PEM: %v", err)
	}
	if !expectedRoots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse expected CA PEM")
	}
	if !rootCAs.Equal(expectedRoots) {
		t.Fatal("expected root CA pool to contain exactly the configured CA")
	}
}

func clearNATSTLSEnv(t *testing.T) {
	t.Helper()

	t.Setenv("NATS_TLS_CERT_PATH", "")
	t.Setenv("NATS_TLS_KEY_PATH", "")
	t.Setenv("NATS_TLS_CA_PATH", "")
}

func writeNATSTLSTestMaterial(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()

	dir := t.TempDir()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-nats-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-nats-client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	caPath = filepath.Join(dir, "ca.crt")

	writePEMFile(t, certPath, "CERTIFICATE", clientDER)
	writePEMFile(t, caPath, "CERTIFICATE", caDER)
	writePEMFile(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	return certPath, keyPath, caPath
}

func writePEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = f.Close()
		t.Fatalf("write %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}
