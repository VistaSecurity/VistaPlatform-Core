package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testDERCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "normalize-pem-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNormalizePEM(t *testing.T) {
	der := testDERCert(t)
	properPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b64 := base64.StdEncoding.EncodeToString(der)

	t.Run("proper PEM passes through", func(t *testing.T) {
		if got := NormalizePEM(properPEM); got != strings.TrimSpace(properPEM) {
			t.Errorf("PEM input was altered")
		}
	})

	t.Run("bare base64 DER becomes PEM", func(t *testing.T) {
		got := NormalizePEM(b64)
		if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE-----") {
			t.Fatalf("expected PEM output, got %q…", got[:40])
		}
		block, _ := pem.Decode([]byte(got))
		if block == nil {
			t.Fatal("output does not decode as PEM")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Fatalf("normalized cert does not parse: %v", err)
		}
	})

	t.Run("base64 with whitespace becomes PEM", func(t *testing.T) {
		// Inject newlines every 64 chars, the way device APIs often wrap.
		var wrapped strings.Builder
		for i := 0; i < len(b64); i += 64 {
			end := i + 64
			if end > len(b64) {
				end = len(b64)
			}
			wrapped.WriteString(b64[i:end] + "\n")
		}
		got := NormalizePEM(wrapped.String())
		if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE-----") {
			t.Fatalf("expected PEM output for wrapped base64")
		}
	})

	t.Run("unrecognized input returned unchanged", func(t *testing.T) {
		if got := NormalizePEM("not a certificate!"); got != "not a certificate!" {
			t.Errorf("garbage input was altered: %q", got)
		}
	})
}
