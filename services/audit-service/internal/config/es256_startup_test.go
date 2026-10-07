package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
)

// This is the production migration state documented by the chart: the legacy
// HMAC secret is absent and a verifier obtains ES256 public keys from JWKS.
// Config loading used to replace the absent secret with a public dev literal,
// after which the production-secret guard terminated the process before the
// service could fetch a key.
func TestProductionStartsWithoutLegacyHMACAndVerifiesJWKS(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("INTERNAL_AUTH_SECRET", "strong-internal-auth-secret-0123456789")
	t.Setenv("JWT_SECRET", "")
	if err := os.Unsetenv("JWT_SECRET"); err != nil {
		t.Fatal(err)
	}

	pair, err := jwtkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwtkeys.NewSigner([]jwtkeys.KeyPair{*pair})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwtkeys.ServeJWKS(w, signer)
	}))
	defer server.Close()

	// ES256 verification is configured the way the chart configures it; with an
	// absent JWT_SECRET that is what lets the production guard accept startup.
	t.Setenv("JWT_JWKS_URL", server.URL)

	cfg := Load()
	if cfg.JWT.Secret != "" {
		t.Fatalf("production JWT secret = %q, want disabled legacy HMAC", cfg.JWT.Secret)
	}

	keys := jwtkeys.NewKeySet(nil)
	client := &jwtkeys.Client{URL: server.URL, HTTP: server.Client(), Keys: keys}
	if err := client.Refresh(context.Background()); err != nil {
		t.Fatalf("fetch JWKS: %v", err)
	}
	verifier := jwtkeys.NewVerifierWithKeySet(keys, cfg.JWT.Secret)
	raw, err := signer.Sign(jwt.MapClaims{
		"sub": "migration-test",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse(raw, verifier.Keyfunc(), verifier.ParserOptions()...)
	if err != nil || !parsed.Valid {
		t.Fatalf("verify ES256 token after production startup: valid=%v err=%v", parsed != nil && parsed.Valid, err)
	}
}
