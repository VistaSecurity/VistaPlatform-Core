package handlers

// Regression for the merge gap: admin-service minted ES256 refresh
// tokens (via platformSigner) but RefreshToken still verified with an
// HMAC-only keyfunc, so every platform session failed on the first refresh.
//
// These tests pin the mint↔verify lockstep without standing up the full
// handler (DB + family rotation). Mutation-verified: restoring the HMAC-only
// Parse makes TestParsePlatformRefreshToken_AcceptsES256WhenSigning fail.

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
)

const refreshES256Secret = "admin-refresh-es256-test-secret"

func mustPlatformSigner(t *testing.T) *jwtkeys.Signer {
	t.Helper()
	kp, err := jwtkeys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s, err := jwtkeys.NewSigner([]jwtkeys.KeyPair{*kp})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestParsePlatformRefreshToken_AcceptsES256WhenSigning(t *testing.T) {
	prev := platformSigner
	t.Cleanup(func() { platformSigner = prev })

	InitTokenSigning(mustPlatformSigner(t))

	_, refresh, err := generateTokens("11111111-1111-1111-1111-111111111111", "admin@example.com", "super_admin", refreshES256Secret, false)
	if err != nil {
		t.Fatalf("generateTokens: %v", err)
	}

	// Sanity: the minted refresh token really is ES256 — otherwise this test
	// would pass against the broken HMAC-only verifier and prove nothing.
	unverified, _, err := jwt.NewParser().ParseUnverified(refresh, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if _, ok := unverified.Method.(*jwt.SigningMethodECDSA); !ok {
		t.Fatalf("minted refresh alg = %T (%s), want ECDSA — test premise broken", unverified.Method, unverified.Method.Alg())
	}

	claims, err := parsePlatformRefreshToken(refresh, refreshES256Secret)
	if err != nil {
		t.Fatalf("parsePlatformRefreshToken rejected an ES256 refresh this service just minted: %v", err)
	}
	if claims["type"] != "refresh" {
		t.Fatalf("type = %v, want refresh", claims["type"])
	}
	if claims["user_id"] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("user_id = %v", claims["user_id"])
	}
}

func TestParsePlatformRefreshToken_StillAcceptsLegacyHS256(t *testing.T) {
	prev := platformSigner
	t.Cleanup(func() { platformSigner = prev })
	platformSigner = nil // force the HS256 mint path

	_, refresh, err := generateTokens("11111111-1111-1111-1111-111111111111", "admin@example.com", "super_admin", refreshES256Secret, false)
	if err != nil {
		t.Fatalf("generateTokens: %v", err)
	}

	claims, err := parsePlatformRefreshToken(refresh, refreshES256Secret)
	if err != nil {
		t.Fatalf("legacy HS256 refresh rejected during the migration window: %v", err)
	}
	if claims["type"] != "refresh" {
		t.Fatalf("type = %v, want refresh", claims["type"])
	}
}

func TestParsePlatformRefreshToken_RejectsForgedHS256WithPublicKey(t *testing.T) {
	prev := platformSigner
	t.Cleanup(func() { platformSigner = prev })

	s := mustPlatformSigner(t)
	InitTokenSigning(s)

	pub := s.PublicKeys()[0]
	pubDER, err := x509.MarshalPKIXPublicKey(pub.Key)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "11111111-1111-1111-1111-111111111111",
		"type":    "refresh",
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	forged.Header["kid"] = pub.KID
	tok, err := forged.SignedString(pubDER)
	if err != nil {
		t.Fatalf("sign forgery: %v", err)
	}
	if _, err := parsePlatformRefreshToken(tok, refreshES256Secret); err == nil {
		t.Fatal("HS256 forgery signed with the PUBLIC key verified")
	}
}
