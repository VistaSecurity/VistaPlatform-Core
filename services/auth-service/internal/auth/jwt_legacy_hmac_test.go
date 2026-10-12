package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
)

const legacyHMACTestSecret = "legacy-hmac-test-secret-not-a-credential"

func hs256Token(t *testing.T, secret string, mutate func(*JWTClaims)) string {
	t.Helper()
	now := time.Now()
	claims := &JWTClaims{
		UserID:   uuid.New(),
		TenantID: uuid.Nil,
		Email:    "forged-admin@example.test",
		Role:     "platform_admin",
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "x",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			Issuer:    "crypto-inventory-auth",
			Audience:  jwt.ClaimStrings{"crypto-inventory"},
			ID:        uuid.NewString(),
		},
	}
	if mutate != nil {
		mutate(claims)
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newSigningService(t *testing.T) *JWTService {
	t.Helper()
	kp, err := jwtkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwtkeys.NewSigner([]jwtkeys.KeyPair{*kp})
	if err != nil {
		t.Fatal(err)
	}
	return NewJWTServiceWithKeys(legacyHMACTestSecret, signer, time.Hour, time.Hour)
}

// Anyone holding JWT_SECRET can mint an HS256 platform-admin token. With the
// switch off, auth-service must stop honouring it, as every other service does
// once the chart closes the migration window.
func TestJWTService_LegacyHMACSwitch(t *testing.T) {
	forged := hs256Token(t, legacyHMACTestSecret, nil)

	svc := newSigningService(t)
	if _, err := svc.ValidateToken(forged); err != nil {
		t.Fatalf("default (window open): HS256 token rejected: %v", err)
	}

	svc.SetAcceptLegacyHMAC(false)
	if _, err := svc.ValidateToken(forged); err == nil {
		t.Fatal("legacy HMAC off: a forged HS256 token was accepted")
	}

	svc.SetAcceptLegacyHMAC(true)
	if _, err := svc.ValidateToken(forged); err != nil {
		t.Fatalf("legacy HMAC back on: HS256 token rejected: %v", err)
	}
}

// With no signing key the service mints HS256 itself, so honouring "off" would
// make it reject every token it issues. The switch is ignored (and logged).
func TestJWTService_LegacyHMACSwitchIgnoredWithoutSigningKey(t *testing.T) {
	svc := NewJWTService(legacyHMACTestSecret, time.Hour, time.Hour)
	svc.SetAcceptLegacyHMAC(false)

	access, _, err := svc.GenerateTokens(uuid.New(), uuid.Nil, "a@example.test", "platform_admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateToken(access); err != nil {
		t.Fatalf("service rejected a token it just minted: %v", err)
	}
}

// Tokens are minted with nbf = iat = now; a verifier a few seconds behind the
// issuer must still take them.
func TestJWTService_ValidateTokenToleratesClockSkew(t *testing.T) {
	svc := NewJWTService(legacyHMACTestSecret, time.Hour, time.Hour)
	skewed := func(by time.Duration) string {
		return hs256Token(t, legacyHMACTestSecret, func(c *JWTClaims) {
			c.NotBefore = jwt.NewNumericDate(time.Now().Add(by))
			c.IssuedAt = jwt.NewNumericDate(time.Now().Add(by))
		})
	}
	if _, err := svc.ValidateToken(skewed(10 * time.Second)); err != nil {
		t.Errorf("token minted 10s ahead of this clock rejected: %v", err)
	}
	if _, err := svc.ValidateToken(skewed(5 * time.Minute)); err == nil {
		t.Error("token valid only 5 minutes from now was accepted: leeway is unbounded")
	}
}
