package middleware

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCSRFTokenBinding(t *testing.T) {
	const secret = "csrf-test-secret"

	a := CSRFToken(secret, "session-a")
	b := CSRFToken(secret, "session-b")

	if a == "" || b == "" {
		t.Fatal("expected non-empty tokens for non-empty jtis")
	}
	if a == b {
		t.Fatal("tokens for different sessions must differ")
	}
	if CSRFToken(secret, "session-a") != a {
		t.Fatal("token must be deterministic for the same session")
	}
	if CSRFToken("other-secret", "session-a") == a {
		t.Fatal("a different server secret must produce a different token")
	}
	if CSRFToken(secret, "") != "" {
		t.Fatal("empty jti must yield an empty (unbindable) token")
	}

	// Validation: bound token accepted for its own session, rejected for another.
	if !ValidCSRFToken(secret, "session-a", a) {
		t.Fatal("token must validate against its own session")
	}
	if ValidCSRFToken(secret, "session-b", a) {
		t.Fatal("token must NOT validate against a different session")
	}
	if ValidCSRFToken(secret, "session-a", "") || ValidCSRFToken(secret, "", a) {
		t.Fatal("empty submitted/jti must be invalid")
	}
}

func TestValidCSRFForToken(t *testing.T) {
	const secret = "csrf-test-secret"
	sign := func(jti string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		})
		s, err := tok.SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	accessA := sign("jti-a")
	csrfA := CSRFToken(secret, "jti-a")

	if !ValidCSRFForToken(secret, accessA, csrfA) {
		t.Fatal("CSRF bound to the access token's jti must validate")
	}
	// A CSRF token for a different jti must not validate against accessA.
	if ValidCSRFForToken(secret, accessA, CSRFToken(secret, "jti-b")) {
		t.Fatal("CSRF for a different session must not validate")
	}
	// A token with no jti is unbindable.
	if ValidCSRFForToken(secret, sign(""), CSRFToken(secret, "")) {
		t.Fatal("a token without a jti must not produce a valid binding")
	}
}

// ─── Token-embedded CSRF binding ────────────────────────────────────
//
// The binding moved from HMAC(jti) keyed by the shared JWT secret into a `csrf`
// claim inside the token, so that verifying services no longer need the signing
// secret for anything. These pin both halves of the migration.

func mintWithCSRFClaim(t *testing.T, csrf string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"jti": "session-jti-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if csrf != "" {
		claims["csrf"] = csrf
	}
	// Signed with an arbitrary secret: the CSRF path reads the claim WITHOUT
	// verifying the signature (the surrounding JWT middleware does that), so
	// which key signed it is deliberately irrelevant here.
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("irrelevant"))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func TestCSRF_ClaimBinding_NoSecretRequired(t *testing.T) {
	csrf, err := NewCSRFClaim()
	if err != nil {
		t.Fatalf("NewCSRFClaim: %v", err)
	}
	token := mintWithCSRFClaim(t, csrf)

	// The whole point: validation succeeds with an EMPTY jwtSecret. If this ever
	// starts needing a secret again, the shared secret is back in every service.
	if !ValidCSRFForToken("", token, csrf) {
		t.Error("claim-bound CSRF token did not validate without a shared secret")
	}
	if ValidCSRFForToken("", token, "some-other-value") {
		t.Error("a mismatched CSRF value validated")
	}
	if ValidCSRFForToken("", token, "") {
		t.Error("an empty CSRF value validated")
	}

	// The cookie an issuer sets must be exactly the claim.
	if got := CSRFTokenForAccessToken("", token); got != csrf {
		t.Errorf("CSRFTokenForAccessToken = %q, want the claim %q", got, csrf)
	}
}

func TestCSRF_ClaimIsSessionBound(t *testing.T) {
	a, _ := NewCSRFClaim()
	b, _ := NewCSRFClaim()
	if a == b {
		t.Fatal("NewCSRFClaim returned the same value twice")
	}
	tokenA := mintWithCSRFClaim(t, a)

	// A CSRF value minted for another session must not validate here — this is
	// the property introduced and must not regress.
	if ValidCSRFForToken("", tokenA, b) {
		t.Error("a CSRF token from a different session validated")
	}
}

func TestCSRF_LegacyTokensStillValidateDuringMigration(t *testing.T) {
	const secret = "legacy-shared-jwt-secret"
	legacyToken := mintWithCSRFClaim(t, "") // no csrf claim — a pre-cutover session

	expected := CSRFTokenForAccessToken(secret, legacyToken)
	if expected == "" {
		t.Fatal("legacy derivation produced no CSRF token")
	}
	if !ValidCSRFForToken(secret, legacyToken, expected) {
		t.Error("legacy HMAC-bound CSRF token stopped validating")
	}
	// And it must still fail without the secret, i.e. the legacy path really is
	// the one being exercised rather than silently passing.
	if ValidCSRFForToken("", legacyToken, expected) {
		t.Error("legacy CSRF token validated with no secret — the legacy path is not actually keyed")
	}
}
