package auth_test

// End-to-end proof for: a token minted by auth-service's real JWTService
// is accepted by the real shared middleware that every OTHER service runs —
// using only the PUBLIC key, with no shared secret anywhere in the verifying
// half.
//
// The unit tests in shared/security/jwtkeys prove the primitives. This proves
// the wiring: the claim shape auth-service actually emits, parsed by the
// middleware that actually guards the other services, through the same
// jwt.ParseWithClaims call the request path uses. Those are the two halves that
// drifted apart in every "the code looks right" bug this repo has hit.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/auth"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
)

// guardedService stands in for any of the ~15 services that only VERIFY. It is
// wired exactly as they are: the shared middleware, a verifier over public keys
// and whatever legacy secret it was given.
func guardedService(v *jwtkeys.Verifier, legacySecret string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(sharedmw.RequireJWTAuth(sharedmw.AuthConfig{
		JWTSecret:       legacySecret,
		Verifier:        v,
		RequireIssuer:   "crypto-inventory-auth",
		RequireAudience: "crypto-inventory",
	}))
	r.GET("/protected", func(c *gin.Context) {
		tenant, _ := sharedmw.GetTenantIDFromContext(c)
		c.JSON(http.StatusOK, gin.H{"tenant": tenant.String()})
	})
	return r
}

func get(t *testing.T, r *gin.Engine, bearer string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestES256Token_VerifiesAcrossServicesWithNoSharedSecret(t *testing.T) {
	kp, err := jwtkeys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer, err := jwtkeys.NewSigner([]jwtkeys.KeyPair{*kp})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// auth-service: holds the PRIVATE key. Its legacy secret is set, because
	// mid-migration it still has one — this test is about the verifying side.
	issuer := auth.NewJWTServiceWithKeys("issuer-side-legacy-secret", signer, time.Hour, 24*time.Hour)

	tenantID := uuid.New()
	token, _, _, err := issuer.GenerateAccessTokenWithTTL(uuid.New(), tenantID, "u@example.test", "tenant_admin", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// The other service: PUBLIC key only, and — this is the assertion that
	// matters — an EMPTY legacy secret. If this passes, a leak of JWT_SECRET
	// from any of those 15 services forges nothing.
	guarded := guardedService(jwtkeys.NewVerifier(signer.PublicKeys(), ""), "")
	if code := get(t, guarded, token); code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an ES256 token did not verify against public keys alone", code)
	}
}

// The verifying service must not be able to MINT. Holding only the public key,
// the best it can do is an HS256 forgery — which must fail.
func TestVerifierCannotForge(t *testing.T) {
	kp, _ := jwtkeys.Generate()
	signer, _ := jwtkeys.NewSigner([]jwtkeys.KeyPair{*kp})

	// A "compromised" verifying service: it has the public key set and nothing
	// else. Sign an admin token with the only key material it holds.
	stolen := signer.PublicKeys()[0]
	forged := auth.NewJWTService("", time.Hour, time.Hour) // no signer → legacy HS256 path
	tok, _, _, err := forged.GenerateAccessTokenWithTTL(uuid.New(), uuid.New(), "attacker@example.test", "super_admin", time.Hour)
	if err != nil {
		t.Fatalf("mint forgery: %v", err)
	}

	guarded := guardedService(jwtkeys.NewVerifier([]jwtkeys.PublicKey{stolen}, ""), "")
	if code := get(t, guarded, tok); code == http.StatusOK {
		t.Fatal("a token minted without the private key was accepted")
	}
}

// The migration window has to work in BOTH directions, because services roll
// one at a time: an old HS256 session must keep working against an upgraded
// verifier, and a new ES256 token must work against a verifier that still has
// the legacy secret configured.
func TestMigrationWindow_BothTokenGenerationsVerify(t *testing.T) {
	const legacy = "the-shared-secret-being-retired"
	kp, _ := jwtkeys.Generate()
	signer, _ := jwtkeys.NewSigner([]jwtkeys.KeyPair{*kp})

	legacyIssuer := auth.NewJWTService(legacy, time.Hour, time.Hour)
	newIssuer := auth.NewJWTServiceWithKeys(legacy, signer, time.Hour, time.Hour)

	oldTok, _, _, err := legacyIssuer.GenerateAccessTokenWithTTL(uuid.New(), uuid.New(), "a@example.test", "viewer", time.Hour)
	if err != nil {
		t.Fatalf("mint legacy: %v", err)
	}
	newTok, _, _, err := newIssuer.GenerateAccessTokenWithTTL(uuid.New(), uuid.New(), "b@example.test", "viewer", time.Hour)
	if err != nil {
		t.Fatalf("mint new: %v", err)
	}

	dual := guardedService(jwtkeys.NewVerifier(signer.PublicKeys(), legacy), legacy)
	for name, tok := range map[string]string{"legacy HS256": oldTok, "new ES256": newTok} {
		if code := get(t, dual, tok); code != http.StatusOK {
			t.Errorf("dual-mode verifier rejected the %s token (status %d)", name, code)
		}
	}

	// Closing the window: drop the legacy secret. Old sessions stop, new ones
	// carry on. This is the state that makes JWT_SECRET worthless.
	hardened := guardedService(jwtkeys.NewVerifier(signer.PublicKeys(), ""), "")
	if code := get(t, hardened, oldTok); code == http.StatusOK {
		t.Error("a legacy HS256 token still verified after the migration window closed")
	}
	if code := get(t, hardened, newTok); code != http.StatusOK {
		t.Errorf("an ES256 token was rejected after the migration window closed (status %d)", code)
	}
}

// Access tokens must carry the `csrf` claim, because the double-submit check
// in every verifying service now reads it from the token instead of deriving it
// from the shared secret. If minting stops emitting it, CSRF silently falls
// back to the legacy HMAC path — which needs the very secret this change
// removes, so the regression would only surface much later as "CSRF broke when
// we deleted JWT_SECRET".
func TestAccessTokensCarryCSRFClaim_RefreshTokensDoNot(t *testing.T) {
	kp, _ := jwtkeys.Generate()
	signer, _ := jwtkeys.NewSigner([]jwtkeys.KeyPair{*kp})
	issuer := auth.NewJWTServiceWithKeys("legacy", signer, time.Hour, 24*time.Hour)

	access, refresh, err := issuer.GenerateTokens(uuid.New(), uuid.New(), "u@example.test", "viewer")
	if err != nil {
		t.Fatalf("GenerateTokens: %v", err)
	}

	// Validated with an EMPTY secret: passing proves the check used the claim,
	// not the HMAC derivation.
	csrf := sharedmw.CSRFTokenForAccessToken("", access)
	if csrf == "" {
		t.Fatal("no csrf value derived for the access token")
	}
	if !sharedmw.ValidCSRFForToken("", access, csrf) {
		t.Error("the token's own csrf claim did not validate without a shared secret")
	}
	if sharedmw.ValidCSRFForToken("", access, "not-the-right-value") {
		t.Error("a wrong csrf value validated")
	}

	// Refresh tokens are exchanged server-side and never presented from a form,
	// so they carry no csrf claim.
	//
	// Inspected directly rather than through CSRFTokenForAccessToken, which
	// falls back to the legacy HMAC(jti) derivation when there is no claim and
	// so returns a non-empty value either way. Asserting on the helper's output
	// would have passed whether or not the claim was actually absent — the test
	// would have been measuring the fallback, not the thing it names.
	if csrfClaimIn(t, refresh) != "" {
		t.Error("refresh token carries a csrf claim; it should not")
	}
	if csrfClaimIn(t, access) == "" {
		t.Error("access token carries no csrf claim")
	}

	// A scoped (PAT) token and an impersonation token are both access tokens
	// presented from a browser, so both need the claim.
	scoped, _, _, err := issuer.GenerateScopedAccessTokenWithTTL(uuid.New(), uuid.New(), "p@example.test", "viewer", []string{"assets.read"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateScopedAccessTokenWithTTL: %v", err)
	}
	if sharedmw.CSRFTokenForAccessToken("", scoped) == "" {
		t.Error("scoped PAT access token carries no csrf claim")
	}

	imp, _, _, err := issuer.GenerateImpersonationToken(
		uuid.New(), uuid.New(), "target@example.test", "viewer",
		"admin-id", "admin@example.test", "support", "10.0.0.1", "curl", time.Hour)
	if err != nil {
		t.Fatalf("GenerateImpersonationToken: %v", err)
	}
	if sharedmw.CSRFTokenForAccessToken("", imp) == "" {
		t.Error("impersonation token carries no csrf claim")
	}
}

// Two sessions must not share a CSRF value, or the binding introduced is
// gone.
func TestCSRFClaimIsPerSession(t *testing.T) {
	kp, _ := jwtkeys.Generate()
	signer, _ := jwtkeys.NewSigner([]jwtkeys.KeyPair{*kp})
	issuer := auth.NewJWTServiceWithKeys("legacy", signer, time.Hour, time.Hour)

	a, _, _, _ := issuer.GenerateAccessTokenWithTTL(uuid.New(), uuid.New(), "a@example.test", "viewer", time.Hour)
	b, _, _, _ := issuer.GenerateAccessTokenWithTTL(uuid.New(), uuid.New(), "b@example.test", "viewer", time.Hour)

	csrfA := sharedmw.CSRFTokenForAccessToken("", a)
	csrfB := sharedmw.CSRFTokenForAccessToken("", b)
	if csrfA == csrfB {
		t.Fatal("two sessions were issued the same csrf value")
	}
	if sharedmw.ValidCSRFForToken("", a, csrfB) {
		t.Error("session A accepted session B's csrf value")
	}
}

// csrfClaimIn reads the `csrf` claim straight out of a token, without the
// helper's legacy fallback, so a test can tell "the claim is absent" apart from
// "the helper derived something".
func csrfClaimIn(t *testing.T, token string) string {
	t.Helper()
	var c struct {
		CSRF string `json:"csrf"`
		jwt.RegisteredClaims
	}
	if _, _, err := jwt.NewParser().ParseUnverified(token, &c); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return c.CSRF
}
