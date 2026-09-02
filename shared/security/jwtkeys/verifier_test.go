package jwtkeys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustSigner(t *testing.T) *Signer {
	t.Helper()
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s, err := NewSigner([]KeyPair{*kp})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func claims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	s := mustSigner(t)
	v := NewVerifier(s.PublicKeys(), "")

	tok, err := s.Sign(claims())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parsed, err := jwt.Parse(tok, v.Keyfunc(), v.ParserOptions()...)
	if err != nil || !parsed.Valid {
		t.Fatalf("verify round-trip failed: %v", err)
	}
	if got := parsed.Header["kid"]; got != s.ActiveKID() {
		t.Errorf("kid header = %v, want %q", got, s.ActiveKID())
	}
	if parsed.Method.Alg() != Alg {
		t.Errorf("alg = %q, want %q", parsed.Method.Alg(), Alg)
	}
}

// THE test for this package. An attacker knows the public key — it is published
// at /.well-known/jwks.json, on purpose. The classic attack is to re-sign a
// token with HS256 using those public-key bytes as the HMAC secret, betting the
// verifier picks its key by reading the token's own `alg` header.
//
// If Keyfunc ever regresses to returning the public key BYTES regardless of
// method, this test fails and the platform is forgeable by anyone who can curl
// the JWKS endpoint. Mutation-verified: rewriting Keyfunc to hand back
// x509.MarshalPKIXPublicKey(key) for HMAC tokens makes this test fail with
// exactly that message.
//
// Worth knowing what this does NOT prove. golang-jwt's HMAC verifier requires a
// []byte key and its ECDSA verifier requires an *ecdsa.PublicKey, so a keyfunc
// that returns the *typed* public key for an HS256 token already fails inside
// the library. The exploitable shape is specifically a refactor that stores keys
// as PEM/DER bytes — which is a plausible one, since that is how keys arrive on
// disk. That is the case pinned here.
func TestKeyfunc_RejectsHS256ForgedWithThePublicKey(t *testing.T) {
	s := mustSigner(t)
	pub := s.PublicKeys()[0]
	v := NewVerifier([]PublicKey{pub}, "") // no legacy secret: HS256 must not verify at all

	// Build the forgery the way a real attacker would: take the published key,
	// use its encoded bytes as an HMAC secret, and claim to be an admin.
	pubDER, err := x509.MarshalPKIXPublicKey(pub.Key)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	forgedClaims := claims()
	forgedClaims["role"] = "super_admin"
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, forgedClaims)
	forged.Header["kid"] = pub.KID
	forgedTok, err := forged.SignedString(pubDER)
	if err != nil {
		t.Fatalf("sign forgery: %v", err)
	}

	if _, err := jwt.Parse(forgedTok, v.Keyfunc(), v.ParserOptions()...); err == nil {
		t.Fatal("HS256 token signed with the PUBLIC key verified — algorithm confusion is live")
	}

	// Same forgery, but against a verifier that still accepts the legacy shared
	// secret (the migration window). It must still fail: the HMAC branch hands
	// back the legacy secret, never the public key.
	vLegacy := NewVerifier([]PublicKey{pub}, "the-real-legacy-secret")
	if _, err := jwt.Parse(forgedTok, vLegacy.Keyfunc(), vLegacy.ParserOptions()...); err == nil {
		t.Fatal("forgery verified against a legacy-accepting verifier — the HMAC branch is reachable with the public key")
	}
}

func TestKeyfunc_RejectsAlgNone(t *testing.T) {
	s := mustSigner(t)
	v := NewVerifier(s.PublicKeys(), "legacy")

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims())
	tok.Header["kid"] = s.ActiveKID()
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign alg=none: %v", err)
	}
	if _, err := jwt.Parse(raw, v.Keyfunc(), v.ParserOptions()...); err == nil {
		t.Fatal("alg=none token verified")
	}
}

func TestKeyfunc_RejectsUnknownAndMissingKID(t *testing.T) {
	signer := mustSigner(t)
	other := mustSigner(t)

	// A verifier that trusts only `other` must reject tokens from `signer`,
	// even though both are valid ES256 tokens.
	v := NewVerifier(other.PublicKeys(), "")
	tok, err := signer.Sign(claims())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := jwt.Parse(tok, v.Keyfunc(), v.ParserOptions()...); err == nil {
		t.Fatal("token signed by an untrusted key verified")
	}

	// A kid-less ES256 token is rejected rather than falling back to trying
	// every key — "try them all" would defeat rotation and revocation.
	noKid := jwt.NewWithClaims(jwt.SigningMethodES256, claims())
	raw, err := noKid.SignedString(signer.active.Private)
	if err != nil {
		t.Fatalf("sign without kid: %v", err)
	}
	vSelf := NewVerifier(signer.PublicKeys(), "")
	if _, err := jwt.Parse(raw, vSelf.Keyfunc(), vSelf.ParserOptions()...); err == nil {
		t.Fatal("ES256 token with no kid verified")
	}
}

// The migration window: both token generations must verify while legacy is on,
// and turning legacy off must immediately stop the old ones.
func TestLegacyHMAC_AcceptedThenRejected(t *testing.T) {
	const legacy = "old-shared-jwt-secret"
	s := mustSigner(t)

	legacyTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims()).SignedString([]byte(legacy))
	if err != nil {
		t.Fatalf("sign legacy: %v", err)
	}
	newTok, err := s.Sign(claims())
	if err != nil {
		t.Fatalf("sign new: %v", err)
	}

	dual := NewVerifier(s.PublicKeys(), legacy)
	if !dual.AcceptsLegacyHMAC() {
		t.Fatal("AcceptsLegacyHMAC() = false with a secret configured")
	}
	for name, tok := range map[string]string{"legacy": legacyTok, "es256": newTok} {
		if _, err := jwt.Parse(tok, dual.Keyfunc(), dual.ParserOptions()...); err != nil {
			t.Errorf("dual-mode verifier rejected the %s token: %v", name, err)
		}
	}

	hardened := NewVerifier(s.PublicKeys(), "")
	if hardened.AcceptsLegacyHMAC() {
		t.Fatal("AcceptsLegacyHMAC() = true with no secret configured")
	}
	if _, err := jwt.Parse(legacyTok, hardened.Keyfunc(), hardened.ParserOptions()...); err == nil {
		t.Error("legacy HS256 token still verified after the legacy secret was removed")
	}
	if _, err := jwt.Parse(newTok, hardened.Keyfunc(), hardened.ParserOptions()...); err != nil {
		t.Errorf("ES256 token rejected by the hardened verifier: %v", err)
	}
}

// Rotation must not invalidate sessions minted moments earlier.
func TestRotate_OldTokensKeepVerifying(t *testing.T) {
	s := mustSigner(t)
	oldKID := s.ActiveKID()
	oldTok, err := s.Sign(claims())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	next, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s.Rotate(*next)

	if s.ActiveKID() == oldKID {
		t.Fatal("Rotate did not change the active key")
	}
	if len(s.PublicKeys()) != 2 {
		t.Fatalf("JWKS publishes %d keys after rotation, want 2", len(s.PublicKeys()))
	}

	v := NewVerifier(s.PublicKeys(), "")
	if _, err := jwt.Parse(oldTok, v.Keyfunc(), v.ParserOptions()...); err != nil {
		t.Errorf("token signed before rotation stopped verifying: %v", err)
	}
	newTok, err := s.Sign(claims())
	if err != nil {
		t.Fatalf("Sign after rotate: %v", err)
	}
	if _, err := jwt.Parse(newTok, v.Keyfunc(), v.ParserOptions()...); err != nil {
		t.Errorf("token signed after rotation did not verify: %v", err)
	}
}

// ─── JWKS document ─────────────────────────────────────────────────────────

func TestJWKS_RoundTripAndTampering(t *testing.T) {
	s := mustSigner(t)
	body, err := MarshalJWKS(s.PublicKeys())
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(keys) != 1 || keys[0].KID != s.ActiveKID() {
		t.Fatalf("round-trip lost the key: %+v", keys)
	}

	// A JWKS whose kid does not match its key material must be refused: the kid
	// is how a token names its key, so accepting an attacker-chosen name lets a
	// hostile document bind a key they control to a kid we already trust.
	var doc JWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc.Keys[0].Kid = "attacker-chosen"
	tampered, _ := json.Marshal(doc)
	if _, err := ParseJWKS(tampered); err == nil {
		t.Error("JWKS with a mismatched kid was accepted")
	}

	// A point that is not on P-256 must not reach the ECDSA verifier.
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc.Keys[0].X = base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 1))
	offCurve, _ := json.Marshal(doc)
	if _, err := ParseJWKS(offCurve); err == nil {
		t.Error("JWKS with an off-curve point was accepted")
	}
}

// Coordinates must be fixed-width. A key whose X starts with a zero byte would
// serialise short under a naive implementation and fail in strict parsers — a
// bug that shows up on roughly 1 key in 256 and is miserable to diagnose. So
// keep generating real keys until a leading zero turns up in each coordinate,
// and check both: a synthetic point cannot be used here because ToJWK now
// refuses anything that is not on the curve, and checking only one coordinate
// would not notice the other being trimmed.
func TestToJWK_PadsShortCoordinates(t *testing.T) {
	var foundX, foundY bool
	for i := 0; i < 50000 && (!foundX || !foundY); i++ {
		kp, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		pub := &kp.Private.PublicKey
		raw, err := pub.Bytes() // 0x04 || X || Y, both padded to 32 bytes
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		shortX, shortY := raw[1] == 0, raw[1+32] == 0
		if !shortX && !shortY {
			continue
		}
		foundX = foundX || shortX
		foundY = foundY || shortY

		j, err := ToJWK(PublicKey{KID: kp.KID, Key: pub})
		if err != nil {
			t.Fatalf("ToJWK: %v", err)
		}
		// 32 bytes → 43 base64url chars with no padding.
		if len(j.X) != 43 || len(j.Y) != 43 {
			t.Errorf("coordinate lengths = (%d, %d), want (43, 43) — not left-padded to the curve size (leading zero in x=%v, y=%v)", len(j.X), len(j.Y), shortX, shortY)
		}
		// It must still survive the round trip: a coordinate with a leading
		// zero has to reconstruct the same key on the way in.
		back, err := FromJWK(j)
		if err != nil {
			t.Fatalf("FromJWK: %v", err)
		}
		if !back.Key.Equal(pub) {
			t.Error("round trip through a leading-zero coordinate lost the key")
		}
	}
	if !foundX || !foundY {
		t.Fatalf("no key with a leading zero turned up (x=%v, y=%v) — the padding path was never exercised", foundX, foundY)
	}
}

// A JWKS must never publish a point that is not on the curve, so ToJWK refuses
// to encode one rather than serving it and leaving the check to consumers.
func TestToJWK_RejectsOffCurvePoint(t *testing.T) {
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1),
		Y:     big.NewInt(2),
	}
	if _, err := ToJWK(PublicKey{KID: "k", Key: pub}); err == nil {
		t.Error("ToJWK encoded a point that is not on P-256")
	}
	if _, err := MarshalJWKS([]PublicKey{{KID: "k", Key: pub}}); err == nil {
		t.Error("MarshalJWKS served a point that is not on P-256")
	}
}

func TestServeJWKS_ServesParseableDocument(t *testing.T) {
	s := mustSigner(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ServeJWKS(w, s)
	}))
	defer srv.Close()

	v := NewVerifier(nil, "")
	c := &Client{URL: srv.URL, Interval: time.Hour, HTTP: srv.Client(), Keys: v.KeySet()}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if kids := v.KIDs(); len(kids) != 1 || kids[0] != s.ActiveKID() {
		t.Fatalf("verifier keys after refresh = %v, want [%s]", kids, s.ActiveKID())
	}
	tok, _ := s.Sign(claims())
	if _, err := jwt.Parse(tok, v.Keyfunc(), v.ParserOptions()...); err != nil {
		t.Errorf("token did not verify against JWKS-fetched keys: %v", err)
	}
}

// A failed refresh must never blank the key set — that would turn a network
// blip into a platform-wide 401 storm.
func TestClient_FailedRefreshKeepsPreviousKeys(t *testing.T) {
	s := mustSigner(t)
	v := NewVerifier(s.PublicKeys(), "")

	for name, handler := range map[string]http.HandlerFunc{
		"500":       func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"garbage":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) },
		"empty set": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) },
	} {
		srv := httptest.NewServer(handler)
		c := &Client{URL: srv.URL, Interval: time.Hour, HTTP: srv.Client(), Keys: v.KeySet()}
		if err := c.Refresh(context.Background()); err == nil {
			t.Errorf("%s: Refresh returned no error", name)
		}
		if kids := v.KIDs(); len(kids) != 1 {
			t.Errorf("%s: key set was clobbered by a failed refresh (kids=%v)", name, kids)
		}
		srv.Close()
	}
}

// A key removed from the issuer's JWKS must stop verifying, or revoking a
// compromised key would need a redeploy of every service.
func TestClient_RefreshReplacesRatherThanMerges(t *testing.T) {
	compromised := mustSigner(t)
	replacement := mustSigner(t)
	v := NewVerifier(compromised.PublicKeys(), "")

	oldTok, _ := compromised.Sign(claims())
	if _, err := jwt.Parse(oldTok, v.Keyfunc(), v.ParserOptions()...); err != nil {
		t.Fatalf("precondition: token should verify before revocation: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ServeJWKS(w, replacement)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Interval: time.Hour, HTTP: srv.Client(), Keys: v.KeySet()}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if _, err := jwt.Parse(oldTok, v.Keyfunc(), v.ParserOptions()...); err == nil {
		t.Error("a token from a key dropped by the issuer still verifies — revocation via JWKS does not work")
	}
}

// ─── PEM ───────────────────────────────────────────────────────────────────

func TestParsePrivatePEM_MultipleKeysActiveFirst(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	aPEM, _ := EncodePrivatePEM(a.Private)
	bPEM, _ := EncodePrivatePEM(b.Private)

	keys, err := ParsePrivatePEM(append(aPEM, bPEM...))
	if err != nil {
		t.Fatalf("ParsePrivatePEM: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(keys))
	}
	if keys[0].KID != a.KID {
		t.Errorf("first key = %q, want %q — the first PEM block must be the active signer", keys[0].KID, a.KID)
	}

	s, err := NewSigner(keys)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s.ActiveKID() != a.KID {
		t.Errorf("ActiveKID = %q, want the first block %q", s.ActiveKID(), a.KID)
	}
}

func TestParsePrivatePEM_RejectsNonP256(t *testing.T) {
	if _, err := ParsePrivatePEM([]byte("not a pem")); err == nil {
		t.Error("garbage input parsed as a key")
	}
	// An RSA key in a PKCS#8 block must be refused rather than silently
	// producing a signer that emits tokens nothing can verify.
	rsaPEM := "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----\n"
	if _, err := ParsePrivatePEM([]byte(rsaPEM)); err == nil {
		t.Error("a non-ECDSA key was accepted as a signing key")
	}
}

func TestDeriveKID_StableAndKeyBound(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()

	again, err := DeriveKID(&a.Private.PublicKey)
	if err != nil {
		t.Fatalf("DeriveKID: %v", err)
	}
	if again != a.KID {
		t.Errorf("kid is not stable: %q then %q", a.KID, again)
	}
	if a.KID == b.KID {
		t.Error("two independently generated keys share a kid")
	}
	if strings.ContainsAny(a.KID, "+/=") {
		t.Errorf("kid %q is not base64url — it lands in a JSON header and a URL", a.KID)
	}
}

func TestSignerFromEnv_AbsentIsNotAnError(t *testing.T) {
	// The migration depends on this: no keys provisioned must mean "keep
	// signing HS256", not "fail to start".
	t.Setenv("TESTPREFIX_SIGNING_KEY", "")
	t.Setenv("TESTPREFIX_SIGNING_KEY_FILE", "")
	s, err := SignerFromEnv("TESTPREFIX")
	if err != nil {
		t.Fatalf("SignerFromEnv with nothing configured returned an error: %v", err)
	}
	if s != nil {
		t.Fatal("SignerFromEnv returned a signer with nothing configured")
	}
	if _, err := s.Sign(claims()); err != ErrNoSigningKey {
		t.Errorf("Sign on a nil signer = %v, want ErrNoSigningKey", err)
	}

	kp, _ := Generate()
	pemBytes, _ := EncodePrivatePEM(kp.Private)
	t.Setenv("TESTPREFIX_SIGNING_KEY", string(pemBytes))
	s, err = SignerFromEnv("TESTPREFIX")
	if err != nil {
		t.Fatalf("SignerFromEnv: %v", err)
	}
	if s == nil || s.ActiveKID() != kp.KID {
		t.Fatalf("inline PEM did not load the expected key")
	}
}

// A verifier that starts BEFORE its issuer must recover in seconds, not after a
// whole refresh interval.
//
// This is the bug the first Core v0.1.0 deploy exposed: every service raced
// auth-service's startup, logged "JWKS endpoint returned 404", and then had an
// empty key set until the 300s ticker fired. Platform-admin login was broken for
// exactly that long. It read as harmless only because legacy HS256 still covered
// pre-existing sessions; with that turned off it is a total auth outage on every
// restart.
//
// There is no bootstrap key set to fall back on — Helm cannot derive a public
// key from the private PEM it generates — so retrying fast is the whole fix.
func TestClient_RecoversQuicklyWhenTheIssuerStartsLate(t *testing.T) {
	s := mustSigner(t)

	var mu sync.Mutex
	up := false
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		ready := up
		mu.Unlock()
		if !ready {
			w.WriteHeader(http.StatusNotFound) // the issuer is still booting
			return
		}
		ServeJWKS(w, s)
	}))
	defer srv.Close()

	v := NewVerifier(nil, "")
	// A deliberately long steady interval: if recovery waited for the ticker,
	// this test would time out rather than pass slowly.
	c := &Client{URL: srv.URL, Interval: time.Hour, HTTP: srv.Client(), Keys: v.KeySet()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err == nil {
		t.Fatal("precondition: the first fetch was supposed to fail")
	}
	if len(v.KIDs()) != 0 {
		t.Fatal("precondition: the key set should be empty after a failed first fetch")
	}

	mu.Lock()
	up = true
	mu.Unlock()

	deadline := time.Now().Add(15 * time.Second)
	for len(v.KIDs()) == 0 {
		if time.Now().After(deadline) {
			mu.Lock()
			n := calls
			mu.Unlock()
			t.Fatalf("key set still empty 15s after the issuer came up (%d fetch attempts) — recovery is waiting for the steady interval", n)
		}
		time.Sleep(50 * time.Millisecond)
	}

	tok, err := s.Sign(claims())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := jwt.Parse(tok, v.Keyfunc(), v.ParserOptions()...); err != nil {
		t.Errorf("token did not verify after recovery: %v", err)
	}
}
