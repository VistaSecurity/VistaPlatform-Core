package middleware

// Session-bound CSRF tokens.
//
// The double-submit check previously compared the X-CSRF-Token header to the
// csrf_token cookie for equality only — any value present in both passed, so it
// was not bound to the user's session. A controlled same-site subdomain could
// set a csrf cookie and pair it with a matching header.
//
// The original fix bound the CSRF token to the session as HMAC(jti), keyed by a
// value derived from the shared JWT secret. That worked, but it made every
// validator need the JWT secret — so moving token signing to asymmetric keys
// would have removed the shared secret from 15 services with one hand and
// kept it with the other, purely for this check.
//
// So the binding moved INTO the token. An issuer mints a random `csrf` claim,
// sets it as the csrf cookie, and validators compare the submitted header to the
// claim. The claim is inside the signed JWT, so forging it requires forging the
// token — a strictly stronger property than the HMAC form, and it needs no
// shared secret at all.
//
// The HMAC path below is retained for tokens issued BEFORE the cutover, which
// carry no `csrf` claim. It is dead once every pre-cutover session has expired;
// see the migration note in shared/security/jwtkeys.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/golang-jwt/jwt/v5"
)

// NewCSRFClaim generates the random per-session CSRF value an issuer embeds in
// the token's `csrf` claim and sets as the csrf cookie.
//
// 32 bytes from crypto/rand: this value is compared for equality, never
// derived, so its only requirement is that it cannot be guessed.
func NewCSRFClaim() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// csrfClaimOf reads the `csrf` claim from an access token WITHOUT verifying the
// signature.
//
// Safe for the same reason unverifiedJTI is: the surrounding JWT middleware
// validates the signature separately, and this function's only job is to answer
// "what does this token say its CSRF value is". An attacker who edits the claim
// invalidates the signature, and the request is rejected a few lines later.
//
// Returns "" for a pre-cutover token, which routes the caller to the legacy
// HMAC comparison.
func csrfClaimOf(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	var claims struct {
		CSRF string `json:"csrf"`
		jwt.RegisteredClaims
	}
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims); err != nil {
		return ""
	}
	return claims.CSRF
}

// csrfBindingLabel domain-separates the CSRF HMAC key from the JWT signing key,
// so deriving the CSRF key from the JWT secret doesn't reuse the signing key.
const csrfBindingLabel = "vistaplatform-csrf-binding-v1"

func csrfKey(jwtSecret string) []byte {
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(csrfBindingLabel))
	return mac.Sum(nil)
}

// CSRFToken returns the session-bound CSRF token for an access token's jti: the
// value the server sets as the csrf cookie and the client must echo in
// X-CSRF-Token. Returns "" for an empty jti (an unbindable token).
func CSRFToken(jwtSecret, jti string) string {
	if jti == "" {
		return ""
	}
	mac := hmac.New(sha256.New, csrfKey(jwtSecret))
	mac.Write([]byte(jti))
	return hex.EncodeToString(mac.Sum(nil))
}

// CSRFTokenForAccessToken returns the CSRF value to set as the cookie
// alongside a freshly issued access token.
//
// Prefers the token's own `csrf` claim; falls back to the legacy HMAC(jti)
// derivation for a token minted without one. Issuers that embed the claim can
// keep calling this unchanged.
func CSRFTokenForAccessToken(jwtSecret, accessToken string) string {
	if claim := csrfClaimOf(accessToken); claim != "" {
		return claim
	}
	return CSRFToken(jwtSecret, unverifiedJTI(accessToken))
}

// ValidCSRFToken reports whether submitted is the session-bound CSRF token for
// jti, using a constant-time compare. Empty jti or submitted is always invalid.
func ValidCSRFToken(jwtSecret, jti, submitted string) bool {
	if jti == "" || submitted == "" {
		return false
	}
	expected := CSRFToken(jwtSecret, jti)
	return expected != "" && hmac.Equal([]byte(expected), []byte(submitted))
}

// ValidCSRFForToken reports whether the submitted CSRF token is bound to the
// session of the given access token. Validators call this with the request's
// access-token cookie value.
//
// Two forms, checked in order:
//
// - The token carries a `csrf` claim (post-): compare the submitted value
//     to the claim. No secret needed — the claim is covered by the token's
//     signature, which the surrounding JWT middleware validates separately.
//   - No claim (a session minted before the cutover): fall back to the legacy
//     HMAC(jti) derivation, which needs jwtSecret.
//
// Once every pre-cutover session has expired, jwtSecret is unused here and can
// be removed from the verifying services entirely.
func ValidCSRFForToken(jwtSecret, accessToken, submitted string) bool {
	if submitted == "" {
		return false
	}
	if claim := csrfClaimOf(accessToken); claim != "" {
		return hmac.Equal([]byte(claim), []byte(submitted))
	}
	return ValidCSRFToken(jwtSecret, unverifiedJTI(accessToken), submitted)
}

// unverifiedJTI extracts the jti from an access token without signature
// verification.
func unverifiedJTI(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims); err != nil {
		return ""
	}
	return claims.ID
}
