package jwtkeys

import (
	"crypto/ecdsa"
	"fmt"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// KeySet is a concurrency-safe holder for the trusted public keys.
//
// It is a separate type because a process has ONE key set but several
// Verifiers: a service mounts the auth middleware at multiple route groups,
// and each mount may carry a different legacy HMAC secret. Sharing a KeySet
// means one JWKS poller updates them all; giving each Verifier its own copy of
// the map would mean a rotation reached some of them and not others.
type KeySet struct {
	mu   sync.RWMutex
	keys map[string]*ecdsa.PublicKey
}

// NewKeySet builds a key set over an initial list.
func NewKeySet(keys []PublicKey) *KeySet {
	ks := &KeySet{}
	ks.Set(keys)
	return ks
}

// Set replaces the trusted keys. Called by Client on every successful JWKS
// refresh.
//
// Replacement, not merge: a key removed from the issuer's JWKS must stop
// verifying, or revoking a compromised key would require a redeploy of all ~17
// services. The cost is that a JWKS briefly serving an incomplete document
// would reject good tokens — which is why Client refuses to install an empty or
// unparseable set and keeps the last good one instead.
func (ks *KeySet) Set(keys []PublicKey) {
	next := make(map[string]*ecdsa.PublicKey, len(keys))
	for _, k := range keys {
		next[k.KID] = k.Key
	}
	ks.mu.Lock()
	ks.keys = next
	ks.mu.Unlock()
}

func (ks *KeySet) lookup(kid string) (*ecdsa.PublicKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, ok := ks.keys[kid]
	return k, ok
}

// KIDs lists the trusted key ids, for logging and health output.
func (ks *KeySet) KIDs() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]string, 0, len(ks.keys))
	for k := range ks.keys {
		out = append(out, k)
	}
	return out
}

// Verifier resolves a token's signing key. It is what every non-issuing
// service holds: a shared set of PUBLIC keys, plus — during the migration
// window — its own copy of the legacy shared HMAC secret.
//
// Safe for concurrent use; the key set is swapped atomically by a JWKS refresh
// while requests are in flight.
type Verifier struct {
	keys *KeySet

	// legacyHMAC is the old shared JWT_SECRET. Non-empty means HS256 tokens are
	// still accepted, which is required until every session minted before the
	// cutover has expired. Passing "" is the switch that finally makes a leaked
	// JWT_SECRET worthless.
	//
	// Per-Verifier rather than per-KeySet: call sites legitimately differ here,
	// and an earlier version that shared one Verifier process-wide let the first
	// caller's secret win for everyone — which showed up as a 401 in an
	// unrelated test rather than as anything resembling a key-management bug.
	legacyHMAC []byte
}

// NewVerifier builds a verifier over its own private key set.
func NewVerifier(keys []PublicKey, legacyHMACSecret string) *Verifier {
	return NewVerifierWithKeySet(NewKeySet(keys), legacyHMACSecret)
}

// NewVerifierWithKeySet builds a verifier that shares an existing key set, so a
// single JWKS poller keeps every verifier in the process current.
func NewVerifierWithKeySet(ks *KeySet, legacyHMACSecret string) *Verifier {
	v := &Verifier{keys: ks}
	if legacyHMACSecret != "" {
		v.legacyHMAC = []byte(legacyHMACSecret)
	}
	return v
}

// SetKeys replaces the trusted public keys on this verifier's key set. When the
// set is shared, every verifier over it sees the change.
func (v *Verifier) SetKeys(keys []PublicKey) { v.keys.Set(keys) }

// KIDs lists the trusted key ids.
func (v *Verifier) KIDs() []string { return v.keys.KIDs() }

// AcceptsLegacyHMAC reports whether HS256 tokens still verify. Exposed so a
// service can log its posture at startup — "are we still accepting the shared
// secret" is the whole question this change exists to answer.
func (v *Verifier) AcceptsLegacyHMAC() bool {
	if v == nil {
		return false
	}
	return len(v.legacyHMAC) > 0
}

// Keyfunc returns a jwt.Keyfunc that selects the verification key by algorithm
// CLASS, not by the `alg` value the token asks for.
//
// This is the whole defence against algorithm confusion. A token is either:
//
//   - ECDSA-signed → look up its `kid` in the trusted PUBLIC key set. Missing
//     or unknown kid is a hard failure; there is no "try them all" fallback,
//     because trying every key turns an unknown-key error into a signature
//     oracle and defeats the point of rotation.
//   - HMAC-signed → the legacy shared secret, and only while one is configured.
//
// An attacker who takes the public key (it is public — that is the point) and
// re-signs a token as HS256 lands in the second branch, where the key is the
// legacy secret they do not have. The public key is never reachable as an HMAC
// key. verifier_test.go pins this with an actual forged token rather than by
// assertion.
func (v *Verifier) Keyfunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodECDSA:
			kid, _ := token.Header["kid"].(string)
			if kid == "" {
				return nil, ErrNoKID
			}
			key, ok := v.keys.lookup(kid)
			if !ok {
				return nil, fmt.Errorf("%w: %q", ErrUnknownKID, kid)
			}
			return key, nil

		case *jwt.SigningMethodHMAC:
			secret := v.legacyHMAC
			if len(secret) == 0 {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil

		default:
			// Covers alg:none (SigningMethodNone) and RSA, neither of which this
			// platform ever issues. Anything unrecognised is a forgery attempt.
			return nil, jwt.ErrSignatureInvalid
		}
	}
}

// ParserOptions returns the options every verification site should pass, so the
// accepted algorithm list is defined in one place rather than re-derived at
// each of the six call sites.
//
// jwt.WithValidMethods is belt-and-braces alongside Keyfunc: Keyfunc already
// refuses to hand back a key for anything else, but stating the allowlist means
// the parser rejects the token before it reaches the key lookup at all.
func (v *Verifier) ParserOptions() []jwt.ParserOption {
	methods := []string{Alg}
	if v.AcceptsLegacyHMAC() {
		methods = append(methods, "HS256")
	}
	return []jwt.ParserOption{jwt.WithValidMethods(methods)}
}

// KeySet returns the verifier's underlying key set, so a JWKS client can be
// pointed at it and so several verifiers can be built over the same keys.
func (v *Verifier) KeySet() *KeySet { return v.keys }
