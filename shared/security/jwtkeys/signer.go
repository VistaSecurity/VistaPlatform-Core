package jwtkeys

import (
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Signer mints ES256 tokens with a `kid` header. Only the two token issuers
// (auth-service, admin-service) construct one; every other service gets a
// Verifier and nothing else.
//
// The zero value is not usable — build one with NewSigner or SignerFromEnv.
type Signer struct {
	mu     sync.RWMutex
	active KeyPair
	// all holds every key the signer knows about, active first. Published as
	// the JWKS so tokens signed by a key that has since been rotated out still
	// verify for the remainder of their TTL.
	all []KeyPair
}

// NewSigner builds a signer over an ordered key list. The first key signs;
// the rest are published for verification only.
func NewSigner(keys []KeyPair) (*Signer, error) {
	if len(keys) == 0 {
		return nil, ErrNoSigningKey
	}
	return &Signer{active: keys[0], all: append([]KeyPair(nil), keys...)}, nil
}

// SignerFromEnv builds a signer from a PEM file path or inline PEM.
//
//	<prefix>_SIGNING_KEY_FILE  path to a PKCS#8 PEM (the chart mounts a Secret here)
//	<prefix>_SIGNING_KEY       inline PEM, for docker-compose and tests
//
// Returns (nil, nil) when NEITHER is set. That is deliberate and is what makes
// this change safe to roll out: a deployment with no keys provisioned keeps
// signing HS256 with the legacy shared secret, and only starts issuing ES256
// once an operator provisions keys. The alternative — failing to start — would
// turn a chart upgrade into an outage for anyone who missed the new value.
func SignerFromEnv(prefix string) (*Signer, error) {
	if path := os.Getenv(prefix + "_SIGNING_KEY_FILE"); path != "" {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		keys, err := ParsePrivatePEM(pemBytes)
		if err != nil {
			return nil, err
		}
		return NewSigner(keys)
	}
	if inline := os.Getenv(prefix + "_SIGNING_KEY"); inline != "" {
		keys, err := ParsePrivatePEM([]byte(inline))
		if err != nil {
			return nil, err
		}
		return NewSigner(keys)
	}
	return nil, nil
}

// Sign produces a signed ES256 token for the given claims, with the active
// key's id in the `kid` header.
func (s *Signer) Sign(claims jwt.Claims) (string, error) {
	if s == nil {
		return "", ErrNoSigningKey
	}
	s.mu.RLock()
	active := s.active
	s.mu.RUnlock()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = active.KID
	return tok.SignedString(active.Private)
}

// ActiveKID reports which key is currently signing. Surfaced so a service can
// log it at startup — "which key is this pod signing with" is the first
// question during a rotation and should not require exec'ing into the pod.
func (s *Signer) ActiveKID() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active.KID
}

// PublicKeys returns every key this signer publishes, for the JWKS endpoint.
func (s *Signer) PublicKeys() []PublicKey {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PublicKey, 0, len(s.all))
	for _, k := range s.all {
		out = append(out, k.Public())
	}
	return out
}

// Rotate promotes a new key to active, keeping the previous keys published for
// verification. Existing sessions keep working until their tokens expire.
//
// Callers must publish the new JWKS (i.e. let verifiers refresh) BEFORE the
// first token signed with the new key reaches them; the refresh interval in
// Client is the window that has to be respected. Rotating faster than that
// window produces tokens with an unknown kid, which verifiers correctly reject.
func (s *Signer) Rotate(next KeyPair) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.all
	s.active = next
	s.all = append([]KeyPair{next}, prev...)
}

// RetireBefore drops keys that have not signed anything since t, so a
// compromised or simply old key stops being published. Never drops the active
// key: a signer with no key cannot mint tokens, and silently becoming unable to
// issue tokens is a worse failure than publishing one key too long.
func (s *Signer) RetireBefore(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]KeyPair, 0, len(s.all))
	for _, k := range s.all {
		if k.KID == s.active.KID || k.NotAfter.IsZero() || k.NotAfter.After(cutoff) {
			kept = append(kept, k)
		}
	}
	s.all = kept
}
