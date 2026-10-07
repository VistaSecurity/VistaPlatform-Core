// Package ssostate holds one SSO sign-in attempt between the authorize redirect
// and the identity provider's callback, for every OAuth 2.0 / OIDC client flow
// the platform runs (tenant SSO and social sign-up in auth-service, staff SSO in
// admin-service).
//
// It binds three things to the attempt:
//
//   - The browser. Begin returns a random binding value for an HttpOnly,
//     SameSite=Lax cookie scoped to the callback path; only its SHA-256 is kept
//     server-side. Finish refuses a callback whose browser does not present it.
//     Without this, an attacker completes the IdP flow with their OWN account
//     and feeds the victim the callback URL: the victim's browser is signed in
//     as the attacker (login CSRF). The state alone cannot stop that, because
//     the attacker started the attempt and knows its state.
//   - The authorization code (PKCE, RFC 7636, S256). Begin generates a
//     code_verifier, kept server-side; the authorize request carries only its
//     challenge. A code stolen on its way back (logs, referrers, a hostile
//     redirect) cannot be redeemed without the verifier, and a code minted for
//     one attempt cannot be replayed into another.
//   - Single use. Finish consumes the record atomically, so a callback URL
//     replays at most once.
//
// Lax, not Strict: the IdP's redirect back is a cross-site top-level GET, and a
// Strict cookie is not sent on it.
package ssostate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// TTL bounds how long a sign-in attempt may sit at the IdP. The binding cookie
// expires with it.
const TTL = 10 * time.Minute

// CodeChallengeMethod is the only PKCE method the platform sends.
const CodeChallengeMethod = "S256"

var (
	// ErrNoBinding: the callback arrived without the binding cookie — it was
	// not started in this browser (or the cookie expired).
	ErrNoBinding = errors.New("ssostate: no browser binding presented")
	// ErrUnknownState: no attempt is recorded for the state — never issued,
	// expired, or already used.
	ErrUnknownState = errors.New("ssostate: unknown, expired or already-used state")
	// ErrBindingMismatch: the browser presented a binding that is not this
	// attempt's.
	ErrBindingMismatch = errors.New("ssostate: browser binding does not match the state")
)

// Record is the server-side half of an attempt.
type Record struct {
	// BindingHash is hex(SHA-256(binding cookie value)). Begin sets it.
	BindingHash string `json:"binding_hash"`
	// CodeVerifier is the PKCE verifier sent at token exchange. Begin sets it.
	CodeVerifier string `json:"code_verifier"`
	// Nonce is the OIDC nonce, for flows that verify an id_token.
	Nonce string `json:"nonce,omitempty"`
	// Data carries the flow's own context (tenant, provider, invitation...).
	Data      map[string]string `json:"data,omitempty"`
	CreatedAt int64             `json:"created_at"`
}

// Attempt is what the authorize handler needs to build the redirect and the
// cookie. Binding goes ONLY into the cookie.
type Attempt struct {
	State         string
	Binding       string
	CodeChallenge string
}

// Store keeps records until their callback. Take must be atomic get-and-delete.
type Store interface {
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Take returns the value and deletes it; ErrUnknownState when absent.
	Take(ctx context.Context, key string) ([]byte, error)
}

// Begin records a new attempt under keyPrefix+state. rec's BindingHash,
// CodeVerifier and CreatedAt are filled in here; the caller supplies Nonce and
// Data.
func Begin(ctx context.Context, store Store, keyPrefix string, rec Record) (Attempt, error) {
	if store == nil {
		return Attempt{}, errors.New("ssostate: no store")
	}
	state, err := randomToken()
	if err != nil {
		return Attempt{}, err
	}
	binding, err := randomToken()
	if err != nil {
		return Attempt{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return Attempt{}, err
	}
	rec.BindingHash = hashBinding(binding)
	rec.CodeVerifier = verifier
	rec.CreatedAt = time.Now().Unix()
	raw, err := json.Marshal(rec)
	if err != nil {
		return Attempt{}, err
	}
	if err := store.Put(ctx, keyPrefix+state, raw, TTL); err != nil {
		return Attempt{}, fmt.Errorf("ssostate: persist attempt: %w", err)
	}
	return Attempt{State: state, Binding: binding, CodeChallenge: S256Challenge(verifier)}, nil
}

// Finish validates a callback: the browser must present a binding (checked
// before the store is touched), the state must name a live attempt (consumed
// here, whatever the outcome), and the binding must be that attempt's. Only
// then is the record returned. A store error other than "absent" is returned
// as-is so the caller can fail closed with a 5xx.
func Finish(ctx context.Context, store Store, keyPrefix, state, binding string) (Record, error) {
	if binding == "" {
		return Record{}, ErrNoBinding
	}
	if state == "" || store == nil {
		return Record{}, ErrUnknownState
	}
	raw, err := store.Take(ctx, keyPrefix+state)
	if err != nil {
		return Record{}, err
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		// A record written before this package (no binding) parses here too and
		// fails the comparison below; only garbage lands in this branch.
		return Record{}, ErrUnknownState
	}
	if !BindingMatches(binding, rec.BindingHash) {
		return Record{}, ErrBindingMismatch
	}
	return rec, nil
}

// IsRefusal reports whether err is one of the attempt-validation refusals (a
// 4xx), as opposed to a store failure.
func IsRefusal(err error) bool {
	return errors.Is(err, ErrNoBinding) || errors.Is(err, ErrUnknownState) || errors.Is(err, ErrBindingMismatch)
}

// BindingMatches compares a presented cookie value with a stored hash in
// constant time. An empty value or hash never matches.
func BindingMatches(binding, storedHash string) bool {
	if binding == "" || storedHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashBinding(binding)), []byte(storedHash)) == 1
}

// S256Challenge is BASE64URL(SHA256(verifier)) without padding (RFC 7636 4.2).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func hashBinding(binding string) string {
	sum := sha256.Sum256([]byte(binding))
	return fmt.Sprintf("%x", sum[:])
}

// randomToken is 32 random bytes, base64url: 43 characters, which is also the
// minimum PKCE verifier length.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("ssostate: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Cookie describes the binding cookie for one flow.
type Cookie struct {
	Name string
	// Path is the callback path (CallbackPath), so the cookie goes nowhere else.
	Path   string
	Domain string
	Secure bool
}

// Set writes the binding cookie: HttpOnly, SameSite=Lax, expiring with TTL.
func (ck Cookie) Set(w http.ResponseWriter, binding string) {
	http.SetCookie(w, &http.Cookie{
		Name: ck.Name, Value: binding, Path: ck.Path, Domain: ck.Domain,
		MaxAge: int(TTL / time.Second), HttpOnly: true, Secure: ck.Secure, SameSite: http.SameSiteLaxMode,
	})
}

// Clear expires the binding cookie. The callback calls it on every outcome:
// the attempt is over either way.
func (ck Cookie) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: ck.Name, Value: "", Path: ck.Path, Domain: ck.Domain,
		MaxAge: -1, HttpOnly: true, Secure: ck.Secure, SameSite: http.SameSiteLaxMode,
	})
}

// Read returns the presented binding, or "".
func (ck Cookie) Read(r *http.Request) string {
	c, err := r.Cookie(ck.Name)
	if err != nil {
		return ""
	}
	return c.Value
}

// CallbackPath is the (escaped) path of redirectURI, the path the browser
// requests when the IdP sends it back. "/" if redirectURI does not parse.
func CallbackPath(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.EscapedPath() == "" {
		return "/"
	}
	return u.EscapedPath()
}

// RedisStore is the production store: SET with expiry, GETDEL to consume
// (atomic; Redis 6.2+).
type RedisStore struct{ rdb *redis.Client }

// NewRedisStore wraps a client; nil yields a nil Store so callers fail closed.
func NewRedisStore(rdb *redis.Client) Store {
	if rdb == nil {
		return nil
	}
	return RedisStore{rdb: rdb}
}

func (s RedisStore) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.rdb.Set(ctx, key, value, ttl).Err()
}

func (s RedisStore) Take(ctx context.Context, key string) ([]byte, error) {
	v, err := s.rdb.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrUnknownState
	}
	return v, err
}

// MemoryStore is the single-process fallback for a service running without
// Redis. With several replicas an attempt started on one and finished on
// another is refused (fails closed). It holds at most maxMemoryEntries live
// attempts.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
	now     func() time.Time
}

type memoryEntry struct {
	value   []byte
	expires time.Time
}

const maxMemoryEntries = 10000

// NewMemoryStore returns an empty in-process store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: map[string]memoryEntry{}, now: time.Now}
}

func (s *MemoryStore) Put(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.entries) >= maxMemoryEntries {
		for k, e := range s.entries {
			if !now.Before(e.expires) {
				delete(s.entries, k)
			}
		}
		if len(s.entries) >= maxMemoryEntries {
			return errors.New("ssostate: too many sign-ins in flight")
		}
	}
	s.entries[key] = memoryEntry{value: append([]byte(nil), value...), expires: now.Add(ttl)}
	return nil
}

func (s *MemoryStore) Take(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	delete(s.entries, key)
	if !ok || !s.now().Before(e.expires) {
		return nil, ErrUnknownState
	}
	return e.value, nil
}
