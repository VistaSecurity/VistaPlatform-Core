package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// fingerprintLen is how much of the token hash is recorded on auth events —
// enough to correlate a credential across events, far too little to reverse.
const fingerprintLen = 16

// cacheKey derives the grant-cache key from the PAT without retaining the
// plaintext in memory beyond the request.
func cacheKey(pat string) string {
	sum := sha256.Sum256([]byte(pat))
	return hex.EncodeToString(sum[:])
}

// exchangeSafety is how long before JWT expiry a cached grant is considered
// stale — generous enough that a grant never expires mid tool-call fan-out.
const exchangeSafety = 2 * time.Minute

// maxCacheEntries bounds the grant and negative caches; beyond it the cache is
// dropped wholesale (simple and sufficient — entries self-expire in seconds).
const maxCacheEntries = 10000

// Defaults for Options. The positive TTL is the longest a revoked PAT, a
// deactivated user or a suspended tenant can keep working on a replica that has
// the grant cached (the per-user revocation cutoff closes the user cases
// immediately; see Options.Revocation). It is deliberately far below the 15
// minute exchange JWT lifetime.
const (
	DefaultGrantCacheTTL    = 60 * time.Second
	DefaultNegativeCacheTTL = 30 * time.Second
	// DefaultAuthAttemptsPerMinute bounds, per client address, the requests
	// that cost an upstream exchange (or carry no usable bearer at all).
	DefaultAuthAttemptsPerMinute = 60
	// perTokenAttemptsPerMinute bounds upstream exchanges for ONE credential,
	// which matters when the failure is a backend outage (those are not
	// negatively cached).
	perTokenAttemptsPerMinute = 12
)

// ErrRateLimited is returned when a client address or a credential has used
// its allowance of authentication attempts.
var ErrRateLimited = errors.New("too many authentication attempts")

// Options tunes the Exchanger. Zero values select the defaults.
type Options struct {
	// GrantCacheTTL caps how long a positive exchange result is served from
	// cache, regardless of the JWT's own expiry.
	GrantCacheTTL time.Duration
	// NegativeCacheTTL is how long a rejected credential is refused locally
	// without asking auth-service again.
	NegativeCacheTTL time.Duration
	// AuthAttemptsPerMinute is the per-client-address allowance; negative
	// disables the limiter.
	AuthAttemptsPerMinute int
	// Revocation is consulted on every cached grant, so an erased or
	// cut-off user is refused at once rather than when the cache ages out. Nil
	// disables the check (fail open, like every other consumer of it).
	Revocation sharedmw.RevocationChecker
}

// cachedGrant is a positive cache entry.
type cachedGrant struct {
	grant   *Grant
	validTo time.Time
}

// Exchanger resolves API tokens (PATs) to Grants via auth-service's
// HMAC-guarded /internal/api-tokens/exchange endpoint, caching the resulting
// short-lived JWT for at most Options.GrantCacheTTL so the hot path costs one
// map hit.
//
// Everything that reaches auth-service from an unauthenticated caller is
// bounded here: per-address and per-credential limiters sit in front of the
// upstream call, a rejected credential is refused locally for NegativeCacheTTL,
// and concurrent misses for one credential share a single upstream call.
type Exchanger struct {
	authBaseURL string
	httpc       *http.Client
	audit       *auditlog.Recorder

	grantTTL    time.Duration
	negativeTTL time.Duration
	revocation  sharedmw.RevocationChecker

	ipLimiter    *keyedLimiter
	tokenLimiter *keyedLimiter
	flight       singleflight.Group

	mu       sync.Mutex
	cache    map[string]*cachedGrant // key: SHA-256 of the PAT (never the plaintext)
	negative map[string]time.Time    // key -> refused until
	now      func() time.Time
}

func NewExchanger(authBaseURL string, httpc *http.Client, rec *auditlog.Recorder, opts ...Options) *Exchanger {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.GrantCacheTTL <= 0 {
		o.GrantCacheTTL = DefaultGrantCacheTTL
	}
	if o.NegativeCacheTTL <= 0 {
		o.NegativeCacheTTL = DefaultNegativeCacheTTL
	}
	if o.AuthAttemptsPerMinute == 0 {
		o.AuthAttemptsPerMinute = DefaultAuthAttemptsPerMinute
	}
	burst := o.AuthAttemptsPerMinute / 2
	if burst < 10 {
		burst = 10
	}
	return &Exchanger{
		authBaseURL:  authBaseURL,
		httpc:        httpc,
		audit:        rec,
		grantTTL:     o.GrantCacheTTL,
		negativeTTL:  o.NegativeCacheTTL,
		revocation:   o.Revocation,
		ipLimiter:    newKeyedLimiter(o.AuthAttemptsPerMinute, burst, maxCacheEntries),
		tokenLimiter: newKeyedLimiter(perTokenAttemptsPerMinute, 5, maxCacheEntries),
		cache:        map[string]*cachedGrant{},
		negative:     map[string]time.Time{},
		now:          time.Now,
	}
}

// AllowUnauthenticated spends one of the caller's per-address attempts on a
// request that carries no usable bearer token. The refusal such a request
// earns writes an audit row, so without this bound an anonymous flood is a
// write amplifier on the audit database. A nil Exchanger always allows.
func (e *Exchanger) AllowUnauthenticated(ctx context.Context) bool {
	if e == nil {
		return true
	}
	return e.ipLimiter.allow(RequestContextFrom(ctx).IPAddress)
}

type exchangeResponse struct {
	AccessToken string   `json:"access_token"`
	ExpiresAt   string   `json:"expires_at"`
	TenantID    string   `json:"tenant_id"`
	UserID      string   `json:"user_id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// Exchange resolves the plaintext PAT to a Grant, consulting the cache first.
// Any auth-service rejection surfaces as ErrUnauthorized; exhausting the
// per-address or per-credential allowance surfaces as ErrRateLimited.
//
// Audit: every credential decision auth-service actually makes is recorded —
// the fresh exchange that accepted a token, and every rejection or backend
// failure. A cache hit records nothing, because no decision was taken; the
// identity is still on every tool-call record, so no read is left unattributed.
// Neither does a locally refused repeat of a recently rejected credential, nor
// a rate-limited attempt: the first rejection was recorded, and the repeats
// are exactly the flood that must not become database writes.
func (e *Exchanger) Exchange(ctx context.Context, pat string) (*Grant, error) {
	key := cacheKey(pat)
	fingerprint := key[:fingerprintLen]

	now := e.now()
	e.mu.Lock()
	if c, ok := e.cache[key]; ok {
		if now.Before(c.validTo) && time.Until(c.grant.ExpiresAt) > exchangeSafety {
			g := c.grant
			e.mu.Unlock()
			if e.grantRevoked(ctx, g) {
				e.mu.Lock()
				delete(e.cache, key)
				e.mu.Unlock()
				// Fall through to a fresh exchange: auth-service is the authority
				// on whether the PAT still resolves (a deactivated user does not),
				// and a token minted after the cutoff is legitimately fine.
				return e.exchangeUpstream(ctx, pat, key, fingerprint)
			}
			return g, nil
		}
		delete(e.cache, key)
	}
	if until, ok := e.negative[key]; ok {
		if now.Before(until) {
			e.mu.Unlock()
			return nil, ErrUnauthorized
		}
		delete(e.negative, key)
	}
	e.mu.Unlock()

	return e.exchangeUpstream(ctx, pat, key, fingerprint)
}

// grantRevoked consults the per-user revocation denylist/cutoff.
func (e *Exchanger) grantRevoked(ctx context.Context, g *Grant) bool {
	if e.revocation == nil {
		return false
	}
	uid, err := uuid.Parse(g.UserID)
	if err != nil {
		return false
	}
	return sharedmw.IsUserTokenRevoked(ctx, e.revocation, uid, g.IssuedAt)
}

func (e *Exchanger) exchangeUpstream(ctx context.Context, pat, key, fingerprint string) (*Grant, error) {
	if !e.ipLimiter.allow(RequestContextFrom(ctx).IPAddress) || !e.tokenLimiter.allow(key) {
		return nil, ErrRateLimited
	}

	// Concurrent misses for one credential share one upstream call (and one
	// audit record). The call is detached from the first caller's cancellation
	// so that caller hanging up does not fail everyone waiting on it.
	v, err, _ := e.flight.Do(key, func() (any, error) {
		return e.fetch(context.WithoutCancel(ctx), pat, key, fingerprint)
	})
	if err != nil {
		return nil, err
	}
	return v.(*Grant), nil
}

func (e *Exchanger) fetch(ctx context.Context, pat, key, fingerprint string) (*Grant, error) {
	body, err := json.Marshal(map[string]string{"token": pat})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.authBaseURL+"/api/v1/auth-service/internal/api-tokens/exchange", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	serviceauth.SignRequestFromEnv(req)

	resp, err := e.httpc.Do(req)
	if err != nil {
		err = fmt.Errorf("auth-service unreachable: %w", err)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// proceed
	case http.StatusUnauthorized, http.StatusBadRequest:
		e.rememberRejected(key)
		e.recordAuth(ctx, auditlog.OutcomeTokenRejected, fingerprint, Grant{}, ErrUnauthorized)
		return nil, ErrUnauthorized
	default:
		err := fmt.Errorf("auth-service exchange returned %d", resp.StatusCode)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}

	var er exchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		err = fmt.Errorf("failed to decode exchange response: %w", err)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339, er.ExpiresAt)
	if err != nil {
		err = fmt.Errorf("failed to parse exchange expiry: %w", err)
		e.recordAuth(ctx, auditlog.OutcomeBackendUnavailable, fingerprint, Grant{}, err)
		return nil, err
	}

	issued := e.now()
	issuedAt := jwtIssuedAt(er.AccessToken, issued)
	g := &Grant{
		AccessToken: er.AccessToken,
		ExpiresAt:   expiresAt,
		IssuedAt:    issuedAt,
		TenantID:    er.TenantID,
		UserID:      er.UserID,
		Email:       er.Email,
		Role:        er.Role,
		Permissions: er.Permissions,
	}

	e.mu.Lock()
	if len(e.cache) >= maxCacheEntries {
		e.cache = map[string]*cachedGrant{}
	}
	e.cache[key] = &cachedGrant{grant: g, validTo: issued.Add(e.grantTTL)}
	delete(e.negative, key)
	e.mu.Unlock()

	e.recordAuth(ctx, auditlog.OutcomeTokenExchanged, fingerprint, *g, nil)

	return g, nil
}

// jwtIssuedAt reads the iat claim of a token auth-service just minted for us.
// The signature is NOT checked and need not be: the token came over the
// HMAC-authenticated exchange call, and the value is only compared against a
// revocation cutoff, where a too-early iat errs towards refusing. Anything
// unreadable falls back to fallback.
func jwtIssuedAt(token string, fallback time.Time) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fallback
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fallback
	}
	var claims struct {
		IAT json.Number `json:"iat"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return fallback
	}
	f, err := claims.IAT.Float64()
	if err != nil || f <= 0 {
		return fallback
	}
	return time.Unix(int64(f), 0)
}

// rememberRejected negatively caches a credential auth-service refused.
func (e *Exchanger) rememberRejected(key string) {
	e.mu.Lock()
	if len(e.negative) >= maxCacheEntries {
		e.negative = map[string]time.Time{}
	}
	e.negative[key] = e.now().Add(e.negativeTTL)
	e.mu.Unlock()
}

// recordAuth writes one authentication decision to the shared audit path.
func (e *Exchanger) recordAuth(ctx context.Context, outcome, fingerprint string, g Grant, err error) {
	e.audit.RecordAuth(ctx, auditlog.AuthEvent{
		Outcome:          outcome,
		Identity:         g.Identity(),
		Request:          RequestContextFrom(ctx),
		TokenFingerprint: fingerprint,
		Err:              err,
	})
}
