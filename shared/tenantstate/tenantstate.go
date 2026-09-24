// Package tenantstate decides whether a tenant may still be used, and is the
// one place every enforcement point asks.
//
// Owner decision (admin-ui review RC-4): a tenant that a platform
// admin has suspended, that has been canceled (offboarding, or billing), or that
// has been soft-deleted is NOT usable. Its users cannot sign in, cannot refresh
// a session, and a session issued before the change stops working. Read-only
// access for a suspended tenant was considered and deferred.
//
// Before this package the two facts that express that decision —
// tenants.payment_status and tenants.deleted_at — were written by admin-service
// and read by nothing on the login, refresh or request path, so "Suspend" in the
// admin UI changed nothing a tenant user could notice. The states and their
// meanings live here so the login gate, the refresh gate, every JWT middleware
// and the agent check-in gates cannot come to disagree about who is blocked.
//
// Platform administrators are unaffected: they carry no tenant. A platform
// administrator impersonating a user of a blocked tenant is also allowed — the
// callers skip the check for impersonation tokens — so support can still look
// at a suspended tenant's data.
package tenantstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // PostgreSQL driver for the env-built pool
)

// Response codes returned (as the JSON "code" field, with HTTP 403) when a
// blocked tenant's user or agent is refused. The web UI keys its sign-in
// message off these, so they are part of the API contract.
const (
	// CodeSuspended covers payment_status 'suspended' and 'canceled'.
	CodeSuspended = "tenant_suspended"
	// CodeDeleted covers a soft-deleted tenant (deleted_at set) and a tenant
	// row that no longer exists at all (purged) — at sign-in and on every
	// request.
	CodeDeleted = "tenant_deleted"
	// CodeUnavailable is returned with HTTP 503 when the state could not be
	// read. Enforcement fails CLOSED: an unreadable state is not permission.
	CodeUnavailable = "tenant_status_unavailable"
)

// BlockedPaymentStatuses are the tenants.payment_status values that make a
// tenant unusable. Values are from the valid_payment_status CHECK constraint.
//
// 'past_due' and 'incomplete' are deliberately absent: those tenants are
// customers in the dunning flow, and locking them out of the product is not
// what that flow decides. 'trial' and 'active' are live.
var BlockedPaymentStatuses = []string{"suspended", "canceled"}

// State is one tenant's row as the enforcement points see it.
type State struct {
	// Found is false when no tenants row exists for the id (a purged tenant).
	Found         bool
	PaymentStatus string
	Deleted       bool
	// SessionVersion is incremented whenever all of a tenant's sessions are
	// revoked. Tokens carry the version they were minted under, so a token from
	// before a suspension cannot become usable again after reactivation.
	SessionVersion int64
}

// Blocked reports whether the state makes the tenant unusable and, if so, the
// response code to answer with.
func (s State) Blocked() (code string, blocked bool) {
	if !s.Found || s.Deleted {
		return CodeDeleted, true
	}
	for _, st := range BlockedPaymentStatuses {
		if s.PaymentStatus == st {
			return CodeSuspended, true
		}
	}
	return "", false
}

// Message is the human sentence that accompanies a code. It is written for the
// tenant user who sees it on the sign-in page.
func Message(code string) string {
	switch code {
	case CodeSuspended:
		return "Your organization's account is suspended. Contact your administrator or Vista Security support."
	case CodeDeleted:
		return "Your organization's account has been deleted."
	case CodeUnavailable:
		return "Unable to verify your organization's account status. Please try again shortly."
	default:
		return "Your organization's account is not available."
	}
}

// BlockedError is returned by the session-minting gate when the tenant is
// blocked. Handlers map it to 403 with Code.
type BlockedError struct{ Code string }

func (e *BlockedError) Error() string { return "tenant blocked: " + e.Code }

// AsBlocked unwraps a BlockedError from err.
func AsBlocked(err error) (*BlockedError, bool) {
	var be *BlockedError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}

// Querier is the subset of *sql.DB (or *sql.Tx) Lookup needs.
type Querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// lookupSQL reads the global tenants row. `tenants` has no tenant_isolation
// policy, so this works on the RLS-enforcing app role with no tenant context.
const lookupSQL = `SELECT COALESCE(payment_status, ''), deleted_at IS NOT NULL, session_version FROM tenants WHERE id = $1`

// Lookup reads one tenant's state, uncached. sql.ErrNoRows is not an error: it
// is a tenant that no longer exists, which Blocked reports as deleted.
func Lookup(ctx context.Context, q Querier, tenantID uuid.UUID) (State, error) {
	var s State
	err := q.QueryRowContext(ctx, lookupSQL, tenantID).Scan(&s.PaymentStatus, &s.Deleted, &s.SessionVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return State{Found: false}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read tenant state: %w", err)
	}
	s.Found = true
	return s, nil
}

// Gate returns the check a session-minting path runs before it issues tokens
// for a tenant user: nil when the tenant is usable, a *BlockedError when it is
// not, and the lookup error otherwise (the caller fails closed). It reads
// uncached — sign-in and refresh are rare enough that the answer should be the
// database's, not a cache's.
func Gate(q Querier) func(ctx context.Context, tenantID uuid.UUID) error {
	return func(ctx context.Context, tenantID uuid.UUID) error {
		s, err := Lookup(ctx, q, tenantID)
		if err != nil {
			return err
		}
		if code, blocked := s.Blocked(); blocked {
			return &BlockedError{Code: code}
		}
		return nil
	}
}

// VersionGate is Gate plus the session generation a newly minted token must
// carry. Keeping the state decision and version read in one query prevents a
// suspension from landing between two separate reads.
func VersionGate(q Querier) func(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	return func(ctx context.Context, tenantID uuid.UUID) (int64, error) {
		s, err := Lookup(ctx, q, tenantID)
		if err != nil {
			return 0, err
		}
		if code, blocked := s.Blocked(); blocked {
			return 0, &BlockedError{Code: code}
		}
		return s.SessionVersion, nil
	}
}

// DefaultCacheTTL bounds how long a per-request check trusts a previous answer.
// It is the longest a suspension can take to reach a request carrying an access
// token issued before it. Override with TENANT_STATE_CACHE_TTL (a Go duration;
// "0s" disables caching).
const DefaultCacheTTL = 30 * time.Second

// CacheTTLFromEnv resolves the per-request cache lifetime. An unparseable or
// negative value falls back to the default rather than to "never cache" or
// "cache forever".
func CacheTTLFromEnv() time.Duration {
	v := os.Getenv("TENANT_STATE_CACHE_TTL")
	if v == "" {
		return DefaultCacheTTL
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return DefaultCacheTTL
	}
	return d
}

type cacheEntry struct {
	state   State
	expires time.Time
}

// Checker is the per-request check: Lookup behind a short in-process cache.
// Errors are never cached, so a transient database failure is retried on the
// next request instead of being remembered.
type Checker struct {
	lookup func(context.Context, uuid.UUID) (State, error)
	ttl    time.Duration
	now    func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]cacheEntry
}

// NewChecker builds a Checker over q. ttl <= 0 disables caching.
func NewChecker(q Querier, ttl time.Duration) *Checker {
	return newChecker(func(ctx context.Context, id uuid.UUID) (State, error) { return Lookup(ctx, q, id) }, ttl)
}

func newChecker(lookup func(context.Context, uuid.UUID) (State, error), ttl time.Duration) *Checker {
	return &Checker{lookup: lookup, ttl: ttl, now: time.Now, cache: map[uuid.UUID]cacheEntry{}}
}

// maxCacheEntries bounds the cache. Tenant ids come from signed tokens, so the
// set is naturally small; the bound only guards against an unexpected flood.
const maxCacheEntries = 10000

// Check answers whether tenantID is blocked. On a lookup error it returns the
// error and the caller must fail closed.
func (c *Checker) Check(ctx context.Context, tenantID uuid.UUID) (code string, blocked bool, err error) {
	s, err := c.state(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	// A tenant with no row at all is refused as deleted, exactly as the mint
	// Gate refuses it ( item 2). This check used to let such a token
	// through, on the reasoning that a purge is always preceded by a soft
	// delete that this check already refused. That held only UNTIL the purge:
	// the soft delete's refusal lived in the row the purge removed, so a token
	// issued before the soft delete worked again for the rest of its lifetime.
	// A signed token names a tenant; if that tenant does not exist, the token
	// does not describe anyone who may still act.
	code, blocked = s.Blocked()
	return code, blocked, nil
}

// CheckSession performs the normal tenant-state check and additionally
// rejects a JWT minted under an older tenant session generation. A tenant with
// no row is blocked (see Check), not merely revoked.
func (c *Checker) CheckSession(ctx context.Context, tenantID uuid.UUID, tokenVersion int64) (code string, blocked, revoked bool, err error) {
	s, err := c.state(ctx, tenantID)
	if err != nil {
		return "", false, false, err
	}
	code, blocked = s.Blocked()
	if blocked {
		return code, true, false, nil
	}
	return "", false, tokenVersion < s.SessionVersion, nil
}

func (c *Checker) state(ctx context.Context, tenantID uuid.UUID) (State, error) {
	if c.ttl > 0 {
		c.mu.Lock()
		e, ok := c.cache[tenantID]
		c.mu.Unlock()
		if ok && c.now().Before(e.expires) {
			return e.state, nil
		}
	}
	s, err := c.lookup(ctx, tenantID)
	if err != nil {
		return State{}, err
	}
	if c.ttl > 0 {
		c.mu.Lock()
		if len(c.cache) >= maxCacheEntries {
			c.cache = map[uuid.UUID]cacheEntry{}
		}
		c.cache[tenantID] = cacheEntry{state: s, expires: c.now().Add(c.ttl)}
		c.mu.Unlock()
	}
	return s, nil
}

var (
	poolsMu sync.Mutex
	pools   = map[string]*sql.DB{}
)

// CheckerFromEnv builds a per-request Checker over DATABASE_URL — the same
// connection string every backend already uses — so every service that
// authenticates tenant JWTs enforces tenant state with no per-service wiring
// (the same pattern the JWT revocation denylist uses with REDIS_URL).
//
// The pool is small (the cache keeps traffic to roughly one query per tenant
// per TTL per middleware instance), opened lazily, and shared per process per
// URL. Returns nil when DATABASE_URL is unset; callers log that the check is
// disabled. Each call returns a fresh cache so separately-built middleware
// instances do not share stale answers.
func CheckerFromEnv() *Checker {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil
	}
	poolsMu.Lock()
	defer poolsMu.Unlock()
	db, ok := pools[url]
	if !ok {
		var err error
		db, err = sql.Open("postgres", url)
		if err != nil {
			// Only an unregistered driver makes sql.Open fail, and lib/pq is
			// imported above; treat it like an unset URL.
			return nil
		}
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(1)
		db.SetConnMaxIdleTime(time.Minute)
		db.SetConnMaxLifetime(5 * time.Minute)
		pools[url] = db
	}
	return NewChecker(db, CacheTTLFromEnv())
}
