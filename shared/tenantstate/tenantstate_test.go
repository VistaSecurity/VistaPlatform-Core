package tenantstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBlocked_EveryStateTheOwnerNamed(t *testing.T) {
	cases := []struct {
		name        string
		s           State
		wantBlocked bool
		wantCode    string
	}{
		{"active", State{Found: true, PaymentStatus: "active"}, false, ""},
		{"trial", State{Found: true, PaymentStatus: "trial"}, false, ""},
		{"past_due stays usable (dunning decides, not us)", State{Found: true, PaymentStatus: "past_due"}, false, ""},
		{"incomplete stays usable", State{Found: true, PaymentStatus: "incomplete"}, false, ""},
		{"empty status (legacy NULL) stays usable", State{Found: true}, false, ""},
		{"suspended", State{Found: true, PaymentStatus: "suspended"}, true, CodeSuspended},
		{"canceled", State{Found: true, PaymentStatus: "canceled"}, true, CodeSuspended},
		{"soft-deleted", State{Found: true, PaymentStatus: "active", Deleted: true}, true, CodeDeleted},
		{"soft-deleted wins over suspended", State{Found: true, PaymentStatus: "suspended", Deleted: true}, true, CodeDeleted},
		{"purged (no row)", State{Found: false}, true, CodeDeleted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, blocked := tc.s.Blocked()
			if blocked != tc.wantBlocked || code != tc.wantCode {
				t.Fatalf("Blocked() = (%q, %v), want (%q, %v)", code, blocked, tc.wantCode, tc.wantBlocked)
			}
		})
	}
}

type fakeLookup struct {
	state State
	err   error
	calls int
}

func (f *fakeLookup) fn(context.Context, uuid.UUID) (State, error) {
	f.calls++
	return f.state, f.err
}

// TestChecker_CacheExpiresSoSuspensionLands pins the bound on how long a live
// access token can outlive a suspension: at most one TTL. Mutation: make the
// cache ignore `expires` and this fails on the second assertion.
func TestChecker_CacheExpiresSoSuspensionLands(t *testing.T) {
	f := &fakeLookup{state: State{Found: true, PaymentStatus: "active"}}
	c := newChecker(f.fn, 30*time.Second)
	clock := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return clock }
	id := uuid.New()

	if _, blocked, err := c.Check(context.Background(), id); err != nil || blocked {
		t.Fatalf("live tenant: blocked=%v err=%v", blocked, err)
	}
	f.state = State{Found: true, PaymentStatus: "suspended"}

	clock = clock.Add(29 * time.Second)
	if _, blocked, _ := c.Check(context.Background(), id); blocked {
		t.Fatalf("within the TTL the cached answer should stand (lookups=%d)", f.calls)
	}
	if f.calls != 1 {
		t.Fatalf("cache hit should not re-query; lookups=%d", f.calls)
	}

	clock = clock.Add(2 * time.Second)
	code, blocked, err := c.Check(context.Background(), id)
	if err != nil || !blocked || code != CodeSuspended {
		t.Fatalf("after the TTL the suspension must land: code=%q blocked=%v err=%v", code, blocked, err)
	}
}

// TestChecker_ErrorsAreNotCached — a failed lookup must be retried, and must
// never be remembered as "allowed". Mutation: cache the zero entry on error and
// the recovery assertion fails.
func TestChecker_ErrorsAreNotCached(t *testing.T) {
	f := &fakeLookup{err: errors.New("db down")}
	c := newChecker(f.fn, time.Minute)
	id := uuid.New()

	if _, _, err := c.Check(context.Background(), id); err == nil {
		t.Fatal("lookup error must be returned so the caller fails closed")
	}
	f.err = nil
	f.state = State{Found: true, PaymentStatus: "suspended"}
	code, blocked, err := c.Check(context.Background(), id)
	if err != nil || !blocked || code != CodeSuspended {
		t.Fatalf("after recovery: code=%q blocked=%v err=%v", code, blocked, err)
	}
	if f.calls != 2 {
		t.Fatalf("lookups=%d, want 2 (the error must not have been cached)", f.calls)
	}
}

// TestChecker_PurgedTenantFailsClosed ( item 2) — soft delete, then purge,
// inside one access token's lifetime. The soft delete refuses the token; the
// purge removes the row that carried the refusal, and a missing row must stay
// refused rather than bring the token back to life. Both the plain check and
// the session check are pinned. Mutation: treat !Found as "not blocked" in
// Check (or CheckSession) and the "after the purge" assertions fail.
func TestChecker_PurgedTenantFailsClosed(t *testing.T) {
	f := &fakeLookup{state: State{Found: true, PaymentStatus: "active", SessionVersion: 3}}
	c := newChecker(f.fn, 0)
	id := uuid.New()
	ctx := context.Background()

	if _, blocked, revoked, err := c.CheckSession(ctx, id, 3); err != nil || blocked || revoked {
		t.Fatalf("live tenant: blocked=%v revoked=%v err=%v", blocked, revoked, err)
	}

	f.state = State{Found: true, PaymentStatus: "active", Deleted: true, SessionVersion: 4}
	if code, blocked, _ := c.Check(ctx, id); !blocked || code != CodeDeleted {
		t.Fatalf("soft-deleted: code=%q blocked=%v, want refused %s", code, blocked, CodeDeleted)
	}

	f.state = State{Found: false}
	if code, blocked, err := c.Check(ctx, id); err != nil || !blocked || code != CodeDeleted {
		t.Fatalf("after the purge Check: code=%q blocked=%v err=%v, want refused %s", code, blocked, err, CodeDeleted)
	}
	if code, blocked, _, err := c.CheckSession(ctx, id, 3); err != nil || !blocked || code != CodeDeleted {
		t.Fatalf("after the purge CheckSession: code=%q blocked=%v err=%v, want refused %s", code, blocked, err, CodeDeleted)
	}
}

// TestChecker_BlockedIsNotReportedAsRevoked — a blocked tenant answers with
// its block code, so the client sees tenant_suspended/tenant_deleted rather
// than a generic "session revoked" even when the token is also stale.
func TestChecker_BlockedIsNotReportedAsRevoked(t *testing.T) {
	f := &fakeLookup{state: State{Found: true, PaymentStatus: "suspended", SessionVersion: 5}}
	c := newChecker(f.fn, 0)
	code, blocked, revoked, err := c.CheckSession(context.Background(), uuid.New(), 1)
	if err != nil || !blocked || revoked || code != CodeSuspended {
		t.Fatalf("code=%q blocked=%v revoked=%v err=%v, want blocked %s", code, blocked, revoked, err, CodeSuspended)
	}
}

func TestChecker_ZeroTTLDisablesCache(t *testing.T) {
	f := &fakeLookup{state: State{Found: true, PaymentStatus: "active"}}
	c := newChecker(f.fn, 0)
	id := uuid.New()
	_, _, _ = c.Check(context.Background(), id)
	_, _, _ = c.Check(context.Background(), id)
	if f.calls != 2 {
		t.Fatalf("lookups=%d, want 2 with caching disabled", f.calls)
	}
}

func TestChecker_SessionVersionPermanentlyRevokesOldToken(t *testing.T) {
	f := &fakeLookup{state: State{Found: true, PaymentStatus: "active", SessionVersion: 2}}
	c := newChecker(f.fn, 0)
	id := uuid.New()

	if code, blocked, revoked, err := c.CheckSession(context.Background(), id, 1); err != nil || blocked || !revoked || code != "" {
		t.Fatalf("old token: code=%q blocked=%v revoked=%v err=%v", code, blocked, revoked, err)
	}
	if _, blocked, revoked, err := c.CheckSession(context.Background(), id, 2); err != nil || blocked || revoked {
		t.Fatalf("current token: blocked=%v revoked=%v err=%v", blocked, revoked, err)
	}

	// Reactivation changes payment state, not the monotonically increasing
	// generation, so the old token remains revoked.
	f.state = State{Found: true, PaymentStatus: "active", SessionVersion: 2}
	if _, _, revoked, _ := c.CheckSession(context.Background(), id, 1); !revoked {
		t.Fatal("reactivation revived a pre-suspension token")
	}
}

func TestCacheTTLFromEnv(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want time.Duration
	}{
		{"", DefaultCacheTTL},
		{"0s", 0},
		{"5s", 5 * time.Second},
		{"garbage", DefaultCacheTTL},
		{"-1s", DefaultCacheTTL},
	} {
		t.Setenv("TENANT_STATE_CACHE_TTL", tc.v)
		if got := CacheTTLFromEnv(); got != tc.want {
			t.Errorf("TENANT_STATE_CACHE_TTL=%q → %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestCheckerFromEnv_NilWithoutDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	if c := CheckerFromEnv(); c != nil {
		t.Fatal("no DATABASE_URL must yield no checker (callers log the check as disabled)")
	}
}

func TestAsBlocked(t *testing.T) {
	be := &BlockedError{Code: CodeSuspended}
	wrapped := errors.Join(errors.New("mint"), be)
	got, ok := AsBlocked(wrapped)
	if !ok || got.Code != CodeSuspended {
		t.Fatalf("AsBlocked(%v) = %v, %v", wrapped, got, ok)
	}
	if _, ok := AsBlocked(errors.New("other")); ok {
		t.Fatal("AsBlocked matched a non-blocked error")
	}
}
