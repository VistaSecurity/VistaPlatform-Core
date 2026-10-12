package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/mcp-service/internal/auditlog"
)

const testUser = "22222222-2222-2222-2222-222222222222"

// authFake answers the exchange endpoint, counting calls. accept decides which
// tokens resolve; delay holds each answer so concurrent callers overlap.
type authFake struct {
	srv    *httptest.Server
	calls  atomic.Int32
	accept atomic.Bool
	delay  time.Duration
}

func newAuthFake(t *testing.T) *authFake {
	t.Helper()
	a := &authFake{}
	a.accept.Store(true)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.calls.Add(1)
		time.Sleep(a.delay)
		if !a.accept.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "jwt", "expires_at": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
			"tenant_id": "t", "user_id": testUser, "email": "u@example.com", "role": "tenant_admin",
			"permissions": []string{"assets.read"},
		})
	}))
	t.Cleanup(a.srv.Close)
	t.Setenv("INTERNAL_AUTH_SECRET", "test-secret")
	return a
}

func newTestExchanger(a *authFake, o Options) *Exchanger {
	return NewExchanger(a.srv.URL, nil, auditlog.NewRecorder(nopSink{}), o)
}

// cutoff stands in for the Redis checker's per-user issued-before cutoff.
type cutoff struct {
	mu sync.Mutex
	at time.Time
}

func (c *cutoff) IsRevoked(context.Context, string) bool { return false }
func (c *cutoff) IsIssuedBeforeUserCutoff(_ context.Context, _ uuid.UUID, issuedAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.at.IsZero() && issuedAt.Unix() < c.at.Unix()
}
func (c *cutoff) set(t time.Time) { c.mu.Lock(); c.at = t; c.mu.Unlock() }

// A cached grant is not served after a revocation cutoff: the next call goes
// back to auth-service, which (user deactivated) refuses it.
func TestCachedGrantRefusedAfterRevocationCutoff(t *testing.T) {
	a := newAuthFake(t)
	rc := &cutoff{}
	e := newTestExchanger(a, Options{Revocation: rc})
	ctx := context.Background()

	if _, err := e.Exchange(ctx, "qvpat_x"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Exchange(ctx, "qvpat_x"); err != nil || a.calls.Load() != 1 {
		t.Fatalf("second call should be a cache hit: err=%v calls=%d", err, a.calls.Load())
	}

	rc.set(time.Now().Add(time.Second)) // user deactivated
	a.accept.Store(false)
	if _, err := e.Exchange(ctx, "qvpat_x"); err != ErrUnauthorized {
		t.Fatalf("cached grant survived the cutoff: err=%v", err)
	}
	if a.calls.Load() != 2 {
		t.Fatalf("revoked grant must trigger a fresh exchange, calls=%d", a.calls.Load())
	}
}

// The positive cache is capped well below the JWT lifetime.
func TestGrantCacheTTLIsCapped(t *testing.T) {
	a := newAuthFake(t)
	e := newTestExchanger(a, Options{GrantCacheTTL: 60 * time.Second})
	now := time.Now()
	e.now = func() time.Time { return now }
	ctx := context.Background()

	_, _ = e.Exchange(ctx, "qvpat_x")
	now = now.Add(59 * time.Second)
	_, _ = e.Exchange(ctx, "qvpat_x")
	if a.calls.Load() != 1 {
		t.Fatalf("inside the TTL the grant must be cached, calls=%d", a.calls.Load())
	}
	now = now.Add(2 * time.Second) // 61s: JWT still has ~14 minutes
	_, _ = e.Exchange(ctx, "qvpat_x")
	if a.calls.Load() != 2 {
		t.Fatalf("past the 60s cap the grant must be re-exchanged although the JWT is valid, calls=%d", a.calls.Load())
	}
}

// Concurrent misses for one token share a single upstream call.
func TestConcurrentMissesAreCoalesced(t *testing.T) {
	a := newAuthFake(t)
	a.delay = 150 * time.Millisecond
	a.accept.Store(false)
	e := newTestExchanger(a, Options{AuthAttemptsPerMinute: -1})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.Exchange(context.Background(), "qvpat_same")
		}()
	}
	wg.Wait()
	if got := a.calls.Load(); got != 1 {
		t.Fatalf("auth-service calls = %d, want 1", got)
	}
}

// Negative entries expire.
func TestNegativeCacheExpires(t *testing.T) {
	a := newAuthFake(t)
	a.accept.Store(false)
	e := newTestExchanger(a, Options{NegativeCacheTTL: 30 * time.Second})
	now := time.Now()
	e.now = func() time.Time { return now }
	ctx := context.Background()

	_, _ = e.Exchange(ctx, "qvpat_x")
	_, _ = e.Exchange(ctx, "qvpat_x")
	if a.calls.Load() != 1 {
		t.Fatalf("calls=%d, want 1 inside the window", a.calls.Load())
	}
	now = now.Add(31 * time.Second)
	_, _ = e.Exchange(ctx, "qvpat_x")
	if a.calls.Load() != 2 {
		t.Fatalf("calls=%d, want a retry after the window", a.calls.Load())
	}
}

func TestJWTIssuedAtReadsIat(t *testing.T) {
	// header.{"iat":1700000000}.sig
	tok := "e30.eyJpYXQiOjE3MDAwMDAwMDB9.x"
	fb := time.Unix(5, 0)
	if got := jwtIssuedAt(tok, fb); got.Unix() != 1700000000 {
		t.Fatalf("iat = %v", got)
	}
	if got := jwtIssuedAt("opaque", fb); !got.Equal(fb) {
		t.Fatalf("fallback = %v", got)
	}
}
