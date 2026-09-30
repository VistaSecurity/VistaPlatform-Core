package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingStore answers HostnameCardinality from a map and counts the calls, so
// a test can tell a cache hit from a query.
type countingStore struct {
	mu     sync.Mutex
	counts map[string]int
	err    error
	calls  atomic.Int32
}

func (s *countingStore) HostnameCardinality(_ context.Context, tenantID, value string) (int, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	return s.counts[tenantID+"|"+value], nil
}

func (s *countingStore) set(tenantID, value string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	s.counts[tenantID+"|"+value] = n
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func hostnameID(value string) Identifier {
	return Identifier{Kind: KindHostname, Value: value, Scope: "seg-1", Confidence: 1}
}

func TestGenericNames_MarksDictionaryNamesWithoutAskingTheStore(t *testing.T) {
	store := &countingStore{}
	g := NewGenericNames(store)
	got := g.Mark(context.Background(), "t1", hostnameID("printer"))
	if !got.Generic || got.Confidence != GenericConfidence {
		t.Fatalf("Mark(printer) = %+v, want Generic with confidence %v", got, GenericConfidence)
	}
	if store.calls.Load() != 0 {
		t.Errorf("a dictionary name cost %d queries, want 0", store.calls.Load())
	}
}

func TestGenericNames_MarksATenantFrequentName(t *testing.T) {
	store := &countingStore{}
	store.set("t1", "lobby-display", 3)
	g := NewGenericNames(store)

	got := g.Mark(context.Background(), "t1", hostnameID("Lobby-Display."))
	if !got.Generic || got.Confidence != GenericConfidence {
		t.Fatalf("a name three assets carry = %+v, want Generic with confidence %v", got, GenericConfidence)
	}
	if got.Value != "Lobby-Display." {
		t.Errorf("Mark changed the value to %q; the name is still recorded as given", got.Value)
	}
	// The count was asked for the folded spelling.
	if store.calls.Load() != 1 {
		t.Errorf("queries = %d, want 1", store.calls.Load())
	}

	// Another tenant's count is its own.
	if other := g.Mark(context.Background(), "t2", hostnameID("lobby-display")); other.Generic {
		t.Error("tenant t2 has no such assets; the name was marked generic from t1's count")
	}
}

func TestGenericNames_ThresholdIsExactlyThree(t *testing.T) {
	store := &countingStore{}
	clock := &fakeClock{t: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}
	g := NewGenericNames(store, WithGenericClock(clock.now))
	for n, want := range map[int]bool{0: false, 1: false, 2: false, 3: true, 4: true} {
		store.set("t1", "lobby-display", n)
		clock.t = clock.t.Add(2 * DefaultGenericCacheTTL) // expire the previous answer
		if got := g.IsGeneric(context.Background(), "t1", "lobby-display"); got != want {
			t.Errorf("cardinality %d: IsGeneric = %v, want %v", n, got, want)
		}
	}
}

func TestGenericNames_OnlyHostnamesAreMarked(t *testing.T) {
	store := &countingStore{}
	g := NewGenericNames(store)
	for _, id := range []Identifier{
		{Kind: KindFQDN, Value: "printer.corp.example", Confidence: 1},
		{Kind: KindSerialNumber, Value: "printer", Confidence: 1},
		{Kind: KindName, Value: "printer", Scope: "server", Confidence: 1},
	} {
		if got := g.Mark(context.Background(), "t1", id); got.Generic || got.Confidence != 1 {
			t.Errorf("Mark(%s %q) = %+v, want it untouched", id.Kind, id.Value, got)
		}
	}
	if store.calls.Load() != 0 {
		t.Errorf("non-hostname kinds cost %d queries, want 0", store.calls.Load())
	}
}

func TestGenericNames_NeverRaisesConfidence(t *testing.T) {
	g := NewGenericNames(nil)
	low := hostnameID("printer")
	low.Confidence = 0.1
	if got := g.Mark(context.Background(), "t1", low); got.Confidence != 0.1 || !got.Generic {
		t.Errorf("Mark = %+v, want confidence to stay 0.1 and Generic set", got)
	}
}

func TestGenericNames_AQueryErrorIsNotGenericAndIsNotCached(t *testing.T) {
	store := &countingStore{err: errors.New("db down")}
	g := NewGenericNames(store)
	var logged []string
	g.logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }

	if got := g.Mark(context.Background(), "t1", hostnameID("lobby-display")); got.Generic {
		t.Fatal("an error counting must not mark the name generic")
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "db down") {
		t.Errorf("the error was not logged: %v", logged)
	}
	// Recovery: the failure was not remembered.
	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	store.set("t1", "lobby-display", 5)
	if got := g.Mark(context.Background(), "t1", hostnameID("lobby-display")); !got.Generic {
		t.Error("after the store recovered the name should be generic; the earlier error was cached")
	}
	// A dictionary name is generic even when the store is down.
	store.mu.Lock()
	store.err = errors.New("db down")
	store.mu.Unlock()
	if got := g.Mark(context.Background(), "t1", hostnameID("printer")); !got.Generic {
		t.Error("the static dictionary must not depend on the store")
	}
}

func TestGenericNames_CacheAnswersWithinTheTTLAndExpiresAfter(t *testing.T) {
	store := &countingStore{}
	store.set("t1", "lobby-display", 1)
	clock := &fakeClock{t: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}
	g := NewGenericNames(store, WithGenericClock(clock.now))
	ctx := context.Background()

	if g.IsGeneric(ctx, "t1", "lobby-display") {
		t.Fatal("cardinality 1 must not be generic")
	}
	// The name becomes common, but the cached answer stands inside the window.
	store.set("t1", "lobby-display", 3)
	clock.t = clock.t.Add(DefaultGenericCacheTTL - time.Second)
	if g.IsGeneric(ctx, "t1", "lobby-display") {
		t.Error("inside the TTL the cached count (1) must answer; the store was asked again")
	}
	if store.calls.Load() != 1 {
		t.Errorf("queries = %d inside the TTL, want 1", store.calls.Load())
	}
	// Past it, the store is asked again and the new count is seen.
	clock.t = clock.t.Add(2 * time.Second)
	if !g.IsGeneric(ctx, "t1", "lobby-display") {
		t.Error("after the TTL the new count (3) must be seen")
	}
	if store.calls.Load() != 2 {
		t.Errorf("queries = %d after expiry, want 2", store.calls.Load())
	}
}

func TestGenericNames_CacheIsBounded(t *testing.T) {
	store := &countingStore{}
	g := NewGenericNames(store, WithGenericCacheMax(3))
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		g.IsGeneric(ctx, "t1", fmt.Sprintf("name-%d", i))
		if n := g.cacheLen(); n > 3 {
			t.Fatalf("after %d names the cache holds %d entries, want at most 3", i+1, n)
		}
	}
	if n := g.cacheLen(); n != 3 {
		t.Errorf("cache holds %d entries, want it full at 3", n)
	}

	// Least recently used goes first: touch name-47, add a new one, and 47
	// survives while 48 (untouched since) is the one evicted.
	g.IsGeneric(ctx, "t1", "name-47")
	before := store.calls.Load()
	g.IsGeneric(ctx, "t1", "brand-new")
	g.IsGeneric(ctx, "t1", "name-47")
	if store.calls.Load() != before+1 {
		t.Errorf("name-47 was evicted although it was the most recently used")
	}
}

func TestGenericNames_NilAndZeroValuesApplyTheStaticTestOnly(t *testing.T) {
	var nilNames *GenericNames
	if !nilNames.IsGeneric(context.Background(), "t1", "printer") || nilNames.IsGeneric(context.Background(), "t1", "lobby-display") {
		t.Error("a nil *GenericNames must apply the static test alone")
	}
	var zero GenericNames
	if !zero.IsGeneric(context.Background(), "t1", "iphone-2") || zero.IsGeneric(context.Background(), "t1", "lobby-display") {
		t.Error("the zero GenericNames must apply the static test alone")
	}
}

func TestGenericNames_ConcurrentUse(t *testing.T) {
	store := &countingStore{}
	store.set("t1", "lobby-display", 3)
	g := NewGenericNames(store, WithGenericCacheMax(4))
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				g.Mark(context.Background(), "t1", hostnameID(fmt.Sprintf("n%d", i%9)))
				g.Mark(context.Background(), "t1", hostnameID("lobby-display"))
			}
		}()
	}
	wg.Wait()
	if n := g.cacheLen(); n > 4 {
		t.Errorf("cache holds %d entries under concurrency, want at most 4", n)
	}
}

// Generic is context, not identity: it must not change an identifier's key, or
// the same name seen twice would be two identifiers.
func TestIdentifierKeyIgnoresGeneric(t *testing.T) {
	a := hostnameID("printer")
	b := a
	b.Generic = true
	if a.Key() != b.Key() {
		t.Errorf("Key differs with Generic: %q vs %q", a.Key(), b.Key())
	}
}
