package identity

import (
	"container/list"
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
)

// GenericConfidence is the confidence a generic hostname is recorded with. A
// generic name is true — the device did announce it — but it says little about
// WHICH device, and the number makes that visible to anyone reading the row.
const GenericConfidence = 0.3

// GenericCardinalityThreshold is how many distinct assets in a tenant must
// carry one hostname value before the value is generic for that tenant. One
// asset is a name; two can be a device seen twice under two scopes; three is a
// name nobody chose.
const GenericCardinalityThreshold = 3

// Defaults for the cardinality cache. Ten minutes is the spec's window: a name
// crossing the threshold is recognised within one such window, and a tenant's
// sightings within it cost one query per distinct name rather than one each.
const (
	DefaultGenericCacheTTL = 10 * time.Minute
	DefaultGenericCacheMax = 10_000
)

// HostnameCardinalityCounter is the part of [Repository] the tenant-frequency
// signal needs. It is its own interface so a test can count calls, and so a
// caller holding only a store handle can build a [GenericNames] without the
// whole Repository.
type HostnameCardinalityCounter interface {
	// HostnameCardinality is the number of distinct live assets in the tenant
	// carrying a `hostname` identifier with this value, in ANY scope. See
	// [Repository.HostnameCardinality].
	HostnameCardinality(ctx context.Context, tenantID, value string) (int, error)
}

// GenericNames decides, for one tenant, whether a hostname identifier is
// generic, and marks it so ( B2). It is the ONE place that decision is
// made: inventory-service's host-observation ingest and
// device-interrogation-service's peer path both call it, because two spellings
// of "is this name generic" is how two intake paths come to disagree about the
// same device.
//
// A name is generic when EITHER
//
//   - it is in the static dictionary or matches the pattern
//     ([hostnamequality.IsGeneric]); or
//   - [GenericCardinalityThreshold] or more distinct assets in the tenant carry
//     it, in any scope ([HostnameCardinalityCounter]).
//
// The static test runs first and needs no database. The tenant count is cached
// per (tenant, value) for a TTL and bounded in size, and it is FAIL-OPEN: an
// error counting is logged and the name is treated as not generic by that
// signal. The name is still recorded either way, and a failed count must never
// lose an observation.
//
// Safe for concurrent use. The zero value and a nil *GenericNames are both
// usable and apply the static test alone.
type GenericNames struct {
	counter HostnameCardinalityCounter
	ttl     time.Duration
	max     int
	now     func() time.Time
	logf    func(format string, args ...any)

	mu    sync.Mutex
	order *list.List               // front = most recently used; values are *cardinalityEntry
	byKey map[string]*list.Element // tenant|value → element in order
}

type cardinalityEntry struct {
	key     string
	count   int
	expires time.Time
}

// GenericNamesOption configures [NewGenericNames].
type GenericNamesOption func(*GenericNames)

// WithGenericCacheTTL overrides [DefaultGenericCacheTTL]. A non-positive value
// is ignored.
func WithGenericCacheTTL(d time.Duration) GenericNamesOption {
	return func(g *GenericNames) {
		if d > 0 {
			g.ttl = d
		}
	}
}

// WithGenericCacheMax overrides [DefaultGenericCacheMax], the most
// (tenant, value) counts held at once. A non-positive value is ignored.
func WithGenericCacheMax(n int) GenericNamesOption {
	return func(g *GenericNames) {
		if n > 0 {
			g.max = n
		}
	}
}

// WithGenericClock replaces time.Now, so a test can expire the cache without
// sleeping. Nil is ignored.
func WithGenericClock(now func() time.Time) GenericNamesOption {
	return func(g *GenericNames) {
		if now != nil {
			g.now = now
		}
	}
}

// NewGenericNames builds a GenericNames over a store. counter may be nil, in
// which case only the static dictionary applies.
func NewGenericNames(counter HostnameCardinalityCounter, opts ...GenericNamesOption) *GenericNames {
	g := &GenericNames{
		counter: counter,
		ttl:     DefaultGenericCacheTTL,
		max:     DefaultGenericCacheMax,
		now:     time.Now,
		logf:    log.Printf,
		order:   list.New(),
		byKey:   map[string]*list.Element{},
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// IsGeneric reports whether a hostname is generic for the tenant.
func (g *GenericNames) IsGeneric(ctx context.Context, tenantID, value string) bool {
	if hostnamequality.IsGeneric(value) {
		return true
	}
	if g == nil || g.counter == nil {
		return false
	}
	name := normalizeHostnameValue(value)
	if name == "" {
		return false
	}
	n, err := g.cardinality(ctx, tenantID, name)
	if err != nil {
		g.logf("[identity] hostname cardinality for %q failed; treating it as not generic: %v", name, err)
		return false
	}
	return n >= GenericCardinalityThreshold
}

// Mark returns id marked generic when it is: [Identifier.Generic] set and
// [Identifier.Confidence] lowered to [GenericConfidence] (never raised). Only a
// `hostname` identifier can be generic — an FQDN is issued by someone who owns
// the domain, and every other kind is a token, not a word. Anything else, and a
// hostname that is not generic, comes back unchanged.
//
// The name is still recorded by the engine; marking only changes what it may
// prove.
//
// Do NOT call it for a name an operator typed. A declared `printer` is that
// person's statement about which device this is.
func (g *GenericNames) Mark(ctx context.Context, tenantID string, id Identifier) Identifier {
	if id.Kind != KindHostname || !g.IsGeneric(ctx, tenantID, id.Value) {
		return id
	}
	id.Generic = true
	if id.Confidence <= 0 || id.Confidence > GenericConfidence {
		id.Confidence = GenericConfidence
	}
	return id
}

// MarkAll marks each identifier in place of the slice it is given (which it
// returns), and is the form both intake paths call.
func (g *GenericNames) MarkAll(ctx context.Context, tenantID string, ids []Identifier) []Identifier {
	for i := range ids {
		ids[i] = g.Mark(ctx, tenantID, ids[i])
	}
	return ids
}

// cardinality returns the tenant's count for a normalised value, from the cache
// when it is fresh.
func (g *GenericNames) cardinality(ctx context.Context, tenantID, name string) (int, error) {
	key := tenantID + "|" + name
	now := g.now()

	g.mu.Lock()
	if el, ok := g.byKey[key]; ok {
		e := el.Value.(*cardinalityEntry)
		if now.Before(e.expires) {
			g.order.MoveToFront(el)
			n := e.count
			g.mu.Unlock()
			return n, nil
		}
		g.order.Remove(el)
		delete(g.byKey, key)
	}
	g.mu.Unlock()

	// The query runs outside the lock: two goroutines missing on one key both
	// ask, which costs a duplicate query and nothing else, whereas holding the
	// lock across a database call would serialise every ingest worker behind it.
	n, err := g.counter.HostnameCardinality(ctx, tenantID, name)
	if err != nil {
		// Errors are not cached: the next sighting asks again.
		return 0, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if el, ok := g.byKey[key]; ok {
		// A concurrent miss stored it first; refresh rather than duplicate.
		e := el.Value.(*cardinalityEntry)
		e.count, e.expires = n, now.Add(g.ttl)
		g.order.MoveToFront(el)
		return n, nil
	}
	g.byKey[key] = g.order.PushFront(&cardinalityEntry{key: key, count: n, expires: now.Add(g.ttl)})
	for g.order.Len() > g.max {
		oldest := g.order.Back()
		g.order.Remove(oldest)
		delete(g.byKey, oldest.Value.(*cardinalityEntry).key)
	}
	return n, nil
}

// ── the engine's reaction ( B2, part B) ────────────────────────────────
//
// A generic name is recorded but proves nothing. Three places in the engine act
// on the mark, and all three use the helpers below so they cannot disagree
// about what "linked only by a generic name" means:
//
//   - [Engine.kindVotes] never lets one decide a match;
//   - [Engine.resolveContested] and [Engine.resolveConflict] drop a candidate
//     whose only link is one (no candidate left → unresolved, one left →
//     supporting evidence);
//   - [Engine.resolveSupporting] and [Engine.provisionalMatchMode] never read
//     one as corroboration, so a shared `iphone` cannot be the link that fills
// a MAC into another phone's provisional record — the C1 wrong merge
//     with a default name standing in for the lease.

// genericOnly reports whether a non-empty link consists of generic names and
// nothing else. An empty link is not generic-only: it is no link (the
// confirmed-declaration path seeds a candidate with no evidence at all, and
// that candidate is a direct answer, not a default name).
func genericOnly(link []Identifier) bool {
	if len(link) == 0 {
		return false
	}
	for _, id := range link {
		if !id.Generic {
			return false
		}
	}
	return true
}

// withoutGeneric drops the generic names from a link, leaving what may speak
// for it.
func withoutGeneric(link []Identifier) []Identifier {
	var out []Identifier
	for _, id := range link {
		if !id.Generic {
			out = append(out, id)
		}
	}
	return out
}

// withoutGenericOnly drops, from candidates in discovery order, every asset
// whose evidence is generic names alone. Order is preserved.
func withoutGenericOnly(candidateSeq []string, evidence map[string][]Identifier) []string {
	out := make([]string, 0, len(candidateSeq))
	for _, id := range candidateSeq {
		if genericOnly(evidence[id]) {
			continue
		}
		out = append(out, id)
	}
	return out
}

// cacheLen is the number of cached counts, for the bound test.
func (g *GenericNames) cacheLen() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.order.Len()
}

// normalizeHostnameValue is the spelling stored hostnames have
// ([Normalize] for [KindHostname]: lower case, one trailing dot dropped),
// without the validation, so the count is asked about the value that would be
// stored.
func normalizeHostnameValue(v string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
}
