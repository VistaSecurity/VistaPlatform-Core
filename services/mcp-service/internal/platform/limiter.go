package platform

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyedLimiter is a set of token buckets addressed by an arbitrary key (a
// client IP, a token fingerprint). It is in-process on purpose: the service
// holds no datastore (its registry entry has no redis dependency), and a
// per-replica ceiling is all an abuse limiter needs — N replicas multiply the
// ceiling by N, they do not defeat it.
type keyedLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	perMinute  float64
	burst      int
	maxEntries int
	now        func() time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newKeyedLimiter(perMinute, burst, maxEntries int) *keyedLimiter {
	return &keyedLimiter{
		buckets:    map[string]*bucket{},
		perMinute:  float64(perMinute),
		burst:      burst,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// allow takes one token from key's bucket. A limiter configured with a rate
// below 1/min is disabled and always allows.
func (k *keyedLimiter) allow(key string) bool {
	if k == nil || k.perMinute < 1 {
		return true
	}
	now := k.now()
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxEntries {
			k.evictLocked(now)
		}
		b = &bucket{lim: rate.NewLimiter(rate.Limit(k.perMinute/60), k.burst)}
		k.buckets[key] = b
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}

// evictLocked drops buckets idle for 10 minutes; if the table is still full
// (a flood of distinct keys) it is dropped wholesale. Dropping resets the
// attackers' budgets too, but bounded memory matters more than a perfect memory
// of every address ever seen.
func (k *keyedLimiter) evictLocked(now time.Time) {
	for key, b := range k.buckets {
		if now.Sub(b.seen) > 10*time.Minute {
			delete(k.buckets, key)
		}
	}
	if len(k.buckets) >= k.maxEntries {
		k.buckets = map[string]*bucket{}
	}
}
