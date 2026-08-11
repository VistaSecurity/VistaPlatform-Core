package cache

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ConnectionCache deduplicates discoveries by caching recently seen connections
// This prevents creating thousands of duplicate discoveries for the same connection
type ConnectionCache struct {
	cache   map[string]*CachedConnection
	mu      sync.RWMutex
	ttl     time.Duration // How long before re-reporting a connection
	maxSize int           // Maximum number of cached connections
	hits    int64         // Cache hits (connection already seen)
	misses  int64         // Cache misses (new connection)
}

// CachedConnection represents a cached network connection
type CachedConnection struct {
	Key        string    // "destIP:port:protocol"
	FirstSeen  time.Time // When first observed
	LastSeen   time.Time // Most recent observation
	ReportedAt time.Time // When last reported to control plane
	HitCount   int64     // Number of times seen
}

// NewConnectionCache creates a new connection cache
func NewConnectionCache(ttl time.Duration, maxSize int) *ConnectionCache {
	if ttl == 0 {
		ttl = 60 * time.Minute // Default: 60 minutes
	}
	if maxSize == 0 {
		maxSize = 100000 // Default: 100k entries
	}

	return &ConnectionCache{
		cache:   make(map[string]*CachedConnection, maxSize),
		ttl:     ttl,
		maxSize: maxSize,
		hits:    0,
		misses:  0,
	}
}

// ShouldReport checks if a connection should be reported to the control plane
// Returns:
//   - shouldReport: true if this is a new connection or TTL expired
//   - isNew: true if this is the first time seeing this connection
func (cc *ConnectionCache) ShouldReport(destIP string, port int, protocol string) (shouldReport bool, isNew bool) {
	key := fmt.Sprintf("%s:%d:%s", destIP, port, protocol)
	now := time.Now()

	cc.mu.Lock()
	defer cc.mu.Unlock()

	cached, exists := cc.cache[key]

	// New connection - report it
	if !exists {
		cc.cache[key] = &CachedConnection{
			Key:        key,
			FirstSeen:  now,
			LastSeen:   now,
			ReportedAt: now,
			HitCount:   1,
		}
		cc.misses++

		// Check if we need to evict old entries
		if len(cc.cache) > cc.maxSize {
			cc.evictOldest()
		}

		return true, true
	}

	// Update last seen and hit count
	cached.LastSeen = now
	cached.HitCount++
	cc.hits++

	// Check if TTL expired - report again
	timeSinceReport := now.Sub(cached.ReportedAt)
	if timeSinceReport >= cc.ttl {
		cached.ReportedAt = now
		return true, false
	}

	// Recently reported - skip
	return false, false
}

// evictOldest removes the oldest 10% of entries to make room for new ones
func (cc *ConnectionCache) evictOldest() {
	// Don't call this with lock held - caller must have lock

	// Find oldest entries (sort by ReportedAt)
	type entry struct {
		key        string
		reportedAt time.Time
	}

	entries := make([]entry, 0, len(cc.cache))
	for key, conn := range cc.cache {
		entries = append(entries, entry{key: key, reportedAt: conn.ReportedAt})
	}

	// Sort by ReportedAt ascending (oldest first) — O(n log n)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].reportedAt.Before(entries[j].reportedAt)
	})

	// Evict oldest 10%
	evictCount := len(entries) / 10
	if evictCount < 1 {
		evictCount = 1
	}

	for i := 0; i < evictCount && i < len(entries); i++ {
		delete(cc.cache, entries[i].key)
	}
}

// Cleanup removes expired entries (should be called periodically)
func (cc *ConnectionCache) Cleanup() {
	now := time.Now()

	cc.mu.Lock()
	defer cc.mu.Unlock()

	toDelete := make([]string, 0)

	for key, conn := range cc.cache {
		// Remove if not seen in 2x TTL
		if now.Sub(conn.LastSeen) > (cc.ttl * 2) {
			toDelete = append(toDelete, key)
		}
	}

	for _, key := range toDelete {
		delete(cc.cache, key)
	}
}

// Size returns the current cache size
func (cc *ConnectionCache) Size() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return len(cc.cache)
}

// Stats returns cache statistics
func (cc *ConnectionCache) Stats() CacheStats {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	total := cc.hits + cc.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(cc.hits) / float64(total)
	}

	return CacheStats{
		Size:    len(cc.cache),
		Hits:    cc.hits,
		Misses:  cc.misses,
		HitRate: hitRate,
		TTL:     cc.ttl,
		MaxSize: cc.maxSize,
	}
}

// HitRate returns the cache hit rate as a percentage (0-100)
func (cc *ConnectionCache) HitRate() float64 {
	stats := cc.Stats()
	return stats.HitRate * 100.0
}

// CacheStats holds cache statistics
type CacheStats struct {
	Size    int           `json:"size"`
	Hits    int64         `json:"hits"`
	Misses  int64         `json:"misses"`
	HitRate float64       `json:"hit_rate"`
	TTL     time.Duration `json:"ttl_seconds"`
	MaxSize int           `json:"max_size"`
}

// Clear removes all entries from the cache
func (cc *ConnectionCache) Clear() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.cache = make(map[string]*CachedConnection, cc.maxSize)
	cc.hits = 0
	cc.misses = 0
}

// SetTTL updates the cache TTL at runtime.  Existing entries are not
// retroactively adjusted — the new TTL takes effect on the next
// ShouldReport evaluation for each entry.
func (cc *ConnectionCache) SetTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	cc.mu.Lock()
	cc.ttl = ttl
	cc.mu.Unlock()
}
