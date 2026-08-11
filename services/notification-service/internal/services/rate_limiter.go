package services

import (
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	defaultChannelRateMax    = 60              // deliveries per window per channel
	defaultChannelRateWindow = 5 * time.Minute // sliding window
	rateLimitSpillWindowMin  = 15              // spilled notifications digest within this many minutes
)

// ChannelRateLimiter caps immediate deliveries per channel over a sliding
// window (in-memory, per-instance — storm control §10.3). Excess deliveries are
// not dropped: the caller spills them into the digest engine.
type ChannelRateLimiter struct {
	mu     sync.Mutex
	hits   map[uuid.UUID][]time.Time
	max    int
	window time.Duration
}

// NewChannelRateLimiter reads NOTIFICATION_CHANNEL_RATE_MAX /
// NOTIFICATION_CHANNEL_RATE_WINDOW_SEC (falling back to 60 per 5m). A max <= 0
// disables limiting.
func NewChannelRateLimiter() *ChannelRateLimiter {
	max := defaultChannelRateMax
	if v := os.Getenv("NOTIFICATION_CHANNEL_RATE_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			max = n
		}
	}
	window := defaultChannelRateWindow
	if v := os.Getenv("NOTIFICATION_CHANNEL_RATE_WINDOW_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			window = time.Duration(n) * time.Second
		}
	}
	return &ChannelRateLimiter{hits: map[uuid.UUID][]time.Time{}, max: max, window: window}
}

// Allow records a delivery attempt for the channel and reports whether it is
// within the cap. When it returns false the caller should spill to digest.
func (r *ChannelRateLimiter) Allow(channelID uuid.UUID) bool {
	if r.max <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-r.window)
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.hits[channelID]
	kept := make([]time.Time, 0, len(prev)+1)
	for _, t := range prev {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.max {
		r.hits[channelID] = kept
		return false
	}
	r.hits[channelID] = append(kept, now)
	return true
}
