// Package cache provides a shared Redis caching layer for all services.
// It implements consistent caching patterns with TTL management and cache invalidation.
package cache

import "time"

// TTL constants for different data volatility levels.
// These align with frontend staleTime configurations for consistency.
const (
	// TTLStatic is for data that rarely changes (frameworks, tiers, roles, permissions).
	// Frontend equivalent: STALE_TIMES.STATIC = 5 minutes
	TTLStatic = 5 * time.Minute

	// TTLSemiStatic is for data that changes occasionally (tenants, users, settings).
	// Frontend equivalent: STALE_TIMES.SEMI_STATIC = 30 seconds
	TTLSemiStatic = 30 * time.Second

	// TTLDynamic is for data that changes frequently (metrics, dashboards, logs).
	// Frontend equivalent: STALE_TIMES.DYNAMIC = 10 seconds
	TTLDynamic = 10 * time.Second

	// TTLShort is for very short-lived cache entries (1 minute).
	// Useful for facets, aggregations, and summary calculations.
	TTLShort = 1 * time.Minute

	// TTLRealtime means no caching (always fresh).
	// Used for live monitoring and alerts.
	TTLRealtime = 0
)

// TTLConfig holds configurable TTL values for a service.
// Services can override defaults based on their specific needs.
type TTLConfig struct {
	Static     time.Duration
	SemiStatic time.Duration
	Dynamic    time.Duration
	Short      time.Duration
}

// DefaultTTLConfig returns the default TTL configuration.
func DefaultTTLConfig() TTLConfig {
	return TTLConfig{
		Static:     TTLStatic,
		SemiStatic: TTLSemiStatic,
		Dynamic:    TTLDynamic,
		Short:      TTLShort,
	}
}
