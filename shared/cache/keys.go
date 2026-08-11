package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Key prefixes for different services to prevent key collisions.
const (
	PrefixAdmin      = "admin"
	PrefixInventory  = "inventory"
	PrefixAuth       = "auth"
	PrefixAudit      = "audit"
	PrefixCompliance = "compliance"
	PrefixSensor     = "sensor"
)

// Key generates a cache key with the service prefix and key parts.
// Example: Key(PrefixAdmin, "tenant-stats") -> "admin:tenant-stats"
// Example: Key(PrefixInventory, "assets", "facets", tenantID) -> "inventory:assets:facets:{tenantID}"
func Key(prefix string, parts ...string) string {
	allParts := append([]string{prefix}, parts...)
	return strings.Join(allParts, ":")
}

// TenantKey generates a tenant-scoped cache key.
// Example: TenantKey(PrefixAdmin, tenantID, "stats") -> "admin:tenant:{tenantID}:stats"
func TenantKey(prefix string, tenantID string, parts ...string) string {
	allParts := []string{prefix, "tenant", tenantID}
	allParts = append(allParts, parts...)
	return strings.Join(allParts, ":")
}

// ListKey generates a cache key for list endpoints with optional filters.
// Filters are sorted and hashed to create a stable, compact key.
// Example: ListKey(PrefixAdmin, "tenants", map[string]string{"status": "active"})
//
//	-> "admin:tenants:list:a1b2c3d4" (hash of filters)
func ListKey(prefix string, resource string, filters map[string]string) string {
	if len(filters) == 0 {
		return Key(prefix, resource, "list", "all")
	}

	// Sort filter keys for consistent hashing
	keys := make([]string, 0, len(filters))
	for k := range filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build filter string
	var filterParts []string
	for _, k := range keys {
		if filters[k] != "" {
			filterParts = append(filterParts, fmt.Sprintf("%s=%s", k, filters[k]))
		}
	}

	// If all filters are empty, return "all" key
	if len(filterParts) == 0 {
		return Key(prefix, resource, "list", "all")
	}

	// Hash the filter string for a compact key
	filterStr := strings.Join(filterParts, "&")
	hash := hashString(filterStr)

	return Key(prefix, resource, "list", hash)
}

// InvalidationPattern returns a pattern for invalidating related cache keys.
// Example: InvalidationPattern(PrefixAdmin, "tenants") -> "admin:tenants:*"
func InvalidationPattern(prefix string, parts ...string) string {
	allParts := append([]string{prefix}, parts...)
	return strings.Join(allParts, ":") + ":*"
}

// TenantInvalidationPattern returns a pattern for invalidating all tenant-scoped keys.
// Example: TenantInvalidationPattern(PrefixAdmin, tenantID) -> "admin:tenant:{tenantID}:*"
func TenantInvalidationPattern(prefix string, tenantID string) string {
	return Key(prefix, "tenant", tenantID) + ":*"
}

// hashString creates a short hash of a string for cache key generation.
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8]) // First 8 bytes = 16 hex chars
}
