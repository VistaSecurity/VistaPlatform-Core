// Package handlers provides HTTP handlers for the admin service.
//
// This file is the Redis handler cache. After the MSP carve it is purely the
// cache JANITOR: the invalidation call plus the decorator that mutation
// handlers wrap themselves in. Its cached READ handlers (tenant list, platform
// stats, per-tenant stats rollup) all aggregated across every tenant, so they
// moved to ee/msp/cached_tenant_handlers.go.
//
// What stays here does so because ee/billingapi also wraps its tenant-billing
// PUT in WrapWithCacheInvalidation, so the decorator has to be reachable from
// both Enterprise packages, and Core owns the type either way.
package handlers

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/cache"
)

// CachedHandlers wraps handlers with Redis caching support.
type CachedHandlers struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS connection (crypto_bypass) used by the
	// platform-wide cross-tenant paths annotated below (Phase 4).
	bypassDB *sql.DB
	cache    *cache.Client
}

// NewCachedHandlers creates a new CachedHandlers instance.
// bypassDB is the cross-tenant (BYPASSRLS) handle for platform-wide stats/directory.
func NewCachedHandlers(db, bypassDB *sql.DB, cacheClient *cache.Client) *CachedHandlers {
	return &CachedHandlers{
		db:       db,
		bypassDB: bypassDB,
		cache:    cacheClient,
	}
}

// InvalidateTenantCache invalidates all tenant-related cache entries.
// Call this after any tenant mutation (create, update, delete, suspend, activate).
func (h *CachedHandlers) InvalidateTenantCache(ctx context.Context) error {
	// Invalidate all tenant lists
	if err := h.cache.DeletePattern(ctx, cache.InvalidationPattern(cache.PrefixAdmin, "tenants")); err != nil {
		log.Printf("[ADMIN] Warning: Failed to invalidate tenant list cache: %v", err)
	}

	// Invalidate tenant stats
	_ = h.cache.Delete(ctx, cache.Key(cache.PrefixAdmin, "stats", "tenants"))
	_ = h.cache.Delete(ctx, cache.Key(cache.PrefixAdmin, "stats", "platform"))

	return nil
}

// WrapWithCacheInvalidation wraps a handler function to invalidate tenant cache after successful execution.
// Use this to wrap mutation handlers (create, update, delete, suspend, activate).
func (h *CachedHandlers) WrapWithCacheInvalidation(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Execute the original handler
		handler(c)

		// If the response was successful (2xx), invalidate the cache
		if c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = h.InvalidateTenantCache(ctx)
		}
	}
}
