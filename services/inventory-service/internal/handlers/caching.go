// Package handlers provides HTTP handlers for the inventory service.
// This file provides caching utilities for high-traffic endpoints.
package handlers

import (
	"log"

	"github.com/vistasecurity/vistaplatform/shared/cache"
)

// CacheManager manages caching for inventory service endpoints.
type CacheManager struct {
	client *cache.Client
}

// NewCacheManager creates a new cache manager.
// Returns nil if redisURL is empty or connection fails.
func NewCacheManager(redisURL string) *CacheManager {
	if redisURL == "" {
		return nil
	}

	client, err := cache.NewClient(cache.Options{
		RedisURL: redisURL,
	})
	if err != nil {
		log.Printf("Warning: Failed to connect to Redis cache: %v (caching disabled)", err)
		return nil
	}

	log.Printf("Redis cache initialized for inventory-service")
	return &CacheManager{client: client}
}

// Client returns the underlying cache client.
func (m *CacheManager) Client() *cache.Client {
	if m == nil {
		return nil
	}
	return m.client
}

// Close closes the cache connection.
func (m *CacheManager) Close() error {
	if m == nil || m.client == nil {
		return nil
	}
	return m.client.Close()
}
