package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps a Redis client with caching-specific methods.
type Client struct {
	redis  *redis.Client
	config TTLConfig
}

// Options configures the cache client.
type Options struct {
	// RedisURL is the connection string for Redis.
	// Format: redis://[:password@]host:port[/database]
	RedisURL string

	// PoolSize is the maximum number of connections in the pool.
	// Default: 10
	PoolSize int

	// MinIdleConns is the minimum number of idle connections.
	// Default: 2
	MinIdleConns int

	// MaxRetries is the maximum number of retries before giving up.
	// Default: 3
	MaxRetries int

	// TTLConfig allows customizing TTL values.
	// If nil, defaults are used.
	TTLConfig *TTLConfig
}

// DefaultOptions returns sensible default options. Pool sizes can be overridden via
// REDIS_POOL_SIZE and REDIS_MIN_IDLE_CONNS environment variables for per-environment tuning.
func DefaultOptions() Options {
	poolSize := 25
	if v := os.Getenv("REDIS_POOL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			poolSize = n
		}
	}
	minIdle := 5
	if v := os.Getenv("REDIS_MIN_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			minIdle = n
		}
	}
	return Options{
		PoolSize:     poolSize,
		MinIdleConns: minIdle,
		MaxRetries:   3,
	}
}

// NewClient creates a new cache client with the given options.
func NewClient(opts Options) (*Client, error) {
	if opts.RedisURL == "" {
		return nil, fmt.Errorf("redis URL is required")
	}

	// Apply defaults (match DefaultOptions values)
	if opts.PoolSize == 0 {
		opts.PoolSize = 25
	}
	if opts.MinIdleConns == 0 {
		opts.MinIdleConns = 5
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 3
	}

	// Parse Redis URL using redis.ParseURL which correctly handles both
	// redis:// (plain) and rediss:// (TLS) schemes.
	redisOpts, err := redis.ParseURL(opts.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Overlay pooling options
	redisOpts.PoolSize = opts.PoolSize
	redisOpts.MinIdleConns = opts.MinIdleConns
	redisOpts.MaxRetries = opts.MaxRetries

	// Create Redis client with pooling
	redisClient := redis.NewClient(redisOpts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Use custom TTL config or defaults
	ttlConfig := DefaultTTLConfig()
	if opts.TTLConfig != nil {
		ttlConfig = *opts.TTLConfig
	}

	return &Client{
		redis:  redisClient,
		config: ttlConfig,
	}, nil
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	return c.redis.Close()
}

// Health checks if Redis is healthy.
func (c *Client) Health(ctx context.Context) error {
	return c.redis.Ping(ctx).Err()
}

// Redis returns the underlying Redis client for advanced operations.
func (c *Client) Redis() *redis.Client {
	return c.redis
}

// Config returns the TTL configuration.
func (c *Client) Config() TTLConfig {
	return c.config
}

// Get retrieves a cached value and unmarshals it into the target.
// Returns redis.Nil error if key doesn't exist.
func (c *Client) Get(ctx context.Context, key string, target interface{}) error {
	data, err := c.redis.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}

	return json.Unmarshal(data, target)
}

// GetString retrieves a cached string value.
// Returns redis.Nil error if key doesn't exist.
func (c *Client) GetString(ctx context.Context, key string) (string, error) {
	return c.redis.Get(ctx, key).Result()
}

// Set caches a value with the given TTL.
// The value is marshaled to JSON before storing.
func (c *Client) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.redis.Set(ctx, key, data, ttl).Err()
}

// SetString caches a string value with the given TTL.
func (c *Client) SetString(ctx context.Context, key string, value string, ttl time.Duration) error {
	return c.redis.Set(ctx, key, value, ttl).Err()
}

// Delete removes a key from the cache.
func (c *Client) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.redis.Del(ctx, keys...).Err()
}

// DeletePattern removes all keys matching a pattern.
// Use with caution as SCAN can be slow on large datasets.
func (c *Client) DeletePattern(ctx context.Context, pattern string) error {
	var cursor uint64
	var deleted int64

	for {
		keys, nextCursor, err := c.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan keys: %w", err)
		}

		if len(keys) > 0 {
			count, err := c.redis.Del(ctx, keys...).Result()
			if err != nil {
				return fmt.Errorf("failed to delete keys: %w", err)
			}
			deleted += count
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return nil
}

// Exists checks if a key exists in the cache.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	count, err := c.redis.Exists(ctx, key).Result()
	return count > 0, err
}

// TTL returns the remaining TTL for a key.
// Returns -2 if key doesn't exist, -1 if key has no TTL.
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.redis.TTL(ctx, key).Result()
}

// SetNX sets a value only if the key doesn't exist (for distributed locking).
// Returns true if the key was set, false if it already existed.
func (c *Client) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.redis.SetNX(ctx, key, data, ttl).Result()
}

// GetOrSet tries to get a cached value; if not found, calls the loader function,
// caches the result, and returns it. This is a common caching pattern.
func (c *Client) GetOrSet(ctx context.Context, key string, target interface{}, ttl time.Duration, loader func() (interface{}, error)) error {
	// Try to get from cache first
	err := c.Get(ctx, key, target)
	if err == nil {
		return nil // Cache hit
	}

	// Any Get failure — a real cache error as much as redis.Nil — falls through
	// to the loader. This is a deliberate "fail open": an unreachable cache
	// must degrade to a slower answer, never to no answer.

	// Cache miss - call loader
	value, err := loader()
	if err != nil {
		return fmt.Errorf("loader failed: %w", err)
	}

	// Cache the result (ignore cache errors - fail open)
	_ = c.Set(ctx, key, value, ttl)

	// Copy value to target
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal loaded value: %w", err)
	}

	return json.Unmarshal(data, target)
}

// Increment atomically increments a counter and returns the new value.
func (c *Client) Increment(ctx context.Context, key string) (int64, error) {
	return c.redis.Incr(ctx, key).Result()
}

// IncrementWithTTL atomically increments a counter and sets TTL if it's a new key.
// Returns the new value.
func (c *Client) IncrementWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	pipe := c.redis.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}
