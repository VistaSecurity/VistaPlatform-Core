package cache

import (
	"context"
	"os"
	"testing"
	"time"
)

// getTestRedisURL returns the Redis URL for testing.
// Uses REDIS_TEST_URL env var or defaults to local Redis.
func getTestRedisURL() string {
	if url := os.Getenv("REDIS_TEST_URL"); url != "" {
		return url
	}
	return "redis://localhost:6379/15" // Use DB 15 for tests
}

// skipIfNoRedis skips the test if Redis is not available.
func skipIfNoRedis(t *testing.T) *Client {
	t.Helper()

	client, err := NewClient(Options{
		RedisURL: getTestRedisURL(),
	})
	if err != nil {
		t.Skipf("Redis not available: %v", err)
		return nil
	}

	// Clean up test database
	t.Cleanup(func() {
		ctx := context.Background()
		client.Redis().FlushDB(ctx)
		client.Close()
	})

	return client
}

func TestNewClient(t *testing.T) {
	t.Run("missing URL returns error", func(t *testing.T) {
		_, err := NewClient(Options{})
		if err == nil {
			t.Error("expected error for missing URL")
		}
	})

	t.Run("invalid URL returns error", func(t *testing.T) {
		_, err := NewClient(Options{
			RedisURL: "://invalid",
		})
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.PoolSize != 25 {
		t.Errorf("PoolSize = %d, want 25", opts.PoolSize)
	}
	if opts.MinIdleConns != 5 {
		t.Errorf("MinIdleConns = %d, want 5", opts.MinIdleConns)
	}
	if opts.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", opts.MaxRetries)
	}
}

func TestClient_SetGet(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()

	type testData struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	t.Run("set and get struct", func(t *testing.T) {
		key := "test:struct"
		data := testData{Name: "test", Value: 42}

		err := client.Set(ctx, key, data, TTLShort)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		var result testData
		err = client.Get(ctx, key, &result)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}

		if result.Name != data.Name || result.Value != data.Value {
			t.Errorf("Get returned %+v, want %+v", result, data)
		}
	})

	t.Run("set and get string", func(t *testing.T) {
		key := "test:string"
		value := "hello world"

		err := client.SetString(ctx, key, value, TTLShort)
		if err != nil {
			t.Fatalf("SetString failed: %v", err)
		}

		result, err := client.GetString(ctx, key)
		if err != nil {
			t.Fatalf("GetString failed: %v", err)
		}

		if result != value {
			t.Errorf("GetString returned %q, want %q", result, value)
		}
	})

	t.Run("get non-existent key", func(t *testing.T) {
		var result testData
		err := client.Get(ctx, "nonexistent:key", &result)
		if err == nil {
			t.Error("expected error for non-existent key")
		}
	})
}

func TestClient_Delete(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()

	t.Run("delete single key", func(t *testing.T) {
		key := "test:delete"
		_ = client.SetString(ctx, key, "value", TTLShort)

		err := client.Delete(ctx, key)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		exists, _ := client.Exists(ctx, key)
		if exists {
			t.Error("key should not exist after delete")
		}
	})

	t.Run("delete multiple keys", func(t *testing.T) {
		keys := []string{"test:delete1", "test:delete2", "test:delete3"}
		for _, key := range keys {
			_ = client.SetString(ctx, key, "value", TTLShort)
		}

		err := client.Delete(ctx, keys...)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		for _, key := range keys {
			exists, _ := client.Exists(ctx, key)
			if exists {
				t.Errorf("key %s should not exist after delete", key)
			}
		}
	})
}

func TestClient_DeletePattern(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()

	// Set up test keys
	testKeys := []string{
		"pattern:test:1",
		"pattern:test:2",
		"pattern:test:3",
		"pattern:other:1",
	}

	for _, key := range testKeys {
		_ = client.SetString(ctx, key, "value", TTLShort)
	}

	// Delete keys matching pattern
	err := client.DeletePattern(ctx, "pattern:test:*")
	if err != nil {
		t.Fatalf("DeletePattern failed: %v", err)
	}

	// Check test keys are deleted
	for _, key := range testKeys[:3] {
		exists, _ := client.Exists(ctx, key)
		if exists {
			t.Errorf("key %s should not exist after pattern delete", key)
		}
	}

	// Check other key still exists
	exists, _ := client.Exists(ctx, "pattern:other:1")
	if !exists {
		t.Error("pattern:other:1 should still exist")
	}
}

func TestClient_Exists(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()

	key := "test:exists"
	_ = client.SetString(ctx, key, "value", TTLShort)

	exists, err := client.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("key should exist")
	}

	exists, err = client.Exists(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("nonexistent key should not exist")
	}
}

func TestClient_TTL(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()

	key := "test:ttl"
	_ = client.SetString(ctx, key, "value", 10*time.Second)

	ttl, err := client.TTL(ctx, key)
	if err != nil {
		t.Fatalf("TTL failed: %v", err)
	}

	// TTL should be between 0 and 10 seconds
	if ttl < 0 || ttl > 10*time.Second {
		t.Errorf("TTL = %v, expected between 0 and 10s", ttl)
	}
}

func TestClient_SetNX(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()
	key := "test:setnx"

	// First SetNX should succeed
	set, err := client.SetNX(ctx, key, "value1", TTLShort)
	if err != nil {
		t.Fatalf("SetNX failed: %v", err)
	}
	if !set {
		t.Error("first SetNX should return true")
	}

	// Second SetNX should fail (key exists)
	set, err = client.SetNX(ctx, key, "value2", TTLShort)
	if err != nil {
		t.Fatalf("SetNX failed: %v", err)
	}
	if set {
		t.Error("second SetNX should return false")
	}
}

func TestClient_GetOrSet(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()
	key := "test:getorset"
	callCount := 0

	type testData struct {
		Value int `json:"value"`
	}

	loader := func() (interface{}, error) {
		callCount++
		return testData{Value: 42}, nil
	}

	// First call should invoke loader
	var result1 testData
	err := client.GetOrSet(ctx, key, &result1, TTLShort, loader)
	if err != nil {
		t.Fatalf("GetOrSet failed: %v", err)
	}
	if result1.Value != 42 {
		t.Errorf("GetOrSet returned %+v, want {Value: 42}", result1)
	}
	if callCount != 1 {
		t.Errorf("loader called %d times, want 1", callCount)
	}

	// Second call should return cached value without calling loader
	var result2 testData
	err = client.GetOrSet(ctx, key, &result2, TTLShort, loader)
	if err != nil {
		t.Fatalf("GetOrSet failed: %v", err)
	}
	if result2.Value != 42 {
		t.Errorf("GetOrSet returned %+v, want {Value: 42}", result2)
	}
	if callCount != 1 {
		t.Errorf("loader called %d times, want 1 (should be cached)", callCount)
	}
}

func TestClient_Increment(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()
	key := "test:increment"

	val1, err := client.Increment(ctx, key)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val1 != 1 {
		t.Errorf("first Increment = %d, want 1", val1)
	}

	val2, err := client.Increment(ctx, key)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val2 != 2 {
		t.Errorf("second Increment = %d, want 2", val2)
	}
}

func TestClient_IncrementWithTTL(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()
	key := "test:increment-ttl"

	val, err := client.IncrementWithTTL(ctx, key, 10*time.Second)
	if err != nil {
		t.Fatalf("IncrementWithTTL failed: %v", err)
	}
	if val != 1 {
		t.Errorf("IncrementWithTTL = %d, want 1", val)
	}

	ttl, _ := client.TTL(ctx, key)
	if ttl < 0 || ttl > 10*time.Second {
		t.Errorf("TTL = %v, expected between 0 and 10s", ttl)
	}
}

func TestClient_Health(t *testing.T) {
	client := skipIfNoRedis(t)
	if client == nil {
		return
	}

	ctx := context.Background()

	err := client.Health(ctx)
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}
}
