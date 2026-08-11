package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/redis/go-redis/v9"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// Connect establishes a connection to PostgreSQL using environment-configurable
// pool settings from shared/database (DB_MAX_OPEN_CONNS, DB_MAX_IDLE_CONNS, etc.).
func Connect(databaseURL string) (*sql.DB, error) {
	return shareddatabase.ConnectWithPool(databaseURL, shareddatabase.DefaultPoolConfigFromEnv())
}

// ConnectRedis establishes a connection to Redis.
// Supports redis:// (plain) and rediss:// (TLS) schemes via redis.ParseURL,
// which correctly configures TLS when the rediss:// scheme is used.
func ConnectRedis(redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}
	return redis.NewClient(opts), nil
}
