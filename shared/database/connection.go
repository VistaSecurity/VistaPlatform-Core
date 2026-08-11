// Package database provides shared database connection helpers with standardized pool settings.
package database

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// PoolConfig holds connection pool settings. Zero values mean "use default".
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// DefaultPoolConfig returns the standard pool settings used across all services.
// For environment-configurable pool sizes, use DefaultPoolConfigFromEnv() instead.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	}
}

// DefaultPoolConfigFromEnv returns pool settings sourced from environment variables,
// falling back to hardcoded defaults if unset. This allows per-environment tuning
// (e.g., lower MaxOpenConns behind RDS Proxy, higher in direct-connect scenarios).
//
// Environment variables:
//
//	DB_MAX_OPEN_CONNS    - max open connections (default 25)
//	DB_MAX_IDLE_CONNS    - max idle connections (default 5)
//	DB_CONN_MAX_LIFETIME - connection max lifetime in seconds (default 300)
//	DB_CONN_MAX_IDLE_TIME - connection max idle time in seconds (default 60)
func DefaultPoolConfigFromEnv() PoolConfig {
	cfg := DefaultPoolConfig()

	if v := os.Getenv("DB_MAX_OPEN_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxOpenConns = n
		}
	}
	if v := os.Getenv("DB_MAX_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxIdleConns = n
		}
	}
	if v := os.Getenv("DB_CONN_MAX_LIFETIME"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ConnMaxLifetime = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("DB_CONN_MAX_IDLE_TIME"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ConnMaxIdleTime = time.Duration(n) * time.Second
		}
	}

	return cfg
}

// Connect opens a PostgreSQL connection with the environment-configurable pool
// config and pings. Pool sizes can be tuned via DB_MAX_OPEN_CONNS, DB_MAX_IDLE_CONNS,
// DB_CONN_MAX_LIFETIME, and DB_CONN_MAX_IDLE_TIME environment variables.
func Connect(databaseURL string) (*sql.DB, error) {
	return ConnectWithPool(databaseURL, DefaultPoolConfigFromEnv())
}

// ConnectReadOnly opens a read-only PostgreSQL connection (e.g., to an RDS read
// replica). Falls back to the primary DATABASE_URL if DATABASE_READ_URL is unset.
// Pool sizing follows the same DB_* environment variables as Connect; explicit
// caps (e.g., for RDS Proxy) are never overridden.
func ConnectReadOnly() (*sql.DB, error) {
	url := os.Getenv("DATABASE_READ_URL")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		return nil, fmt.Errorf("neither DATABASE_READ_URL nor DATABASE_URL is set")
	}
	return ConnectWithPool(url, DefaultPoolConfigFromEnv())
}

// ConnectBypass opens the connection used for deliberately cross-tenant DB work
// — the paths annotated `// RLS: cross-tenant — runs on the bypass role`
// (platform-admin aggregates, background sweeps, and auth/bootstrap lookups
// where the tenant is the query's OUTPUT). It reads BYPASS_DATABASE_URL, which
// in an enforcing deployment points at the BYPASSRLS `crypto_bypass` role.
//
// It falls back to DATABASE_URL when BYPASS_DATABASE_URL is unset, so a
// deployment that has not yet flipped to the role split is unchanged: both
// handles resolve to the same (owner) connection and nothing behaves
// differently. After the flip, DATABASE_URL → crypto_app (NOBYPASSRLS, subject
// to RLS) and BYPASS_DATABASE_URL → crypto_bypass (BYPASSRLS). Keeping these two
// pools separate is what guarantees crypto_app can never escalate to bypass —
// only code that explicitly uses this handle reaches the bypass role.
func ConnectBypass() (*sql.DB, error) {
	url := os.Getenv("BYPASS_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		return nil, fmt.Errorf("neither BYPASS_DATABASE_URL nor DATABASE_URL is set")
	}
	return ConnectWithPool(url, DefaultPoolConfigFromEnv())
}

// ConnectWithPool opens a PostgreSQL connection with a custom pool config and pings.
func ConnectWithPool(databaseURL string, pool PoolConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if pool.MaxOpenConns > 0 {
		db.SetMaxOpenConns(pool.MaxOpenConns)
	}
	if pool.MaxIdleConns > 0 {
		db.SetMaxIdleConns(pool.MaxIdleConns)
	}
	if pool.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(pool.ConnMaxLifetime)
	}
	if pool.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(pool.ConnMaxIdleTime)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return db, nil
}
