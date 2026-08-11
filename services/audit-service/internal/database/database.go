package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

type DB struct {
	*sql.DB
}

func NewConnection(cfg *config.Config) (*DB, error) {
	var dbURL string

	// Use DatabaseURL if provided
	if cfg.DatabaseURL != "" {
		dbURL = cfg.DatabaseURL
	} else {
		// Construct from individual fields
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Host,
			cfg.Database.Port,
			cfg.Database.Name,
			cfg.Database.SSLMode,
		)
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	pool := shareddb.DefaultPoolConfigFromEnv()
	db.SetMaxOpenConns(pool.MaxOpenConns)
	db.SetMaxIdleConns(pool.MaxIdleConns)
	db.SetConnMaxLifetime(pool.ConnMaxLifetime)
	db.SetConnMaxIdleTime(pool.ConnMaxIdleTime)

	return &DB{DB: db}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

func (db *DB) Ping() error {
	return db.DB.Ping()
}
