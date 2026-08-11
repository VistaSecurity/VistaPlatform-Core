package database

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
)

type DB struct {
	*sqlx.DB
}

func NewConnection(cfg *config.Config) (*DB, error) {
	dsn := cfg.DatabaseURL
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(cfg.MaxDBConnections)
	db.SetMaxIdleConns(cfg.MaxDBConnections / 2)

	return &DB{db}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}
