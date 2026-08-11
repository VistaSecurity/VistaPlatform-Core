package database

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type DB struct {
	*sqlx.DB
}

func NewConnection(cfg *config.Config) (*DB, error) {
	var dsn string

	// Use DATABASE_URL if available, otherwise construct from individual components
	if cfg.DatabaseURL != "" {
		dsn = cfg.DatabaseURL
		fmt.Printf("Using DATABASE_URL: %s\n", dsn)
	} else {
		dsn = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			cfg.Database.Host,
			cfg.Database.Port,
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Name,
			cfg.Database.SSLMode,
		)
		fmt.Printf("Using individual config: %s\n", dsn)
	}

	fmt.Printf("Final DSN: %s\n", dsn)
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	pool := shareddb.DefaultPoolConfigFromEnv()
	db.SetMaxOpenConns(pool.MaxOpenConns)
	db.SetMaxIdleConns(pool.MaxIdleConns)
	db.SetConnMaxLifetime(pool.ConnMaxLifetime)
	db.SetConnMaxIdleTime(pool.ConnMaxIdleTime)

	return &DB{db}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

func (db *DB) Health() error {
	return db.Ping()
}
