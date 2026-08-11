package database

import (
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

type DB struct {
	*sqlx.DB
}

// SQLDB returns the underlying database/sql.DB. Used by adapters that were
// written against database/sql rather than sqlx — notably the shared/storage
// config + integration providers consumed by cbom-service Phase 2.
func (db *DB) SQLDB() *sql.DB {
	return db.DB.DB
}

func NewConnection(cfg *config.Config) (*DB, error) {
	var dsn string

	// Use DATABASE_URL if available, otherwise construct from individual components
	if cfg.DatabaseURL != "" {
		dsn = cfg.DatabaseURL
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
	}

	sqlDB, err := shareddatabase.Connect(dsn)
	if err != nil {
		return nil, err
	}

	return &DB{sqlx.NewDb(sqlDB, "postgres")}, nil
}

func (db *DB) Close() error {
	return db.DB.Close()
}

func (db *DB) Health() error {
	return db.Ping()
}
