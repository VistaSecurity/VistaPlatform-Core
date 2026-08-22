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
	var source string
	if cfg.DatabaseURL != "" {
		dsn = cfg.DatabaseURL
		source = "DATABASE_URL"
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
		source = "individual config"
	}

	// The DSN carries the database password in both spellings, so it is logged
	// only through redactDSN. This line previously printed the DSN verbatim
	// (three times), putting the credential into stdout — and therefore into
	// container logs and any log aggregator downstream of them.
	fmt.Printf("Connecting to database (%s): %s\n", source, redactDSN(dsn))

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
