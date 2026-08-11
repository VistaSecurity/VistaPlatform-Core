package database

import (
	"github.com/jmoiron/sqlx"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// Connect establishes a connection to PostgreSQL using the shared pool config
// (25 open, 5 idle, 5m lifetime, 1m idle time) and pings before returning.
func Connect(databaseURL string) (*sqlx.DB, error) {
	sqlDB, err := shareddatabase.Connect(databaseURL)
	if err != nil {
		return nil, err
	}
	return sqlx.NewDb(sqlDB, "postgres"), nil
}
