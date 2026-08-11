package database

import (
	"database/sql"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// Connect establishes a connection to PostgreSQL using the shared pool config
// (25 open, 5 idle, 5m lifetime, 1m idle time) and pings before returning.
func Connect(databaseURL string) (*sql.DB, error) {
	return shareddatabase.Connect(databaseURL)
}
