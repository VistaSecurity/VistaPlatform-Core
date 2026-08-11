package database

import (
	"database/sql"

	_ "github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// NewConnection opens a PostgreSQL connection using environment-configurable
// pool settings from shared/database (DB_MAX_OPEN_CONNS, DB_MAX_IDLE_CONNS, etc.).
func NewConnection(databaseURL string) (*sql.DB, error) {
	return shareddatabase.ConnectWithPool(databaseURL, shareddatabase.DefaultPoolConfigFromEnv())
}
