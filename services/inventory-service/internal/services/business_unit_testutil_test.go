package services

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

// seedBusinessUnit inserts a business unit straight into the table (fixtures run
// as the table owner, no RLS context) and returns its id. The slug is the
// lowercased name, which is what the facet bucket key becomes.
func seedBusinessUnit(t *testing.T, db interface {
	QueryRow(query string, args ...any) *sql.Row
}, tenant uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1, $2, lower($2)) RETURNING id`, tenant, name).Scan(&id); err != nil {
		t.Fatalf("seed business unit %s: %v", name, err)
	}
	return id
}
