package testdb

import (
	"database/sql"
	"testing"
)

// RowQuerier is the slice of *sql.DB, *sqlx.DB and a transaction the site
// helpers need.
type RowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// EnsureSite returns the id of the tenant's site called name, creating it
// when the tenant has none (DCIM row 2.1: an asset's site is a row, not
// text). An empty name returns nil, so a test table's "no site" column passes
// straight through as a NULL site_id. tenant is a uuid.UUID or its string.
func EnsureSite(t testing.TB, q RowQuerier, tenant any, name string) any {
	t.Helper()
	if name == "" {
		return nil
	}
	var id string
	if err := q.QueryRow(`
		WITH ins AS (
			INSERT INTO sites (tenant_id, name, slug)
			VALUES ($1::uuid, $2::text, trim(both '-' from regexp_replace(lower($2::text), '[^a-z0-9]+', '-', 'g')) || '-' || substr(md5($2::text), 1, 6))
			ON CONFLICT DO NOTHING RETURNING id)
		SELECT id::text FROM ins
		UNION ALL SELECT id::text FROM sites WHERE tenant_id = $1::uuid AND lower(name) = lower($2::text)
		LIMIT 1`, tenant, name).Scan(&id); err != nil {
		t.Fatalf("testdb: ensure site %q: %v", name, err)
	}
	return id
}

// SiteNameSQL is the SELECT-list expression for an asset row's site name
// (empty when it has none), for tests that assert on placement. It reads the
// row as `assets` (unaliased).
const SiteNameSQL = `coalesce((SELECT st.name FROM sites st WHERE st.id = assets.site_id), '')`
