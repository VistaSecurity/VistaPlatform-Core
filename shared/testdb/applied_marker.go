package testdb

// The applied-marker cache: schema.sql and seed.sql are applied ONCE per
// database, not once per test.
//
// Every one of the ~200 ApplySchemaAndSeed call sites in this repo used to
// re-apply the WHOLE of schema.sql and seed.sql, per test, per package binary.
// That is what made the parallel integration runner flaky rather than merely
// slow: an apply takes ACCESS EXCLUSIVE across every table in file order while
// ordinary tests in other binaries hold ACCESS SHARE on a subset in query order,
// and Postgres resolves the cycle by killing one side — `40P01 deadlock detected`
// reported against a test that has nothing to do with schemas (the
// nightly test-backend failures of and. seed.sql's
// tenant-scoped inserts have the mirror-image problem: `asset_lifecycle_policies`
// selects FROM tenants, and a concurrent NewTenant cleanup cascading its
// throwaway tenant away fails the FK check, which exhausted the retries and
// failed whole packages at setup.
//
// Both the local runner (scripts/run-integration-db-tests.sh) and the nightly
// test-backend job apply both files with psql BEFORE any test binary starts, and
// both then record the marker — so every per-binary re-apply was pure cost and
// pure risk. This cache makes them no-ops.
//
// The marker is read and written while holding the SAME exclusive advisory lock
// (schemaLockKey) the apply takes, which is what makes it a decision rather than
// a guess: two binaries that arrive together cannot both read "not applied" and
// both apply — the second reads the first's row.
//
// Failing to create, read or write the marker is never fatal. The fallback is to
// apply, which is exactly the old behaviour.
//
// A test whose subject IS the re-apply calls ForceApplySchema / ForceApplySeed
// and still applies every time. Those are the only appliers left on a shared
// database, and there are five of them.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
)

// appliedMarkerTable keeps the bookkeeping OUT of `public` and `audit`: the grant
// and RLS guards in shared/database enumerate every relation in those two schemas
// and assert a property of each, so a harness table there would read as a schema
// defect.
//
// `public.schema_migration_status` — which the chart's schema-migration Job
// writes for exactly this purpose in a real deployment — is deliberately NOT
// reused. It is created by that Job and never by schema.sql, so it does not exist
// in a test database at all, and borrowing it would have a test harness writing
// rows a real upgrade reads.
const appliedMarkerTable = "testdb_meta.applied_sql"

// AppliedMarkerDDL creates the marker table. Exported because the local runner
// and the nightly workflow record their own pre-apply through psql and must
// create the identical shape. If the two ever disagree about the shape or the
// key, nothing breaks — the harness just applies again.
const AppliedMarkerDDL = `CREATE SCHEMA IF NOT EXISTS testdb_meta;
CREATE TABLE IF NOT EXISTS testdb_meta.applied_sql (
	path        text PRIMARY KEY,
	content_sha text NOT NULL,
	applied_at  timestamptz NOT NULL DEFAULT now())`

// sqlFile is a named SQL body to apply. The name is the marker key; for the
// repo's own files it is the repo-relative path, which is the spelling the shell
// pre-appliers record too.
type sqlFile struct {
	name string
	body string
}

// grantMarkerPrefix namespaces the marker rows that stand for "these role/grant
// statements have already been re-asserted against this database" (see
// execUnderSchemaLockOnce). They live in the same table so there is one place to
// look, and one place to clear.
const grantMarkerPrefix = "testdb:grants:"

func ensureAppliedMarker(ctx context.Context, conn *sql.Conn) bool {
	_, err := conn.ExecContext(ctx, AppliedMarkerDDL)
	return err == nil
}

func alreadyApplied(ctx context.Context, conn *sql.Conn, f sqlFile) bool {
	var got string
	err := conn.QueryRowContext(ctx,
		`SELECT content_sha FROM `+appliedMarkerTable+` WHERE path = $1`, f.name).Scan(&got)
	return err == nil && got == contentSHA(f.body)
}

func recordApplied(ctx context.Context, conn *sql.Conn, f sqlFile) {
	_, _ = conn.ExecContext(ctx,
		`INSERT INTO `+appliedMarkerTable+` (path, content_sha) VALUES ($1, $2)
		 ON CONFLICT (path) DO UPDATE SET content_sha = EXCLUDED.content_sha, applied_at = now()`,
		f.name, contentSHA(f.body))
}

// invalidateGrantMarkers drops the role/grant markers after a forced apply: the
// file that just ran rewrites the same ACLs, so the next helper that wants them
// asserted should assert them rather than trust a stale marker.
func invalidateGrantMarkers(ctx context.Context, conn *sql.Conn) {
	_, _ = conn.ExecContext(ctx,
		`DELETE FROM `+appliedMarkerTable+` WHERE path LIKE $1`, grantMarkerPrefix+"%")
}

func contentSHA(body string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(body))) }
