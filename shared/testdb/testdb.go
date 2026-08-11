// Package testdb is the shared harness for database-integration tests across
// services — tests that exercise real SQL/transactions/triggers against a live
// Postgres, which mock- or pure-logic unit tests cannot reach.
//
// Tests using it run ONLY when TEST_DATABASE_URL points at a schema-loaded
// Postgres; otherwise they skip, so a plain `go test ./...` and the PR gate
// (which provisions no database) stay green. CI runs them in the nightly
// backend-test job (it already stands up Postgres and applies the schema +
// seed); locally, run `make test-integration-db`, which spins up an ephemeral
// Postgres in Docker and sets the variable for you.
//
// The helper returns a *sql.DB (no sqlx dependency in shared); callers that
// need sqlx wrap it with sqlx.NewDb(db, "postgres").
package testdb

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // registers the "postgres" driver
)

// URLEnv names the environment variable that points at the integration database.
const URLEnv = "TEST_DATABASE_URL"

// Connect opens the integration test database named by TEST_DATABASE_URL, or skips
// the test when the variable is unset. The connection is closed at test end.
func Connect(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv(URLEnv)
	if url == "" {
		t.Skipf("%s not set — skipping DB integration test (run `make test-integration-db`)", URLEnv)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("testdb: open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("testdb: ping %s: %v", url, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// schemaLockKey serializes cross-process schema/grant application. `go test
// ./...` runs package test binaries in parallel; when two of them apply
// schema.sql (or re-assert role grants) against the same database at the same
// time, Postgres fails with "tuple concurrently updated" on the concurrent
// GRANT / ALTER DEFAULT PRIVILEGES / ALTER ROLE statements. Every helper that
// applies schema or grants takes this advisory lock first. Arbitrary but
// stable value (where the race first bit nightly).
const schemaLockKey = 889

// withSchemaLock runs fn on a dedicated connection that holds the
// schemaLockKey Postgres advisory lock. The lock is session-scoped, so even if
// the explicit unlock is skipped (test Fatalf inside fn), closing the
// connection releases it.
func withSchemaLock(t *testing.T, db *sql.DB, fn func(ctx context.Context, conn *sql.Conn)) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("testdb: acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaLockKey); err != nil {
		t.Fatalf("testdb: pg_advisory_lock: %v", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, schemaLockKey) }()
	fn(ctx, conn)
}

// RepoRoot walks up from the test's working directory to the directory
// containing go.work — the repository root, where scripts/database/ lives.
func RepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("testdb: getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("testdb: RepoRoot walked off the top without finding go.work")
		}
		dir = parent
	}
}

// ApplySchemaAndSeed primes the integration database with
// scripts/database/schema.sql and seed.sql from the repo root. Idempotent
// (both files are idempotent per the CLAUDE.md schema invariants) and safe
// under `go test ./...` package parallelism — see schemaLockKey. All packages
// that need a schema-loaded database should call this instead of applying the
// files themselves.
func ApplySchemaAndSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	root := RepoRoot(t)
	withSchemaLock(t, db, func(ctx context.Context, conn *sql.Conn) {
		for _, p := range []string{"scripts/database/schema.sql", "scripts/database/seed.sql"} {
			b, err := os.ReadFile(filepath.Join(root, p))
			if err != nil {
				t.Fatalf("testdb: read %s: %v", p, err)
			}
			// Retry transient races only. The advisory lock serializes
			// appliers against each other, but not against ordinary tests in
			// other binaries: e.g. seed.sql's asset_lifecycle_policies INSERT
			// selects FROM tenants, and a concurrent test-cleanup DELETE of
			// its throwaway tenant committing mid-statement fails the FK
			// check. A fresh attempt takes a new snapshot. Real schema/seed
			// bugs are deterministic and still fail after the retries.
			const attempts = 3
			for i := 1; ; i++ {
				_, err = conn.ExecContext(ctx, string(b))
				if err == nil {
					break
				}
				msg := err.Error()
				transient := strings.Contains(msg, "violates foreign key constraint") ||
					strings.Contains(msg, "deadlock detected") ||
					strings.Contains(msg, "tuple concurrently updated")
				if !transient || i == attempts {
					t.Fatalf("testdb: apply %s (attempt %d/%d): %v", p, i, attempts, err)
				}
				t.Logf("testdb: apply %s hit transient race (attempt %d/%d), retrying: %v", p, i, attempts, err)
				time.Sleep(200 * time.Millisecond)
			}
		}
	})
}

// NewTenant inserts a throwaway tenant and registers cleanup that CASCADE-deletes it
// — and, via the tenant_id foreign keys, everything created under it (e.g.
// compliance_findings, and through them finding history) — so each test is isolated
// and leaves no residue. Returns the new tenant id.
func NewTenant(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "it-" + id.String()[:8] // satisfies the tenants.slug ^[a-z0-9-]+$ check
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, id, "IT "+slug, slug); err != nil {
		t.Fatalf("testdb: seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id) })
	return id
}
