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
	"sync"
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

// WithSchemaShareLock runs fn while holding a SHARED advisory lock on the same
// key the schema appliers take exclusively.
//
// It is for a test in one package that writes a lot of ORDINARY rows while
// another package's binary may be applying schema.sql. The two deadlock:
// schema.sql's DDL takes locks that conflict with concurrent DML on the same
// tables, and while the applier retries (see applySQLFiles), the writer does
// not — it just fails, in a test that has nothing to do with schemas.
//
// SHARED rather than exclusive on purpose: any number of writers may hold it at
// once, so this does not serialize tests against each other. What it prevents
// is overlapping an applier, which holds the key exclusively.
//
// Use it around a BLOCK of writes, not around each statement: taking and
// releasing per row would leave the same window open between them.
func WithSchemaShareLock(t *testing.T, db *sql.DB, fn func()) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("testdb: acquire connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock_shared($1)`, schemaLockKey); err != nil {
		t.Fatalf("testdb: pg_advisory_lock_shared: %v", err)
	}
	// Session-scoped, so closing the connection releases it even if fn calls
	// t.Fatalf and never returns.
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock_shared($1)`, schemaLockKey) }()
	fn()
}

// HoldSchemaShareLock is WithSchemaShareLock for a whole test: it takes the same
// SHARED lock and holds it until the test (and its subtests) finish, releasing it
// from t.Cleanup.
//
// Same guarantee, different shape. The callback form needs the test's writes
// indented into a closure, which for an existing suite means rewriting every
// body — and a re-indentation of six tests to fix a lock is a large diff with a
// small idea in it, in which a real edit is easy to lose. This form is one line
// after the fixture:
//
//	db, tenantID := getTestDBAndTenant(t)
//	testdb.HoldSchemaShareLock(t, db.DB.DB)
//
// Call it AFTER whatever applied the schema, never before: the appliers take the
// same key EXCLUSIVELY, so a holder of the shared lock would block them for the
// rest of the test.
//
// "Whatever applied the schema" is not the whole rule — it is after ANYTHING
// that takes schemaLockKey exclusively, and ConnectAsAppRole,
// ConnectAsBypassRole and EnsureRLSAppRole all do (see rls.go's withSchemaLock).
// Getting that wrong is not a deadlock Postgres breaks: an advisory lock is
// SESSION-scoped, so the share holder sits on one connection of the pool while
// the exclusive request waits on another, forever. It cost a ten-minute package
// timeout in, which then queued every other binary's apply behind it.
//
// The lock is session-scoped on a connection this owns, so the release cannot be
// skipped by a t.Fatalf — Cleanup closes the connection either way.
func HoldSchemaShareLock(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("testdb: acquire connection: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock_shared($1)`, schemaLockKey); err != nil {
		_ = conn.Close()
		t.Fatalf("testdb: pg_advisory_lock_shared: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock_shared($1)`, schemaLockKey)
		_ = conn.Close()
	})
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

// ApplySchemaAndSeed makes sure the integration database carries
// scripts/database/schema.sql and seed.sql from the repo root.
//
// It is a NO-OP when the database already carries those exact file contents —
// which, under `make test-integration-db` and the nightly test-backend job, is
// always: both pre-apply the two files with psql before any test binary starts.
// See the applied-marker cache below for why that matters; the short version is
// that re-applying schema.sql from a test binary is what deadlocks unrelated
// tests in other binaries.
//
// Every package that needs a schema-loaded database should call this rather than
// applying the files itself: an applier that does not go through here takes no
// advisory lock and no marker, and one such applier removes the mutual exclusion
// for everybody.
func ApplySchemaAndSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	applySQLFiles(t, db, false, schemaPath, seedPath)
}

// ApplySchema makes sure scripts/database/schema.sql ONLY is in place, under the
// same advisory lock, marker cache and transient-retry as ApplySchemaAndSeed.
//
// For a test that merely needs the schema present. A test that means to RE-APPLY
// the file — the backfill-convergence and idempotency guards — wants
// [ForceApplySchema]: this one will skip.
func ApplySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	applySQLFiles(t, db, false, schemaPath)
}

// ApplySeed makes sure scripts/database/seed.sql ONLY is in place, onto a
// database whose schema is already there.
//
// As with [ApplySchema], a test that means to re-apply the seed to prove a seeded
// region reconciles wants [ForceApplySeed].
func ApplySeed(t *testing.T, db *sql.DB) {
	t.Helper()
	applySQLFiles(t, db, false, seedPath)
}

// ForceApplySchema applies scripts/database/schema.sql even when the database
// already carries it.
//
// This is the helper for the guards whose whole subject is the re-apply: plant
// the shape a previous release left, run the file, assert the backfill converged,
// run it again, assert it stopped moving. Those cannot be satisfied by a cached
// no-op.
//
// It is also the one remaining way a test binary can hold ACCESS EXCLUSIVE across
// every table while other binaries are running, so use it only when the re-apply
// IS the assertion — and know that ordinary heavy writers elsewhere protect
// themselves from you with [WithSchemaShareLock] / [HoldSchemaShareLock].
//
// A forced apply also clears the marker for the role/grant re-assertions
// (execUnderSchemaLockOnce), since the file it just ran rewrites the same ACLs.
func ForceApplySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	applySQLFiles(t, db, true, schemaPath)
}

// ForceApplySeed applies scripts/database/seed.sql even when the database already
// carries it — the seed counterpart of [ForceApplySchema], for the tests that
// prove a seeded region re-applies without duplicating seeded rows or deleting an
// admin's own.
func ForceApplySeed(t *testing.T, db *sql.DB) {
	t.Helper()
	applySQLFiles(t, db, true, seedPath)
}

// The two files, repo-relative. These strings are also the marker keys, and the
// shell pre-appliers record the identical spelling — see
// scripts/run-integration-db-tests.sh.
const (
	schemaPath = "scripts/database/schema.sql"
	seedPath   = "scripts/database/seed.sql"
)

// RetryTransient runs fn, retrying the errors that are a symptom of two test
// BINARIES sharing one database rather than of anything under test.
//
// The advisory lock in [ApplySchema] and friends serializes appliers against
// each other. It does NOT serialize an applier against an ordinary query in
// another package's binary, and `go test ./...` runs those in parallel: a
// schema apply takes ACCESS EXCLUSIVE across the whole file while a multi-table
// SELECT elsewhere holds ACCESS SHARE on a subset in a different order, and
// Postgres resolves the cycle by killing one of them. The victim is whichever
// binary happened to be mid-statement, which is why it reads as a flaky test in
// a package that has nothing to do with schema.
//
// Only that class is retried, and only a few times. A real failure is
// deterministic and still fails on the last attempt, with its own error — this
// cannot turn a broken query green, which is the property that makes it
// different from a blanket `-p 1` (see run-integration-db-tests.sh, which
// refuses one for exactly that reason).
//
// `could not complete operation in a failed transaction` is in the list because
// it is the SECOND statement's report of the first one's deadlock: a caller
// whose transaction helper swallows one error surfaces the abort here instead.
func RetryTransient(t *testing.T, fn func() error) {
	t.Helper()
	const attempts = 4
	for i := 1; ; i++ {
		err := fn()
		if err == nil {
			return
		}
		if !isTransientRace(err) || i == attempts {
			t.Fatalf("testdb: %v", err)
		}
		t.Logf("testdb: transient cross-binary race (attempt %d/%d), retrying: %v", i, attempts, err)
		time.Sleep(time.Duration(i) * 150 * time.Millisecond)
	}
}

// IsTransientRace reports whether err is one of the cross-binary race classes
// [RetryTransient] retries.
//
// Exported for the callers that cannot simply retry — a best-effort write whose
// failure is REPORTED rather than raised, where the report has to distinguish
// "another test binary's schema apply deadlocked with us" from "this write is
// broken". Treating the first as a failure makes a shared database flaky;
// ignoring the second makes the report worthless.
func IsTransientRace(err error) bool { return err != nil && isTransientRace(err) }

// isTransientRace classifies the errors RetryTransient retries. Named so the
// list is in one place and can be read beside applySQLFiles', which is the same
// list for the same reason.
func isTransientRace(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "deadlock detected") ||
		strings.Contains(msg, "tuple concurrently updated") ||
		strings.Contains(msg, "could not complete operation in a failed transaction") ||
		strings.Contains(msg, "could not serialize access")
}

func applySQLFiles(t *testing.T, db *sql.DB, force bool, paths ...string) {
	t.Helper()
	root := RepoRoot(t)
	files := make([]sqlFile, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("testdb: read %s: %v", p, err)
		}
		files = append(files, sqlFile{name: p, body: string(b)})
	}
	applyFiles(t, db, force, files...)
}

// applyFiles is applySQLFiles with the bodies already in hand, so the cache and
// its mutual exclusion can be tested against small SQL of the test's own
// choosing rather than against the real 30k-line schema.
func applyFiles(t *testing.T, db *sql.DB, force bool, files ...sqlFile) {
	t.Helper()
	withSchemaLock(t, db, func(ctx context.Context, conn *sql.Conn) {
		// The marker is read and written under the SAME exclusive advisory lock
		// the apply takes. That is the whole mechanism: two binaries that arrive
		// together cannot both read "not applied" and both apply — the second
		// one reads the first one's row.
		marked := ensureAppliedMarker(ctx, conn)
		for _, f := range files {
			if !force && marked && alreadyApplied(ctx, conn, f) {
				logSkipOnce(t, f.name)
				continue
			}
			execApply(t, ctx, conn, f)
			if marked {
				recordApplied(ctx, conn, f)
			}
			if force {
				// The file just rewrote the ACLs the role helpers re-assert, so
				// let them run again rather than trust their own marker.
				invalidateGrantMarkers(ctx, conn)
			}
		}
	})
}

func execApply(t *testing.T, ctx context.Context, conn *sql.Conn, f sqlFile) {
	t.Helper()
	// Retry transient races only. The advisory lock serializes appliers against
	// each other, but not against ordinary tests in other binaries: e.g.
	// seed.sql's asset_lifecycle_policies INSERT selects FROM tenants, and a
	// concurrent test-cleanup DELETE of its throwaway tenant committing
	// mid-statement fails the FK check. A fresh attempt takes a new snapshot.
	// Real schema/seed bugs are deterministic and still fail after the retries.
	//
	// With the marker cache above, the only appliers that reach here on a shared
	// database are the deliberate ForceApply* ones, so this is now a backstop for
	// a handful of tests rather than the load-bearing defence it used to be.
	const attempts = 3
	for i := 1; ; i++ {
		_, err := conn.ExecContext(ctx, f.body)
		if err == nil {
			return
		}
		msg := err.Error()
		transient := strings.Contains(msg, "violates foreign key constraint") ||
			strings.Contains(msg, "deadlock detected") ||
			strings.Contains(msg, "tuple concurrently updated")
		if !transient || i == attempts {
			t.Fatalf("testdb: apply %s (attempt %d/%d): %v", f.name, i, attempts, err)
		}
		t.Logf("testdb: apply %s hit transient race (attempt %d/%d), retrying: %v", f.name, i, attempts, err)
		time.Sleep(200 * time.Millisecond)
	}
}

// logSkipOnce says once per process per file that the apply was skipped, so a -v
// log carries the fact without repeating it at all ~200 call sites.
func logSkipOnce(t *testing.T, name string) {
	t.Helper()
	if _, loaded := skipLogged.LoadOrStore(name, struct{}{}); loaded {
		return
	}
	t.Logf("testdb: %s is already applied to this database (content hash matches) — skipping the re-apply; "+
		"use testdb.ForceApply* if the re-apply is the assertion", name)
}

var skipLogged sync.Map

// NewTenant inserts a throwaway tenant and registers cleanup that CASCADE-deletes it
// — and, via the tenant_id foreign keys, everything created under it (e.g.
// findings, and through them finding history) — so each test is isolated
// and leaves no residue. Returns the new tenant id.
//
// The INSERT (and the cleanup DELETE) go through [RetryTransient]: this is an
// ordinary write against `tenants`, not a schema-mutating helper, so it takes
// no advisory lock and can collide with another package binary's concurrent
// ApplySchema* — which holds ACCESS EXCLUSIVE across the whole file, `tenants`
// included — the same cross-binary race class documented on RetryTransient.
// Observed as a bare `40P01 deadlock detected` failing the calling test
// outright instead of retrying (PR's second `make test-integration-db`
// run, admin-service/ee/msp, passing in isolation).
// Deliberately takes NO advisory lock, and MUST NOT.
//
// seed.sql inserts `asset_lifecycle_policies` rows SELECTed from `tenants`, so a
// cascade committing mid-statement fails that INSERT's FK check — the race that
// used to fail whole packages at setup (inventory-service/internal/jobs,
// admin-service/ee/edition). Making the two mutually exclusive by taking the
// schema key in SHARED mode here looks like the fix and was tried: it hangs the
// suite. Every test takes a tenant, so the shared lock is then requested
// constantly, and a shared request queues behind any waiting exclusive one — so
// a test that holds a table or row lock inside an open transaction and then wants
// a tenant waits on an applier that is itself waiting on that table lock. Ten
// packages sat at the 5-minute timeout in nightly's own command (`go test ./...`
// over the whole `shared` module), every one of them parked in
// pg_advisory_lock[_shared]; the per-leg local runner never showed it because its
// legs are separate `go test` invocations.
//
// The race is closed the other way instead: seed.sql is applied ONCE per database
// (see applied_marker.go), so the only appliers that can collide with a cascade
// are the two deliberate ForceApplySeed guards — for which the FK retry in
// execApply, which exists precisely for this, is sufficient. It was not before,
// because ~200 applies per run meant all three attempts could land inside one
// window. Measured over ten full parallel runs of the final tree: four runs hit
// the FK once (on asset_lifecycle_policies or tenant_roles), all four absorbed on
// the first retry, none anywhere near the three-attempt budget.
func NewTenant(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	slug := "it-" + id.String()[:8] // satisfies the tenants.slug ^[a-z0-9-]+$ check
	RetryTransient(t, func() error {
		_, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, id, "IT "+slug, slug)
		return err
	})
	t.Cleanup(func() {
		// Best-effort, same as before this fix (errors were unconditionally
		// swallowed) — a Cleanup must not fail an otherwise-green test over a
		// teardown-only row. What changed is retrying the same transient
		// cross-binary race class as the INSERT above, since a schema apply
		// running concurrently with THIS delete is just as likely as with the
		// insert. If every attempt is transient, the row is simply left behind
		// (CASCADE on the next fresh schema apply, or a manual sweep, clears it).
		for i := 1; i <= 4; i++ {
			_, err := db.Exec(`DELETE FROM tenants WHERE id = $1`, id)
			if err == nil {
				return
			}
			if !isTransientRace(err) {
				t.Logf("testdb: NewTenant cleanup: delete tenant %s: %v", id, err)
				return
			}
			time.Sleep(time.Duration(i) * 150 * time.Millisecond)
		}
		t.Logf("testdb: NewTenant cleanup: delete tenant %s: gave up after transient races", id)
	})
	return id
}
