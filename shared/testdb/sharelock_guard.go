package testdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
)

// RequireSchemaShareLock proves that a test's pass helper takes the schema
// share lock BEFORE it touches a table.
//
// # Why a test needs proving
//
// `go test ./...` runs every package's binary at once against ONE Postgres, and
// a neighbouring package applying schema.sql takes ACCESS EXCLUSIVE locks
// across it in file order. A pass that reads several tables in one transaction
// takes its locks in query order, and Postgres resolves the resulting cycle by
// killing one side — `pq: deadlock detected` on a statement with nothing wrong
// with it, in a test that has nothing to do with schemas. [WithSchemaShareLock]
// makes that overlap impossible, and [RetryTransient] catches what slips past
// it; but both only work where a helper actually uses them, and a helper that
// does not is invisible until the two binaries happen to line up. The hygiene
// producer's recompute was exactly that: green alone, green under
// `make test-integration-db`, and a deadlock the moment inventory-service's
// producers and services packages ran together.
//
// # What it does
//
// setup runs first, with TEST_DATABASE_URL rewritten so every pool it opens is
// tagged (application_name); it builds the fixture and returns the pass to be
// checked. The harness then holds the schema lock EXCLUSIVELY, as an applier
// does, and runs the pass on the test goroutine. One of two things happens:
//
//   - the pass blocks on the share lock while holding no relation lock (the
//     verdict is "guarded"), and the harness releases the lock so it can
//     finish; or
//   - the pass runs to completion while the lock is held (the verdict is
//     "unguarded"), which is exactly the window a real apply deadlocks in.
//
// A pass that takes the share lock only after it has already locked a table is
// reported too: the lock has to come first, or the cycle is still there.
//
// The check is deterministic — nothing races. It holds only the advisory lock,
// never a table, so it cannot deadlock against anything itself; other binaries'
// appliers and guarded passes wait for the few milliseconds it takes to observe
// the verdict.
//
// Because setup opens the pools, it must NOT run under a lock the fixture also
// takes: ConnectAsAppRole and NewTenant take the schema lock exclusively, and
// that is why the fixture is built before the harness takes it. The test must
// not be parallel — the URL rewrite is a t.Setenv.
func RequireSchemaShareLock(t *testing.T, setup func(t *testing.T) (pass func())) {
	t.Helper()
	if err := checkSchemaShareLock(t, setup); err != nil {
		t.Fatalf("testdb: %v", err)
	}
}

// checkSchemaShareLock is RequireSchemaShareLock with the verdict returned
// rather than raised, so the harness can test its own two polarities.
func checkSchemaShareLock(t *testing.T, setup func(t *testing.T) func()) error {
	t.Helper()

	// The applier's pool is opened BEFORE the marker goes on the URL, so its
	// own backend is never mistaken for the pass's. A pool captures its DSN at
	// Open; a connection it makes later still carries no marker.
	applier := Connect(t)

	marker := fmt.Sprintf("testdb-sharelock-%d", time.Now().UnixNano())
	t.Setenv(URLEnv, withApplicationName(t, os.Getenv(URLEnv), marker))
	pass := setup(t)

	ctx := context.Background()
	conn, err := applier.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire applier connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaLockKey); err != nil {
		return fmt.Errorf("pg_advisory_lock: %w", err)
	}

	done := make(chan struct{})
	verdict := make(chan error, 1)
	go func() {
		// The unlock is what lets a GUARDED pass finish, and it must happen
		// whatever the watcher concluded — a session that keeps the exclusive
		// lock blocks every applier and every guarded pass in every binary
		// until this pool closes.
		defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, schemaLockKey) }()
		verdict <- watchForShareLockWaiter(ctx, conn, marker, done)
	}()
	pass()
	close(done)
	return <-verdict
}

// watchForShareLockWaiter polls until a backend tagged marker is waiting for the
// schema share lock, or done closes because the pass returned first.
func watchForShareLockWaiter(ctx context.Context, conn *sql.Conn, marker string, done <-chan struct{}) error {
	const (
		poll     = 20 * time.Millisecond
		patience = 30 * time.Second
	)
	deadline := time.Now().Add(patience)
	for {
		select {
		case <-done:
			return errors.New("the pass ran to completion while the schema lock was held exclusively: " +
				"it does not take testdb.WithSchemaShareLock before touching tables, so another package's " +
				"schema apply can deadlock against it under `go test ./...`")
		default:
		}

		var waiting, holding int
		err := conn.QueryRowContext(ctx, `
			SELECT
			  count(*) FILTER (WHERE l.locktype = 'advisory' AND l.objid::bigint = $2
			                     AND l.mode = 'ShareLock' AND NOT l.granted),
			  count(*) FILTER (WHERE l.locktype = 'relation' AND l.granted)
			FROM pg_stat_activity a
			JOIN pg_locks l ON l.pid = a.pid
			WHERE a.application_name = $1`, marker, schemaLockKey).Scan(&waiting, &holding)
		if err != nil {
			return fmt.Errorf("polling pg_locks for the pass: %w", err)
		}
		if waiting > 0 {
			if holding > 0 {
				return fmt.Errorf("the pass is waiting for the schema share lock while already holding %d relation lock(s): "+
					"the lock must be taken before the first table is touched, or the cycle with a concurrent apply is still there", holding)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the pass neither finished nor waited for the schema share lock within %s — inconclusive", patience)
		}
		time.Sleep(poll)
	}
}

// withApplicationName returns raw (a postgres:// URL) with application_name set
// to name, so the backends of every pool opened from it can be told apart in
// pg_stat_activity.
func withApplicationName(t *testing.T, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("testdb: parse %s: %v", URLEnv, err)
	}
	q := u.Query()
	q.Set("application_name", name)
	u.RawQuery = q.Encode()
	return u.String()
}
