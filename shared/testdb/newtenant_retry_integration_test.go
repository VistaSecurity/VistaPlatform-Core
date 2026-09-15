package testdb_test

// Proves that testdb.NewTenant survives the exact cross-binary race
// RetryTransient exists for, and that it still fails deterministically (never
// hangs) when the contention genuinely outlasts the retry budget.
//
// NewTenant's INSERT fires three AFTER INSERT triggers on `tenants`
// (auto_license_best_practices_on_tenant_create,
// auto_license_iec62351_for_enterprise_on_tenant_create,
// create_system_sensors_on_tenant_create — fired in that alphabetical order,
// per Postgres's trigger-firing rule), the last of which inserts into
// `sensors`. So a single NewTenant call really does touch two tables
// (`tenants` then `sensors`) inside one implicit transaction, which is what
// lets this test build a genuine two-resource deadlock without needing any
// use of ee/ or unexported package internals: a second session that takes
// `sensors` before `tenants` (the opposite order) reliably cycles against it.
//
// Mutation test: comment out the RetryTransient wrapping in NewTenant (bare
// db.Exec again) and TestIntegration_NewTenant_RetriesDeadlock's first subtest
// fails immediately on the induced deadlock instead of retrying past it.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// helperProcessEnv, when set to "1", tells TestHelperProcess_NewTenantUnderLock
// it was deliberately re-invoked (see below) rather than picked up by an
// ordinary `go test ./testdb/...` run.
const helperProcessEnv = "TESTDB_NEWTENANT_HELPER_PROCESS"

// openSingleConnDB opens a dedicated *sql.DB capped at one connection, so a
// session-scoped `SET ...` issued once is guaranteed to still be in effect on
// every later Exec against it (sql.DB would otherwise be free to hand out any
// pooled connection, and a fresh one would not have the setting).
func openSingleConnDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv(testdb.URLEnv)
	if url == "" {
		t.Skipf("%s not set — skipping DB integration test (run `make test-integration-db`)", testdb.URLEnv)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestIntegration_NewTenant_RetriesDeadlock(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	// Held for the whole test, AFTER the apply above (which takes the same key
	// exclusively).
	//
	// Both subtests build a DELIBERATE two-session deadlock and then assert
	// which side loses and how fast. A third session in the cycle breaks that
	// assertion, and a schema apply is exactly such a session: it takes ACCESS
	// EXCLUSIVE on `sensors` and `tenants`, the two tables these subtests lock
	// in opposite orders. Observed under `go test` over the module's DB-backed
	// packages — the apply's own retry logged a deadlock in this test's output
	// and then session A, not session B, was the one Postgres killed:
	//
	//	newtenant_retry_integration_test.go:116: session A: lock tenants:
	//	    pq: deadlock detected (40P01)
	//
	// Shared mode, so this serializes against appliers only, and an applier
	// waits on the advisory lock instead of cycling against the induced
	// deadlock.
	testdb.HoldSchemaShareLock(t, owner)

	t.Run("retries past a deadlock and succeeds once the other side releases within budget", func(t *testing.T) {
		bDB := openSingleConnDB(t) // the connection NewTenant will insert through
		if _, err := bDB.Exec(`SET deadlock_timeout = '200ms'`); err != nil {
			t.Fatalf("set deadlock_timeout: %v", err)
		}

		aDB := openRawDB(t) // the session playing the concurrent schema-apply-shaped contender
		ctx := context.Background()
		tx, err := aDB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("session A: begin: %v", err)
		}
		// Take sensors FIRST — the opposite of the order NewTenant's own insert
		// and trigger cascade takes (tenants, then sensors) — so the two
		// sessions form a genuine wait-for cycle rather than merely queueing.
		if _, err := tx.ExecContext(ctx, `LOCK TABLE sensors IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatalf("session A: lock sensors: %v", err)
		}

		type aOutcome struct{ err error }
		resultCh := make(chan aOutcome, 1)
		go func() {
			// Generous head start: give the foreground INSERT (below) time to
			// acquire the tenants lock and reach the blocked sensors trigger,
			// so session A's request below queues AFTER it — the ordering the
			// cycle depends on. NewTenant's whole cascade is a handful of
			// simple single-row statements; 100ms is comfortable slack.
			time.Sleep(100 * time.Millisecond)
			if _, err := tx.ExecContext(ctx, `LOCK TABLE tenants IN ACCESS EXCLUSIVE MODE`); err != nil {
				resultCh <- aOutcome{err: fmt.Errorf("lock tenants: %w", err)}
				_ = tx.Rollback()
				return
			}
			// Release everything the instant we have it, well inside
			// RetryTransient's ~150ms-before-attempt-2 window, so the retried
			// INSERT finds both tables free.
			if err := tx.Commit(); err != nil {
				resultCh <- aOutcome{err: fmt.Errorf("commit: %w", err)}
				return
			}
			resultCh <- aOutcome{}
		}()

		start := time.Now()
		id := testdb.NewTenant(t, bDB) // runs on the test goroutine — the only place NewTenant may call t.Fatalf
		elapsed := time.Since(start)

		if res := <-resultCh; res.err != nil {
			t.Fatalf("session A: %v", res.err)
		}
		if id == uuid.Nil {
			t.Fatal("NewTenant returned a nil id")
		}
		t.Logf("NewTenant succeeded after %s (retried past the induced deadlock)", elapsed)
		if elapsed < 150*time.Millisecond {
			t.Errorf("NewTenant returned in %s — too fast to have hit the deadlock at all; "+
				"the test isn't proving what it claims to (check the timing/lock ordering above)", elapsed)
		}
	})

	t.Run("fails deterministically, not by hanging, when the contention outlasts the retry budget", func(t *testing.T) {
		// This has to prove NewTenant genuinely FAILS (calls t.Fatalf) once the
		// lock outlives the retry budget — but doing that with an ordinary
		// t.Run subtest would work AND would permanently flip this package's
		// `go test` exit code red, since a failed subtest always propagates to
		// the top regardless of whether the parent inspects t.Run's own bool
		// return. So the actual failing call runs in a re-exec'd copy of this
		// same test binary (the standard `os.Args[0]` "helper process" pattern,
		// as in net/http and os/exec's own tests): its exit code is what we
		// assert on, not our own t.
		aDB := openRawDB(t)
		ctx := context.Background()
		tx, err := aDB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("session A: begin: %v", err)
		}
		if _, err := tx.ExecContext(ctx, `LOCK TABLE sensors IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatalf("session A: lock sensors: %v", err)
		}
		// Held for the rest of this subtest, released unconditionally at
		// cleanup so a failure here can never wedge the shared database for
		// whichever other package binary is sharing it under `go test ./...`.
		t.Cleanup(func() { _ = tx.Rollback() })

		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_NewTenantUnderLock$", "-test.v")
		cmd.Env = append(os.Environ(), helperProcessEnv+"=1")
		start := time.Now()
		out, runErr := cmd.CombinedOutput()
		elapsed := time.Since(start)

		if runErr == nil {
			t.Fatalf("expected the helper process's NewTenant call to fail while sensors stayed locked past the "+
				"retry budget, but it exited 0. Output:\n%s", out)
		}
		// Bound generous relative to the worst case (4 attempts * the helper's
		// statement_timeout + RetryTransient's own sleeps, plus process
		// start-up), but tight enough that an actual hang (blocked on the DB
		// with no timeout at all) would trip it well before `go test`'s own
		// -timeout does.
		const ceiling = 8 * time.Second
		if elapsed > ceiling {
			t.Errorf("helper process took %s to fail — expected a bounded failure under %s, not something that "+
				"reads as a hang. Output:\n%s", elapsed, ceiling, out)
		}
		t.Logf("helper process failed after %s, as expected. Output:\n%s", elapsed, out)
	})
}

// TestHelperProcess_NewTenantUnderLock is not a real test — see the "fails
// deterministically" subtest above, which re-executes this same test binary
// with helperProcessEnv set so this is the only test that runs. It exists so
// that a genuinely-failing NewTenant call (once its own budget is exhausted)
// fails a THROWAWAY process instead of this package's own `go test` result.
//
// Skips immediately (green) under any ordinary `go test ./testdb/...` run.
func TestHelperProcess_NewTenantUnderLock(t *testing.T) {
	if os.Getenv(helperProcessEnv) != "1" {
		t.Skip("helper process for TestIntegration_NewTenant_RetriesDeadlock — not meant to run directly")
	}
	bDB := openSingleConnDB(t)
	// Every attempt NewTenant makes while sensors stays locked (by the parent
	// process) blocks on the trigger's INSERT into sensors; a bounded
	// statement_timeout turns that indefinite block into a real (non-transient)
	// error so the whole call is guaranteed to return instead of hanging.
	// isTransientRace does not classify this message, so RetryTransient must
	// fail fast rather than retry it.
	if _, err := bDB.Exec(`SET statement_timeout = '400ms'`); err != nil {
		t.Fatalf("set statement_timeout: %v", err)
	}
	testdb.NewTenant(t, bDB)
}

// openRawDB opens a *sql.DB with no special session settings — used for the
// "session A" side of each subtest, which only ever needs one live
// transaction (via *sql.Tx, which pins a single connection for its lifetime
// regardless of pool size).
func openRawDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv(testdb.URLEnv)
	if url == "" {
		t.Skipf("%s not set — skipping DB integration test (run `make test-integration-db`)", testdb.URLEnv)
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
