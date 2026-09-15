package testdb

// The applied-marker cache, tested for the property it exists for: two binaries
// arriving together apply ONCE.
//
// Internal test (package testdb, not testdb_test) on purpose: it drives
// applyFiles with a three-line SQL body of its own rather than the real 30k-line
// schema.sql, so the mechanism is measured in milliseconds and the assertion is
// an exact row count rather than "did anything deadlock".
//
// Mutation-proven in both directions: replacing withSchemaLock's
// pg_advisory_lock with a no-op makes TwoConcurrentAppliersApplyOnce fail with
// 2 rows (both goroutines read "not applied" and both applied), and restoring it
// makes it pass again. The marker check is inside the lock for exactly that
// reason.

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_AppliedMarker_TwoConcurrentAppliersApplyOnce(t *testing.T) {
	db := scratchDatabase(t)

	// Each APPLY appends a row. A skipped apply appends nothing, so the row count
	// is the number of applies that actually happened.
	probe := sqlFile{
		name: "testdb-probe.sql",
		body: `CREATE TABLE IF NOT EXISTS applies (at timestamptz NOT NULL DEFAULT now());
		       INSERT INTO applies DEFAULT VALUES;`,
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // line them up so they contend for the lock
			applyFiles(t, db, false, probe)
		}()
	}
	close(start)
	wg.Wait()

	if got := countApplies(t, db); got != 1 {
		t.Fatalf("the file was applied %d times by two concurrent appliers, want exactly 1 — "+
			"the marker check must happen while holding the exclusive advisory lock, or both "+
			"appliers read \"not applied\" and both apply", got)
	}

	// And a later applier, arriving after the fact, still skips.
	applyFiles(t, db, false, probe)
	if got := countApplies(t, db); got != 1 {
		t.Fatalf("a third apply of unchanged content ran anyway (%d rows) — the marker is not being read", got)
	}

	// Forcing applies regardless: that is what the ForceApply* helpers promise the
	// re-appliability guards.
	applyFiles(t, db, true, probe)
	if got := countApplies(t, db); got != 2 {
		t.Fatalf("a FORCED apply did not run (%d rows, want 2) — the re-appliability guards depend on it", got)
	}

	// Changed content is a different hash, so it applies even unforced.
	changed := probe
	changed.body += "\n-- a comment is enough to change the hash\n"
	applyFiles(t, db, false, changed)
	if got := countApplies(t, db); got != 3 {
		t.Fatalf("changed content was skipped (%d rows, want 3) — the marker keys on the hash, not the path", got)
	}
}

func countApplies(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM applies`).Scan(&n); err != nil {
		t.Fatalf("count applies: %v", err)
	}
	return n
}

// scratchDatabase creates an empty throwaway database on the same server as
// TEST_DATABASE_URL and returns a handle to it, dropped at test end.
//
// Empty, not schema-loaded: the marker mechanism is about deciding whether to
// apply, and deciding it about a three-line file is the same decision as about
// schema.sql. It must not be the shared database — that one already carries the
// marker rows the runner recorded.
func scratchDatabase(t *testing.T) *sql.DB {
	t.Helper()
	admin := Connect(t)
	name := "testdb_marker_" + uuid.New().String()[:8]
	// CREATE DATABASE cannot run inside a transaction block, so a plain Exec.
	if _, err := admin.Exec(fmt.Sprintf(`CREATE DATABASE %q`, name)); err != nil {
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, name)) })

	u, err := url.Parse(os.Getenv(URLEnv))
	if err != nil {
		t.Fatalf("parse %s: %v", URLEnv, err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("open scratch database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping scratch database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
