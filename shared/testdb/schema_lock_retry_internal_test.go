package testdb

// The catalog-mutating helpers RETRY, and this is what says so.
//
// `EnsureRLSAppRole`, `ConnectAsBypassRole` and the `ALTER ROLE` in
// `ConnectAsAppRole` all rewrite cluster-global catalogue tuples (pg_class ACLs,
// pg_authid) while other test binaries of the same `go test ./...` run are doing
// ordinary work against the same database. Postgres reports the collision as
// "tuple concurrently updated", which is transient by construction — and a
// harness that did not retry it failed whichever package happened to be calling
// ConnectAsAppRole at that instant, in a test with nothing to do with roles.
//
// The retry lives in ONE place (`execUnderSchemaLock`, on top of
// `RetryTransient`) precisely so that this test covers all three callers. It
// used to live inside EnsureRLSAppRole alone, which left the ALTER ROLE one
// line later — and the whole of ConnectAsBypassRole, the same CREATE ROLE +
// GRANT + ALTER ROLE sequence — exposed to the identical race. Fixing one
// statement of a sequence only moves the flake along it.
//
// Mutation test: replace the RetryTransient call in execUnderSchemaLock with a
// single attempt and this goes red on the induced transient failure.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestIntegration_ExecUnderSchemaLock_RetriesATransientRace drives the helper
// with a statement that fails ONCE with the exact error class Postgres reports
// for a concurrent catalogue update, then succeeds.
//
// The failure is induced rather than raced for: a real collision needs two
// binaries rewriting the same pg_class tuple at the same instant, which is not
// something a test can schedule. What matters is the same thing either way —
// that a first attempt reporting this class is followed by a second.
func TestIntegration_ExecUnderSchemaLock_RetriesATransientRace(t *testing.T) {
	db := Connect(t)

	// A SEQUENCE, not a table, because the induced failure aborts its own
	// statement: an INSERT would roll back with the RAISE and every attempt
	// would look like the first, which is how the first draft of this test
	// "proved" a retry that was never happening. `nextval` is explicitly not
	// transactional — it survives the abort, so it can count attempts.
	probe := "testdb_retry_probe_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := db.Exec(`CREATE SEQUENCE ` + probe); err != nil {
		t.Fatalf("create probe sequence: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP SEQUENCE IF EXISTS ` + probe) })

	// Attempt 1 draws 1 and raises the transient error; attempt 2 draws 2 and
	// succeeds.
	stmt := `DO $$ BEGIN
	  IF nextval('` + probe + `') = 1 THEN
	    RAISE EXCEPTION 'tuple concurrently updated';
	  END IF;
	END $$;`

	execUnderSchemaLock(t, db, "retry probe", []string{stmt})

	var attempts int64
	if err := db.QueryRow(`SELECT last_value FROM ` + probe).Scan(&attempts); err != nil {
		t.Fatalf("read the attempt counter: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("the statement ran %d times, want exactly 2 — 1 means the transient failure was "+
			"never retried (and this test only passed because nothing failed), more means it kept failing", attempts)
	}
}

// TestExecUnderSchemaLock_ClassifiesTheRaceItRetries is the other polarity, and
// it needs no database: the retry must cover exactly the transient class and
// nothing else. A helper that retried everything would turn a genuinely broken
// GRANT into four slow failures instead of one fast one, and would keep a real
// permissions bug looking like flakiness.
func TestExecUnderSchemaLock_ClassifiesTheRaceItRetries(t *testing.T) {
	transient := []string{
		"pq: tuple concurrently updated",
		"pq: deadlock detected",
		"pq: could not serialize access due to concurrent update",
	}
	for _, msg := range transient {
		if !IsTransientRace(fmt.Errorf("EnsureRLSAppRole: %s\nstmt: GRANT …", msg)) {
			t.Errorf("%q is not classified transient; the helper would fail on a race it should ride out", msg)
		}
	}
	deterministic := []string{
		`pq: schema "audit" does not exist`,
		`pq: permission denied to create role`,
		`pq: syntax error at or near "GRANTT"`,
	}
	for _, msg := range deterministic {
		if IsTransientRace(fmt.Errorf("EnsureRLSAppRole: %s\nstmt: GRANT …", msg)) {
			t.Errorf("%q is classified transient; a real failure would be retried and reported four attempts late", msg)
		}
	}
}
