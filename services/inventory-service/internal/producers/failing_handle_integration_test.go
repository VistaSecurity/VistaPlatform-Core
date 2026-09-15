package producers

// A database handle whose Nth query fails, and everything else works.
//
// # Why this exists rather than a closed pool
//
// "A pass that FAILED must not sweep" is the most dangerous property of the
// producer contract, and a guard for it has to be able to FAIL. The eol
// producer can drive it by swapping in a catalogue store that answers once and
// then errors (failed_pass_integration_test.go); the `configuration` and
// `hygiene` producers have no catalogue — their rule tables are in this package
// — so the only dependency that can fail is the database.
//
// A CLOSED pool is not good enough, and that is not a theoretical objection: it
// was tried first. With a closed handle the read fails and so does the write,
// so a producer mutated to swallow its read error still cannot sweep — the
// sweep's transaction never opens. The guard passed with the bug in place,
// which is exactly the "a check that cannot fail is worse than no check"
// failure this repository keeps paying for.
//
// So the failure is injected where a real one arrives: one query, part way
// through the read, on a connection that is fine before and after. That is the
// shape of a deadlock, a statement timeout, or a cancelled context — the read
// has a PARTIAL answer, the pass has made no full statement, and the write
// phase would work perfectly if the producer let it.
//
// Mutation-proven both ways. Delete the `if err != nil { return ... }` after
// either producer's read and both AFailedPassDoesNotSweep tests go red, with
// every finding in the fixture INACTIVE.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// errInjectedReadFailure is what the armed query returns.
var errInjectedReadFailure = errors.New("injected: the read died part way through")

// failAfterQueries counts down to the query that fails. 0 means disarmed.
//
// A package-level counter because a driver is registered once per binary. Each
// test arms it immediately before the call it wants to break and the counter
// disarms itself when it fires, so no test can inherit another's arming — and
// only the handle opened with this driver is affected either way.
var failAfterQueries atomic.Int32

// armQueryFailure makes the nth query on a failingHandle return an error.
//
// n is 1-based and counts QUERIES, not statements: the transaction's own
// `BEGIN` and its `SET LOCAL` go through Exec, so n=2 is the second SELECT of
// the read phase — a read that has already answered once and now cannot finish.
func armQueryFailure(t *testing.T, n int32) {
	t.Helper()
	failAfterQueries.Store(n)
	t.Cleanup(func() { failAfterQueries.Store(0) })
}

func init() { sql.Register(failingDriverName, failingDriver{}) }

const failingDriverName = "vista-producers-failing-pq"

type failingDriver struct{}

func (failingDriver) Open(dsn string) (driver.Conn, error) {
	inner, err := pq.Open(dsn)
	if err != nil {
		return nil, err
	}
	return failingConn{inner}, nil
}

// failingConn forwards everything to lib/pq and intercepts QueryContext.
//
// The forwarded set is the one `database/sql` looks for: without BeginTx,
// ExecContext and PrepareContext it silently falls back to the older
// non-context methods and a cancelled context stops being honoured, which would
// change the behaviour under test rather than only injecting a failure into it.
type failingConn struct{ inner driver.Conn }

func (c failingConn) Prepare(q string) (driver.Stmt, error) { return c.inner.Prepare(q) }
func (c failingConn) Close() error                          { return c.inner.Close() }
func (c failingConn) Begin() (driver.Tx, error)             { return c.inner.Begin() } //nolint:staticcheck // the interface requires it

func (c failingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.inner.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c failingConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.inner.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}

func (c failingConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.inner.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func (c failingConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if n := failAfterQueries.Load(); n > 0 && failAfterQueries.Add(-1) == 0 {
		return nil, errInjectedReadFailure
	}
	return c.inner.(driver.QueryerContext).QueryContext(ctx, q, args)
}

func (c failingConn) ResetSession(ctx context.Context) error {
	if r, ok := c.inner.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

// failingHandle opens a pool on the test database through the driver above.
//
// ONE connection, because the failure counter is per-binary and a pool that
// opened a second connection mid-pass would make which query fails depend on
// scheduling.
func failingHandle(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv(testdb.URLEnv)
	if dsn == "" {
		t.Skipf("%s is not set", testdb.URLEnv)
	}
	db, err := sql.Open(failingDriverName, dsn)
	if err != nil {
		t.Fatalf("opening the failure-injecting handle: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		t.Fatalf("pinging the failure-injecting handle: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
