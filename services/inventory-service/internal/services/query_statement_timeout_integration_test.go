package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Every read that runs a tenant-supplied query-language predicate carries a
// per-statement ceiling (security review X.5, X5-10).
//
// The `~` operator hands a tenant-supplied pattern to Postgres ARE, and the
// validator's caps bound the SHAPE of a predicate but not the TIME one takes
// against a subject the same tenant controls. Context cancellation was the only
// backstop, and it is a weak one: cancelling a context sends a cancel request
// on a SECOND connection and leaves the statement running until the backend
// notices. `SET LOCAL statement_timeout` is enforced by the backend itself.
//
// # What this file proves, and what it does not
//
// It proves the ceiling BINDS — that the SET LOCAL is really issued, really
// aborts an over-long statement, and really reverts with the transaction so it
// cannot leak onto a pooled connection.
//
// It does NOT prove that a catastrophic regex is what would trip it. That was
// measured for this review and the answer was no: `(a+)+`, `(a|a)+b`, `(a*)*b`
// and `([a-z]+)+#` against 44 'a's all returned in under a millisecond on
// PostgreSQL 17. Postgres's ARE is a hybrid DFA/NFA and does not backtrack the
// way PCRE does, so X5-10's premise does not reproduce on that engine. The
// ceiling is kept anyway, as a general bound on a predicate a tenant controls —
// a 256-value `in()` across every partition is expensive without any regex in
// it — but this file says plainly what was and was not demonstrated, rather
// than shipping a test named for a blow-up it cannot produce.
//
// The WIRING — that the asset list and the facet rail actually use the bounded
// helper — is pinned separately and without a database, by
// TestQueryReadsUseTheBoundedTenantTx: a SET LOCAL is not observable from
// outside its own transaction, and a test that tried to infer it from timing
// would be the flaky kind of guard this review exists to remove.

const sqlstateQueryCanceled = "57014"

// The mechanism: a statement past the ceiling is aborted by the server.
//
// To mutation-test: delete the SET LOCAL from WithTenantTxTimeout. This fails —
// the sleep completes and no error comes back. The second half is the other
// polarity: with no ceiling the same statement must succeed, so a
// WithTenantTxTimeout that clamped everything would fail there.
func TestIntegration_WithTenantTxTimeout_AbortsAStatementPastTheCeiling(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	start := time.Now()
	err := database.WithTenantTxTimeout(context.Background(), db, tenant, 150*time.Millisecond, func(tx *sqlx.Tx) error {
		_, e := tx.Exec("SELECT pg_sleep(5)")
		return e
	})
	if err == nil {
		t.Fatal("a five-second statement ran to completion under a 150ms ceiling — the SET LOCAL is not binding")
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || string(pqErr.Code) != sqlstateQueryCanceled {
		t.Fatalf("err = %v, want SQLSTATE %s (statement_timeout). Any other error means the statement was "+
			"stopped by something else and the ceiling is unproven", err, sqlstateQueryCanceled)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the ceiling took %s to fire; it is set to 150ms", elapsed)
	}

	// The other polarity: without a ceiling the same statement completes.
	if err := database.WithTenantTx(context.Background(), db, tenant, func(tx *sqlx.Tx) error {
		_, e := tx.Exec("SELECT pg_sleep(1)")
		return e
	}); err != nil {
		t.Fatalf("a one-second statement failed with no ceiling set: %v", err)
	}
}

// The value that is set is the one the caller asked for, and it is gone once
// the transaction commits.
//
// The second half is the failure a session-level SET would have: the pool hands
// the connection on, and a background job that legitimately takes a minute
// inherits a five-second ceiling from an asset-list request that ran first.
func TestIntegration_WithTenantTxTimeout_SetsTheAskedForValueAndDoesNotLeakIt(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	raw.SetMaxOpenConns(1) // force the follow-up read onto the same connection
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	var inside string
	if err := database.WithTenantTxTimeout(context.Background(), db, tenant, query.StatementTimeout, func(tx *sqlx.Tx) error {
		return tx.QueryRow("SELECT current_setting('statement_timeout')").Scan(&inside)
	}); err != nil {
		t.Fatalf("the bounded transaction failed: %v", err)
	}
	if want := "5s"; inside != want {
		t.Errorf("statement_timeout inside the transaction is %q, want %q (query.StatementTimeout)", inside, want)
	}

	var after string
	if err := raw.QueryRow("SELECT current_setting('statement_timeout')").Scan(&after); err != nil {
		t.Fatalf("reading statement_timeout: %v", err)
	}
	if after != "0" {
		t.Fatalf("statement_timeout is %q on the connection after the transaction committed; SET LOCAL "+
			"should have reverted it, and a ceiling that survives would silently bound the next caller", after)
	}
}
