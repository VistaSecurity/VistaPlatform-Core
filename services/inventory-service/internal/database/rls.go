package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// WithTenantTx runs fn inside a single sqlx transaction that has set
// app.tenant_id to tenantID (via the shared set_tenant_context primitive).
//
// inventory-service is overwhelmingly sqlx-based (.Get/.Select/.QueryRow/.Exec),
// so its tenant-scoped queries need a *sqlx.Tx rather than the plain *sql.Tx that
// shareddatabase.WithTenantTx yields. This helper produces the identical wire
// sequence the shared primitive guarantees — BEGIN, SELECT set_tenant_context($1),
// fn's queries, COMMIT (or ROLLBACK on error) — while exposing the sqlx-flavoured
// transaction the repositories already use.
//
// The actual context-setting SQL is delegated to shareddatabase.SetTenantContext
// so there is a single source of truth for the prologue (and the nil-tenant guard).
// Pinning the SET and the queries to one transaction (one connection) is mandatory
// under a pool — see shared/database/rls.go for the full rationale.
func WithTenantTx(ctx context.Context, db *DB, tenantID uuid.UUID, fn func(*sqlx.Tx) error) error {
	if tenantID == uuid.Nil {
		// Mirror the shared primitive's guard: refuse to scope to the nil tenant.
		return fmt.Errorf("rls: refusing to scope to the nil tenant")
	}

	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := shareddatabase.SetTenantContext(ctx, tx.Tx, tenantID); err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// WithTenantTxTimeout is WithTenantTx with a per-statement ceiling on every
// statement in the transaction (security review X.5, X5-10).
//
// Use it for any read that splices a TENANT-SUPPLIED query-language predicate
// into its WHERE clause. The validator bounds the shape of such a predicate but
// cannot bound the TIME one takes: `~` reaches Postgres ARE, a backtracking
// engine, and a nested unbounded quantifier is inside the permitted subset. A
// context deadline is not a substitute — cancelling a context sends a cancel
// request on a second connection and leaves the statement running until the
// backend notices, while statement_timeout is enforced by the backend itself.
//
// SET LOCAL, so it reverts with the transaction and cannot leak onto a pooled
// connection the next caller gets. The value is interpolated rather than bound
// because SET does not take parameters; it is a Go duration this package
// computes, never anything from a request.
func WithTenantTxTimeout(ctx context.Context, db *DB, tenantID uuid.UUID, timeout time.Duration, fn func(*sqlx.Tx) error) error {
	return WithTenantTx(ctx, db, tenantID, func(tx *sqlx.Tx) error {
		if timeout > 0 {
			ms := timeout.Milliseconds()
			if ms < 1 {
				ms = 1
			}
			if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", ms)); err != nil {
				return fmt.Errorf("rls: set statement_timeout: %w", err)
			}
		}
		return fn(tx)
	})
}

// SQLDB returns the underlying *sql.DB for the rare repository method that needs
// the shared *sql.Tx flavour of WithTenantTx (e.g. raw database/sql call sites)
// instead of the sqlx flavour above.
func (db *DB) SQLDB() *sql.DB {
	return db.DB.DB
}
