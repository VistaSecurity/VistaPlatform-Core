package database

import (
	"context"
	"database/sql"
	"fmt"

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

// SQLDB returns the underlying *sql.DB for the rare repository method that needs
// the shared *sql.Tx flavour of WithTenantTx (e.g. raw database/sql call sites)
// instead of the sqlx flavour above.
func (db *DB) SQLDB() *sql.DB {
	return db.DB.DB
}
