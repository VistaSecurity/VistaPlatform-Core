package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// Tenant isolation is enforced in two layers:
//
//  1. Primary: an explicit `WHERE tenant_id = $X` predicate on every
//     tenant-scoped query (the control the IDOR tests assert).
//  2. Defense-in-depth: PostgreSQL RLS policies that match the session variable
//     app.tenant_id. These become an *enforced* boundary once a service connects
//     as a non-owner role (see ADR platform-0001); until then the owner role
//     bypasses them and they are dormant.
//
// WithTenantTx is the canonical entrypoint for layer 2. Every tenant-scoped DB
// operation should run through it (or another path that sets app.tenant_id on
// the same connection as the query). Once RLS is enforcing, any tenant-scoped
// query that does NOT set app.tenant_id fails closed — it returns zero rows.
//
// WithTenantTx runs fn inside a single transaction that has set app.tenant_id to
// tenantID via set_tenant_context(). Pinning the SET and the queries to one
// transaction (hence one connection) is mandatory under a connection pool: a SET
// issued on a pooled *sql.DB can land on a different connection than the
// following query, which would silently leak across tenants under load.
// set_tenant_context() uses set_config(..., is_local => true), so the scope is
// transaction-local and clears automatically on commit or rollback — no manual
// reset, and no bleed onto the next checkout of the connection.
//
// fn typically closes over result variables (see the cbom-service repositories
// for the established pattern):
//
//	var rows []Thing
//	err := database.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
//	        r, err := tx.QueryContext(ctx, `SELECT ... FROM things WHERE deleted_at IS NULL`)
//	        ...
//	})
func WithTenantTx(ctx context.Context, db *sql.DB, tenantID uuid.UUID, fn func(*sql.Tx) error) error {
	// The all-zeros tenant is never legitimate and would otherwise scope the
	// transaction to a "tenant" no real row matches — fail loudly instead.
	if tenantID == uuid.Nil {
		return fmt.Errorf("rls: refusing to scope to the nil tenant")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// set_tenant_context raises on a NULL/zero tenant, so a missing tenant is a
	// hard error here rather than a silent "see nothing" (or, worse, "see all").
	if _, err := tx.ExecContext(ctx, "SELECT set_tenant_context($1)", tenantID); err != nil {
		return fmt.Errorf("rls: set tenant context: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// SetTenantContext sets app.tenant_id on an existing transaction. Use it when a
// caller already manages its own *sql.Tx (e.g. a multi-step unit of work) and
// wants the remainder of that transaction scoped to tenantID. For the common
// case prefer WithTenantTx, which owns the transaction lifecycle.
func SetTenantContext(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("rls: refusing to scope to the nil tenant")
	}
	if _, err := tx.ExecContext(ctx, "SELECT set_tenant_context($1)", tenantID); err != nil {
		return fmt.Errorf("rls: set tenant context: %w", err)
	}
	return nil
}
