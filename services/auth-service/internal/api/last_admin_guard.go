package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// errLastAdmin means the requested change would leave the tenant with no active
// tenant_admin. Handlers map it to a 400 whose wording suits the operation.
var errLastAdmin = errors.New("would remove the last tenant admin")

// guardLastTenantAdmin refuses a change that would strip a tenant of its last
// active tenant_admin. It MUST be called inside the same WithTenantTx as the
// mutation it guards (deactivate, soft-delete, erase, or a role change away from
// tenant_admin), for two reasons:
//
//   - check-then-act: with the count and the write in different transactions,
//     two admins removing each other (or two requests against the last two
//     admins) each see "one other admin remains" and both succeed, leaving none.
//     A per-tenant advisory lock taken first serialises those decisions, and
//     because it is held to commit, the second request's count runs after the
//     first request's write is visible (READ COMMITTED takes a fresh snapshot
//     per statement).
//   - it only counts role standing that exists at that instant, in that tx.
//
// Only the tenant_admin role counts. billing_admin used to be counted as an
// "admin", so a tenant whose only other admin was a billing_admin (who cannot
// manage users) could be left with nobody able to administer it. A target who is
// not currently an active tenant_admin is never blocked: removing someone who is
// not holding the role cannot orphan it.
func guardLastTenantAdmin(ctx context.Context, tx *sql.Tx, tenantID, userID uuid.UUID) error {
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('tenant_admin_guard:' || $1::text, 0))`,
		tenantID.String()); err != nil {
		return fmt.Errorf("lock tenant admin set: %w", err)
	}

	var targetIsAdmin bool
	var others int
	err := tx.QueryRowContext(ctx, `
		WITH admins AS (
			SELECT DISTINCT utr.user_id
			FROM user_tenant_roles utr
			JOIN tenant_roles tr ON tr.id = utr.role_id
			JOIN users u ON u.id = utr.user_id
			WHERE utr.tenant_id = $1
			  AND tr.tenant_id = $1
			  AND tr.name = 'tenant_admin'
			  AND utr.is_active = true
			  AND (utr.expires_at IS NULL OR utr.expires_at > NOW())
			  AND u.is_active = true
			  AND u.deleted_at IS NULL
		)
		SELECT EXISTS (SELECT 1 FROM admins WHERE user_id = $2),
		       (SELECT COUNT(*) FROM admins WHERE user_id <> $2)
	`, tenantID, userID).Scan(&targetIsAdmin, &others)
	if err != nil {
		return fmt.Errorf("count tenant admins: %w", err)
	}
	if targetIsAdmin && others == 0 {
		return errLastAdmin
	}
	return nil
}
