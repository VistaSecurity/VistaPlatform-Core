package services

// What suspending a tenant owes it (RC-4), in one place so every
// route that suspends — the MSP tenant editor, offboarding, and a trial that
// ends with no Free plan to land on (owner decision — does the
// same two things:
//
//   - Remember the status being replaced (tenants.suspended_from_payment_status),
//     so reactivating restores it rather than a hard-coded 'active'.
//   - End the tenant's sessions: every refresh token its users hold is revoked
//     and session_version bumped, so lifting the suspension later does not
//     quietly bring the old sessions back. Access tokens stop working through
//     the per-request tenant-state check (shared/tenantstate), within its cache
//     TTL.

import (
	"context"
	"database/sql"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/tenantstate"
)

// BlockedStatusesSQL is tenantstate.BlockedPaymentStatuses as a SQL IN-list, so
// the "which statuses are a suspension" rule has one source.
var BlockedStatusesSQL = "('" + strings.Join(tenantstate.BlockedPaymentStatuses, "','") + "')"

// RememberPriorStatusSQL is the SET fragment every suspending write carries:
// remember the status being replaced, unless the tenant is ALREADY suspended or
// canceled — then the remembered value is the one from before the first
// suspension, and must not be overwritten with 'suspended'. In an UPDATE's SET
// list the right-hand columns are the row's OLD values, so the UPDATE must
// not also have a FROM item exposing a payment_status column.
var RememberPriorStatusSQL = `suspended_from_payment_status = CASE
		WHEN COALESCE(payment_status, '') IN ` + BlockedStatusesSQL + ` THEN suspended_from_payment_status
		ELSE payment_status END`

// RestoredStatusSQL is the status a suspension lift restores. A missing or
// invalid remembered value falls back to active; a blocked value is never used
// as the pre-suspension state because it can only describe a nested block.
var RestoredStatusSQL = `CASE
		WHEN suspended_from_payment_status IS NULL
		  OR suspended_from_payment_status IN ` + BlockedStatusesSQL + ` THEN 'active'
		ELSE suspended_from_payment_status END`

// RevokeTenantSessions revokes every live refresh token held by the tenant's
// users, in the caller's transaction. refresh_tokens carries no tenant column,
// so the tenant is reached through users; on the bypass pool that read is
// unfiltered, and inside WithTenantTx RLS scopes it to exactly this tenant,
// which is the same set.
func RevokeTenantSessions(ctx context.Context, tx *sql.Tx, tenantID string) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE tenants
		   SET session_version = session_version + 1
		 WHERE id = $1`, tenantID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE refresh_tokens
		   SET is_revoked = true, revoked_at = NOW()
		 WHERE is_revoked = false
		   AND user_id IN (SELECT id FROM users WHERE tenant_id = $1)`, tenantID)
	return err
}
