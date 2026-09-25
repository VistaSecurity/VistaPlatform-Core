package trials

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// billing_trial_tracking is the ONE trial store (owner decision 6, admin-UI
// data review 2026-09). A tenant is on a trial when it has a trial row that
// has not converted to paid AND its plan is one the MSP marked is_trial.
//
// tenants.payment_status = 'trial' is kept, but only as a value DERIVED from
// that store: the licence usage ledger folds payment_status into the state a
// usage report counts days by (shared/licenseusage.StateOf), and the tenant
// list filters on it. Removing the value would mean rewriting that ledger and
// the tenants CHECK constraint for no gain in truth; deriving it keeps one
// source of truth and every existing reader working. So nothing writes
// 'trial' by hand any more — every writer of the trial store calls
// SyncPaymentStatus in the same transaction, and the admin tenant editor
// refuses 'trial' outright.

// liveTrialExistsSQL is true when tenant $1 is on a trial by the definition
// above. A converted row, a row left behind on a tier that is not a trial
// tier, and a tenant with no tier are all "not on a trial".
const liveTrialExistsSQL = `EXISTS (
	SELECT 1
	FROM billing_trial_tracking btt
	JOIN tenants tt ON tt.id = btt.tenant_id
	JOIN subscription_tiers st ON st.id = tt.subscription_tier_id
	WHERE btt.tenant_id = $1
	  AND NOT COALESCE(btt.converted_to_paid, false)
	  AND st.is_trial)`

// SyncPaymentStatusSQL derives tenants.payment_status from the trial store.
// It only ever moves a tenant between 'active' and 'trial': a suspended,
// canceled, past-due or incomplete tenant is left alone (those states are set
// by the flows that own them, and a suspension remembers a trial through
// suspended_from_payment_status). Bind $1 = tenant id.
//
// billing_trial_tracking carries a tenant_isolation RLS policy, so run it on
// a transaction with app.tenant_id set to $1 (shared/database.WithTenantTx)
// or on the bypass pool. On the app pool with no tenant context the trial row
// is invisible and a trialling tenant would be flipped to 'active'.
const SyncPaymentStatusSQL = `
	UPDATE tenants t
	   SET payment_status = CASE WHEN live.v THEN 'trial' ELSE 'active' END,
	       updated_at = NOW()
	  FROM (SELECT ` + liveTrialExistsSQL + ` AS v) live
	 WHERE t.id = $1
	   AND ((live.v AND t.payment_status = 'active')
	     OR (NOT live.v AND t.payment_status = 'trial'))`

// PaidStatusSQL is the payment_status of tenant $1 once a payment has been
// recorded: 'trial' while its trial is live (Stripe marks a trial's $0 first
// invoice paid), 'active' otherwise. Use it as the value in the same UPDATE
// that records the payment — writing 'active' and then deriving in a second
// statement lets a reader see a live trial as 'active' in between. Same RLS
// requirement as SyncPaymentStatusSQL.
const PaidStatusSQL = `CASE WHEN ` + liveTrialExistsSQL + ` THEN 'trial' ELSE 'active' END`

// SQLExecer is satisfied by *sql.Tx and *sql.DB.
type SQLExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// SyncPaymentStatus runs SyncPaymentStatusSQL for one tenant. See that
// constant for the RLS requirement.
func SyncPaymentStatus(ctx context.Context, exec SQLExecer, tenantID uuid.UUID) error {
	if _, err := exec.ExecContext(ctx, SyncPaymentStatusSQL, tenantID); err != nil {
		return fmt.Errorf("trials: derive payment_status for tenant %s: %w", tenantID, err)
	}
	return nil
}
