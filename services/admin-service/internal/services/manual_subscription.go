package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// The manual (invoice) billing_subscriptions row has no payment provider
// behind it to say when the customer left: the tenant's own lifecycle is the
// only record. Revenue (owner decision 5) counts that row as long as it is
// live, so it has to follow the tenant — offboarding, the tenant editor's
// 'canceled' and deletion end it; cancelling the offboarding (or editing the
// tenant back out of 'canceled') brings it back while the tenant is still on
// the invoice plan the row records.
//
// Ending it sets status 'canceled' and canceled_at now with end_reason NULL.
// A move to another plan is recorded differently, by the
// tenants_plan_change_retires_manual_subscription trigger whichever service
// changes the tier: end_reason 'plan_change', and the revive below leaves
// that row alone — it is retired for good, even if the tenant comes back to
// the plan by a route that does not re-record it (only Assign to tenant
// starts invoicing again). Whether either is churn is revenue's per-tenant
// rule (did the tenant stop paying?), not the row's.
//
// Stripe rows are not touched: Stripe's webhooks own them.
const syncManualSubscriptionSQL = `
WITH manual AS (SELECT id FROM billing_providers WHERE key = 'manual'),
tenant AS (
	SELECT t.id,
	       (t.deleted_at IS NOT NULL OR t.payment_status = 'canceled') AS gone,
	       CASE WHEN st.billing_method = 'invoice' THEN 'invoice:' || st.id::text END AS invoice_ref
	FROM tenants t
	LEFT JOIN subscription_tiers st ON st.id = t.subscription_tier_id
	WHERE t.id = $1
),
ended AS (
	UPDATE billing_subscriptions bs
	   SET status = 'canceled', canceled_at = NOW(), end_reason = NULL, updated_at = NOW()
	  FROM tenant
	 WHERE bs.tenant_id = tenant.id
	   AND tenant.gone
	   AND bs.provider_id = (SELECT id FROM manual)
	   AND bs.status <> 'canceled'
	RETURNING bs.id
)
UPDATE billing_subscriptions bs
   SET status = 'active', canceled_at = NULL, updated_at = NOW()
  FROM tenant
 WHERE bs.tenant_id = tenant.id
   AND NOT tenant.gone
   AND bs.provider_id = (SELECT id FROM manual)
   AND bs.status = 'canceled'
   AND bs.end_reason IS NULL
   AND bs.external_subscription_id = tenant.invoice_ref`

// SQLExecer is satisfied by *sql.Tx and *sql.DB.
type SQLExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// SyncManualSubscription makes tenantID's manual (invoice) subscription row
// follow the tenant's lifecycle (see syncManualSubscriptionSQL). Call it in
// the same transaction as any change to the tenant's payment_status or
// deleted_at. billing_subscriptions is RLS-policied: run it on the bypass
// pool or in a transaction with app.tenant_id set to tenantID
// (shared/database.WithTenantTx) — on the app pool with no tenant context the
// row is invisible and nothing changes.
func SyncManualSubscription(ctx context.Context, exec SQLExecer, tenantID uuid.UUID) error {
	if _, err := exec.ExecContext(ctx, syncManualSubscriptionSQL, tenantID); err != nil {
		return fmt.Errorf("sync manual subscription for tenant %s: %w", tenantID, err)
	}
	return nil
}
