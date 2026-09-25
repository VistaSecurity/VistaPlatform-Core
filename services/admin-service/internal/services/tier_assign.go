package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/licenseusage"
	"github.com/vistasecurity/vistaplatform/shared/trials"
)

// Assign-to-tenant refusals, mapped to HTTP statuses by the handler.
var (
	// ErrAssignTenantNotFound: no such (undeleted) tenant.
	ErrAssignTenantNotFound = errors.New("tenant not found")
	// ErrPlanPrivateToAnotherTenant: a custom plan owned by a different tenant.
	ErrPlanPrivateToAnotherTenant = errors.New("this plan is private to another tenant")
	// ErrBilledThroughStripe: owner decision 7. A tenant with a live Stripe
	// subscription changes plan through billing (the support change-plan
	// path, or the tenant's own billing page), which changes the Stripe price
	// too. Assigning here would move entitlements without touching what
	// Stripe charges.
	ErrBilledThroughStripe = errors.New("tenant is billed through Stripe")
)

// BilledThroughStripeMessage is the refusal the operator reads (409).
const BilledThroughStripeMessage = "This tenant is billed through Stripe — change plan through billing"

// AssignTierResult summarizes assigning a plan to a tenant.
type AssignTierResult struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	TierID        uuid.UUID `json:"tier_id"`
	TierName      string    `json:"tier_name"`
	BillingMethod string    `json:"billing_method"`
	PaymentStatus string    `json:"payment_status,omitempty"`
	Activated     bool      `json:"activated"`
	// PreviousTierID is the plan the tenant was on, for the audit record.
	PreviousTierID *uuid.UUID `json:"-"`
}

// liveStripeSubscriptionSQL is true when tenant $1 has a Stripe subscription
// Stripe is still billing (anything but cancelled or expired-incomplete).
// The support billing edit's placeholder row (external_subscription_id
// 'pending', status 'incomplete' — intent recorded before any Stripe
// subscription exists) is not one: Stripe bills nothing for it.
const liveStripeSubscriptionSQL = `
	SELECT EXISTS (
		SELECT 1
		FROM billing_subscriptions bs
		JOIN billing_providers bp ON bp.id = bs.provider_id AND bp.key = 'stripe'
		WHERE bs.tenant_id = $1
		  AND bs.status NOT IN ('canceled', 'incomplete_expired')
		  AND bs.external_subscription_id <> 'pending'
		  AND bs.canceled_at IS NULL)`

// AssignTierToTenant assigns a (typically custom/enterprise) plan to a tenant.
//
// Owner decision 7 (admin-UI data review RC-25):
//
//   - REFUSED with ErrBilledThroughStripe when the tenant has a live Stripe
//     subscription: its plan changes through billing, so the price Stripe
//     charges and the entitlements the tenant gets cannot drift apart.
//   - An invoice-billed plan is record-only: NO Stripe subscription is
//     created. The tenant is pointed at the plan, marked active, and a manual
//     billing_subscriptions row records the plan (it is what revenue and the
//     billing view read). Sales invoices the customer out-of-band.
//   - A stripe-billed plan on a tenant with no Stripe subscription only sets
//     the tier; card collection still flows through checkout, so
//     payment_status is left to it.
//   - Any plan change retires the manual (invoice) subscription row of the
//     plan the tenant is leaving (status 'canceled', canceled_at now,
//     end_reason 'plan_change'). Whether that is churn is decided per tenant
//     by revenue: not when the tenant goes on paying (another invoice plan,
//     or a card plan it checks out), yes when it stops (a free plan). That is
//     not done here: the
//     tenants_plan_change_retires_manual_subscription trigger does it in the
//     same statement as the tier write, for every writer of the tier in every
//     service. An invoice plan then re-records the row for the new plan.
//   - An invoice-billed plan is a paid plan: a live trial the tenant had is
//     marked converted, so the trial sweep (TrialManager.CheckTrialExpiry)
//     can never lock or downgrade a tenant that is now paying, and the
//     conversion counts in the trial conversion rate.
//
// Everything is one transaction: the tenant row (locked), the plan-ownership
// claim, the manual subscription row and the derived trial status
// (shared/trials — moving off a trial plan ends the 'trial' label). Marking a
// SUSPENDED tenant active is a reactivation, recorded in the licence usage
// ledger after the commit, attributed to actor.
func (s *TierService) AssignTierToTenant(tierID, tenantID uuid.UUID, actor string) (*AssignTierResult, error) {
	tier, err := s.GetTier(tierID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTierNotFound, err)
	}
	// A private custom plan may only be assigned to its owning tenant.
	if tier.OwnerTenantID != nil && *tier.OwnerTenantID != tenantID {
		return nil, ErrPlanPrivateToAnotherTenant
	}

	res := &AssignTierResult{TenantID: tenantID, TierID: tierID, TierName: tier.Name, BillingMethod: tier.BillingMethod}
	ctx := context.Background()
	var prevStatus sql.NullString
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		var prevTier uuid.NullUUID
		if e := tx.QueryRowContext(ctx,
			`SELECT payment_status, subscription_tier_id FROM tenants WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
			tenantID).Scan(&prevStatus, &prevTier); errors.Is(e, sql.ErrNoRows) {
			return ErrAssignTenantNotFound
		} else if e != nil {
			return fmt.Errorf("check tenant: %w", e)
		}
		if prevTier.Valid {
			id := prevTier.UUID
			res.PreviousTierID = &id
		}

		var billedByStripe bool
		if e := tx.QueryRowContext(ctx, liveStripeSubscriptionSQL, tenantID).Scan(&billedByStripe); e != nil {
			return fmt.Errorf("check Stripe subscription: %w", e)
		}
		if billedByStripe {
			return ErrBilledThroughStripe
		}

		// A custom plan assigned without a prior owner claims that tenant as
		// owner, so it stays private going forward.
		if tier.IsCustom && tier.OwnerTenantID == nil {
			if _, e := tx.ExecContext(ctx,
				`UPDATE subscription_tiers SET owner_tenant_id = $1, updated_at = NOW() WHERE id = $2`,
				tenantID, tierID); e != nil {
				return fmt.Errorf("claim plan ownership: %w", e)
			}
		}

		if tier.BillingMethod == "invoice" {
			if _, e := tx.ExecContext(ctx,
				`UPDATE tenants SET subscription_tier_id = $1, payment_status = 'active', updated_at = NOW() WHERE id = $2`,
				tierID, tenantID); e != nil {
				return fmt.Errorf("assign invoice plan: %w", e)
			}
			if e := recordManualSubscription(ctx, tx, tenantID, tier); e != nil {
				return e
			}
			if _, e := tx.ExecContext(ctx, `
				UPDATE billing_trial_tracking
				   SET converted_to_paid = true, converted_at = NOW(), updated_at = NOW()
				 WHERE tenant_id = $1 AND NOT COALESCE(converted_to_paid, false)`, tenantID); e != nil {
				return fmt.Errorf("convert trial: %w", e)
			}
			res.PaymentStatus = "active"
			res.Activated = true
		} else {
			// This write retires the manual (invoice) row the tenant had
			// (tenants_plan_change_retires_manual_subscription).
			if _, e := tx.ExecContext(ctx,
				`UPDATE tenants SET subscription_tier_id = $1, updated_at = NOW() WHERE id = $2`,
				tierID, tenantID); e != nil {
				return fmt.Errorf("assign plan: %w", e)
			}
		}
		return trials.SyncPaymentStatus(ctx, tx, tenantID)
	})
	if err != nil {
		return nil, err
	}

	// The ledger is written on the bypass pool (read-only for the app role),
	// after the change has committed: best effort, like every call site whose
	// change commits on another pool.
	if res.Activated && licenseusage.StateOf(prevStatus.String) == licenseusage.StateSuspended {
		licenseusage.RecordBestEffort(ctx, s.bypassDB, tenantID, licenseusage.Reactivated, actor)
	}
	return res, nil
}

// recordManualSubscription writes the billing_subscriptions row under the
// "manual" provider that records an invoice-billed plan (it is what revenue
// analytics and the admin billing view read). Runs in the caller's
// tenant-scoped transaction: billing_subscriptions is RLS-policied, and a
// failure fails the assignment rather than leaving a plan with no record.
func recordManualSubscription(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, tier *models.SubscriptionTier) error {
	var providerID uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO billing_providers (key, display_name, is_active)
		VALUES ('manual', 'Manual / Invoice', true)
		ON CONFLICT (key) DO UPDATE SET is_active = true
		RETURNING id
	`).Scan(&providerID); err != nil {
		return fmt.Errorf("ensure manual provider: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO billing_subscriptions (tenant_id, provider_id, external_subscription_id, plan_key, status)
		VALUES ($1, $2, $3, $4, 'active')
		ON CONFLICT (tenant_id, provider_id) DO UPDATE
		SET external_subscription_id = EXCLUDED.external_subscription_id,
		    plan_key = EXCLUDED.plan_key,
		    status = 'active',
		    canceled_at = NULL,
		    updated_at = NOW()
	`, tenantID, providerID, "invoice:"+tier.ID.String(), tier.Name); err != nil {
		return fmt.Errorf("write manual subscription: %w", err)
	}
	return nil
}
