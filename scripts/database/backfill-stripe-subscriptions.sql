-- Backfill: Audit tenants who paid via the legacy PaymentIntent flow
-- ============================================================
-- These tenants have an active Stripe customer and a paid subscription_tier
-- but NO row in billing_subscriptions with an external_subscription_id,
-- because the old flow only created a one-time PaymentIntent — never a Subscription.
--
-- This script DOES NOT create Stripe subscriptions automatically.
-- Creating subscriptions for existing customers requires their stored
-- payment method ID, which must be retrieved from Stripe's API.
--
-- Recommended migration procedure:
--  1. Run the diagnostic query below to identify affected tenants.
--  2. For each tenant, use the Stripe Dashboard or API to:
--       a. Find their customer ID (stored in billing_customers.external_customer_id)
--       b. Retrieve their saved payment method (customer.list_payment_methods)
--       c. Create a Stripe Subscription for the correct Price ID
--            POST /v1/subscriptions with customer, items[price], default_payment_method
--       d. Record the subscription ID back to billing_subscriptions (step 3 below).
--  3. After Stripe subscription is created, run the INSERT below to record it locally.
--
-- This script is intentionally advisory; run it in a transaction and review results
-- before committing to production.

-- ─── Diagnostic: tenants needing a Stripe subscription ───────────────────────
-- Run this to see which tenants still need to be migrated.
/*
SELECT
    t.id                             AS tenant_id,
    t.name                           AS tenant_name,
    t.billing_email,
    t.payment_status,
    st.name                          AS tier_name,
    st.stripe_price_id,
    bc.external_customer_id          AS stripe_customer_id,
    bs.external_subscription_id      AS current_stripe_sub_id
FROM tenants t
JOIN subscription_tiers st ON st.id = t.subscription_tier_id
LEFT JOIN billing_customers bc
    ON bc.tenant_id = t.id
    AND bc.provider_id = (SELECT id FROM billing_providers WHERE key = 'stripe')
LEFT JOIN billing_subscriptions bs
    ON bs.tenant_id = t.id
    AND bs.provider_id = (SELECT id FROM billing_providers WHERE key = 'stripe')
WHERE t.is_active = true
  AND t.payment_status IN ('active', 'trial')
  AND st.price_cents > 0                          -- paid tier
  AND bc.external_customer_id IS NOT NULL          -- has a Stripe customer
  AND (bs.external_subscription_id IS NULL         -- but no subscription recorded
       OR bs.external_subscription_id = '')
ORDER BY t.created_at;
*/

-- ─── Recording step: after creating Stripe subscriptions via Dashboard/API ────
-- For each tenant, after you have created the Stripe subscription, run:
/*
BEGIN;

INSERT INTO billing_subscriptions (
    tenant_id,
    provider_id,
    external_subscription_id,
    plan_key,
    status,
    current_period_start,
    current_period_end,
    cancel_at_period_end,
    created_at,
    updated_at
)
VALUES (
    '<tenant_uuid>',
    (SELECT id FROM billing_providers WHERE key = 'stripe'),
    'sub_XXXXXXXXXXXXXXXX',   -- Stripe subscription ID from Dashboard
    '<tier_name>',            -- e.g. 'professional'
    'active',
    NOW(),                    -- update to actual period start from Stripe
    NOW() + INTERVAL '1 month',  -- update to actual period end from Stripe
    false,
    NOW(),
    NOW()
)
ON CONFLICT (tenant_id, provider_id) DO UPDATE
SET external_subscription_id = EXCLUDED.external_subscription_id,
    plan_key = EXCLUDED.plan_key,
    status = EXCLUDED.status,
    current_period_start = EXCLUDED.current_period_start,
    current_period_end = EXCLUDED.current_period_end,
    updated_at = NOW();

COMMIT;
*/

-- ─── Sync stripe_coupon_id for existing coupons ──────────────────────────────
-- Existing coupons in billing_coupons were created before Stripe sync was added.
-- Use the admin API endpoint POST /billing/coupons/sync-stripe (not yet implemented)
-- or recreate each coupon via the admin UI (which will auto-sync to Stripe on save).
-- To identify unsynced coupons:
/*
SELECT id, code, name, discount_type, discount_value, duration
FROM billing_coupons
WHERE is_active = true
  AND (stripe_coupon_id IS NULL OR stripe_coupon_id = '')
ORDER BY created_at;
*/
