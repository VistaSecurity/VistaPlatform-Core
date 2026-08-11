-- Migration: Add Stripe-native IDs to support subscription-managed billing
-- Run this on existing databases. New deployments use schema.sql which already includes these columns.
-- Safe to run multiple times (IF NOT EXISTS / IF EXISTS guards).

-- Stripe Price ID on subscription_tiers
-- Each paid tier maps to a Stripe Price object (e.g. price_pro_monthly).
-- Populate these values from the Stripe Dashboard after creating Products + Prices.
ALTER TABLE subscription_tiers
    ADD COLUMN IF NOT EXISTS stripe_price_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_subscription_tiers_stripe_price
    ON subscription_tiers(stripe_price_id)
    WHERE stripe_price_id IS NOT NULL;

-- Stripe Coupon and Promotion Code IDs on billing_coupons
-- When a coupon is created in the admin panel, it is mirrored to Stripe as a Coupon object
-- and a Promotion Code object (the customer-facing code string).
ALTER TABLE billing_coupons
    ADD COLUMN IF NOT EXISTS stripe_coupon_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS stripe_promotion_code_id VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_billing_coupons_stripe_coupon
    ON billing_coupons(stripe_coupon_id)
    WHERE stripe_coupon_id IS NOT NULL;
