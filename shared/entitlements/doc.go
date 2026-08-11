// Package entitlements is the single source of truth for what a tenant is
// allowed to do at runtime.
//
// It resolves a (tenant, billable_item) pair to an EffectiveEntitlement by
// merging three layers in order:
//
//  1. tenant_entitlements  — an active, non-expired per-tenant override
//  2. tier_entitlements    — what the tenant's subscription tier includes
//  3. billable_items.default_value — conservative fallback
//
// Callers reach for helpers like IsEnabled, GetQuantity, and CheckCap rather
// than poking at jsonb shapes themselves. Those helpers handle every kind
// (boolean, numeric_cap, numeric_metered, enum_choice) the catalog defines.
//
// Onboarding-state tenants (no subscription_tier_id) intentionally resolve
// every item to the default_value with Source=default. The legacy
// LimitEnforcementService had a "no tier → allow everything" carve-out;
// that carve-out is preserved at the shim layer (shared/services), not in
// this package, so direct callers of the resolver always see deterministic
// values.
//
// This package is the data layer the rest of the platform reads from. It
// must not import service-specific packages (no compliance-engine, no
// auth-service); it only depends on database/sql and the standard library.
package entitlements
