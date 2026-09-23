// Package entitlements is the single source of truth for what a tenant is
// allowed to do at runtime.
//
// It resolves a (tenant, billable_item) pair to an EffectiveEntitlement in two
// steps. First, three layers of tenant data, merged in order:
//
//  1. tenant_entitlements  — an active, non-expired per-tenant override
//  2. tier_entitlements    — what the tenant's subscription tier (plan) includes
//  3. billable_items.default_value — conservative fallback
//
// Then the licence step (license.go), which reads the install's one
// platform_license row and decides what the tenant rows are allowed to mean:
//
//   - no licence (Core), or an expired one: edition-gated capabilities are off,
//     whatever the tenant rows say; everything else is as resolved;
//   - Enterprise: gated capabilities the licence covers are on for every tenant
//     unless an override switches a tenant off, and capacity is unlimited
//     unless an override caps it — plans play no part;
//   - MSP: the tenant rows stand, so the MSP's plans decide.
//
// Callers reach for helpers like IsEnabled, GetQuantity, and CheckCap rather
// than poking at jsonb shapes themselves. Those helpers handle every kind
// (boolean, numeric_cap, numeric_metered, enum_choice) the catalog defines.
//
// Onboarding-state tenants (no subscription_tier_id) resolve every item to the
// default_value with Source=default before the licence step. The legacy
// LimitEnforcementService's "no tier → allow" carve-out for UNGATED
// capabilities is preserved at the shim layer (shared/services), not in this
// package, so direct callers of the resolver always see deterministic values.
//
// This package is the data layer the rest of the platform reads from. It
// must not import service-specific packages (no compliance-engine, no
// auth-service); it only depends on database/sql and the standard library.
package entitlements
