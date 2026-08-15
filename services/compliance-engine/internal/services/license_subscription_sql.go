package services

// Predicates for tenant_framework_licenses rows that grant access:
// active status and not past subscription_expires_at (NULL = perpetual).
const (
	sqlActiveSubscription    = `subscription_status = 'active' AND (subscription_expires_at IS NULL OR subscription_expires_at > NOW())`
	sqlActiveSubscriptionTfl = `tfl.subscription_status = 'active' AND (tfl.subscription_expires_at IS NULL OR tfl.subscription_expires_at > NOW())`
)

// licensedFindingScopeSQL is the READ GATE on materialized findings.
//
// The engine deliberately persists findings for EVERY published framework, not
// only activated ones (ADR-0015, evaluation_engine.go): per-asset reconcile
// bounds the write volume, and preview scores for unactivated frameworks derive
// uniformly from the same rows. ADR-0015 pairs that with "detailed drill-down is
// the reward for activation, enforced at the read/UI layer" — this is that layer.
// It did not exist, and its absence was visible in the product: a tenant with ONE
// activated framework saw four on Findings → By Framework, a Dashboard "5
// Critical" sourced entirely from an unactivated framework, and a Posture page
// whose Top Exposures panel disagreed with the control grid beside it (the grid
// reads licensed-only /frameworks/context, the panel read ungated findings).
//
// Two ways a control earns visibility:
//   - it belongs to a platform framework the tenant has ACTIVELY licensed, or
//   - it belongs to one of the tenant's own custom policies (tenant_frameworks),
//     which are authored by the tenant and need no license.
//
// A finding whose control resolves to neither is excluded — the same treatment
// GetFindingsByControl already gave orphaned controls ("an exposure needs a
// framework home"), now applied to unactivated ones too.
//
// NOT for the evaluation, scoring, or preview paths: those must see every
// published framework or preview scores and reconcile convergence break. Callers
// are the tenant-facing list/aggregate readers only.
//
// alias is the compliance_findings alias in the caller's query; tenantParam is
// the placeholder already bound to the tenant id (always $1 in these queries).
func licensedFindingScopeSQL(alias, tenantParam string) string {
	return `(
		EXISTS (
			SELECT 1
			FROM platform_framework_controls pfc
			JOIN tenant_framework_licenses tfl ON tfl.platform_framework_id = pfc.framework_id
			WHERE pfc.id = ` + alias + `.control_id
			  AND tfl.tenant_id = ` + tenantParam + `
			  AND ` + sqlActiveSubscriptionTfl + `
		)
		OR EXISTS (
			SELECT 1
			FROM tenant_framework_controls tfc
			JOIN tenant_frameworks tf ON tf.id = tfc.framework_id
			WHERE tfc.id = ` + alias + `.control_id
			  AND tf.tenant_id = ` + tenantParam + `
		)
	)`
}
