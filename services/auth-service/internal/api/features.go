package api

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// knownFeatures is the canonical list of feature flags the platform recognises.
// Add a flag here when a new gated feature is introduced; the response always
// includes every entry so the frontend can rely on a stable shape.
//
// Note on marketing-only flags: the subscription_tiers.features JSONB column
// also carries display-only flags (sso, custom_branding, ai_insights,
// priority_support, reporting_enabled, dedicated_success_manager). Those
// appear on plan-comparison-cards and tier-selection but are NOT enforced —
// they're hints to the buyer about what tier they're on, not gates on
// behaviour. To gate one, add it here and wire it through
// LimitEnforcementService.CheckFeatureAccess, then surface via useFeature()
// in the frontend.
// Keys that are edition-gated (see shared/entitlements.editionByItem) resolve
// to false on a Core deployment even when the tenant has no tier, so the
// frontend can gate purely on this map without a separate edition probe.
var knownFeatures = []string{
	"custom_policies",
	"threshold_overrides",
	"ot_active_probing",
	"ot_primary_lens",
	"cbom_signing",
	"sso_saml",
	"custom_branding",
	"cmdb_sync",
	"siem_export",
	"billing_portal",
}

// complianceFrameworkUsage carries the current active subscription count and
// the effective limit for the compliance_frameworks tier knob. A nil Limit
// serialises as JSON null and means unlimited.
type complianceFrameworkUsage struct {
	Current int  `json:"current"`
	Limit   *int `json:"limit"`
}

// getTenantFeaturesHandler resolves the current tenant's feature flags from
// (tier features) ∪ (active per-tenant overrides), plus any usage-bound limits
// the frontend needs to make UI gating decisions (e.g. disabling Subscribe at
// cap). Used by web-ui in addition to per-call RBAC.
//
// Thin wrapper around newTenantFeaturesHandler that constructs the production
// LimitEnforcementService from `db`. Kept as the public production entry
// point so router.go (and `cmd/main.go` upstream of it) is untouched. The
// inner factory takes the `limitChecker` interface (defined in
// auth_stores.go) so the contract test can substitute an in-memory stub
// without touching a database.
func getTenantFeaturesHandler(db *sql.DB) gin.HandlerFunc {
	return newTenantFeaturesHandler(sharedservices.NewLimitEnforcementService(db))
}

// newTenantFeaturesHandler is the testable factory behind
// getTenantFeaturesHandler. Production callers go through the db-typed
// wrapper above; the contract test calls this directly with a stub
// limitChecker.
func newTenantFeaturesHandler(limitSvc limitChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.GetString("tenantID")
		if tenantIDStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}
		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
			return
		}

		features := make(map[string]bool, len(knownFeatures))
		for _, name := range knownFeatures {
			ok, err := limitSvc.CheckFeatureAccess(tenantID, name)
			if err != nil {
				log.Printf("getTenantFeaturesHandler: CheckFeatureAccess(%s) for tenant %s failed: %v", name, tenantID, err)
				features[name] = false
				continue
			}
			features[name] = ok
		}

		// Compliance framework usage drives the tier-aware Subscribe affordance.
		// On error, omit from the response rather than fail the whole call —
		// the UI degrades to "always enabled" which matches old behaviour.
		limits := gin.H{}
		if current, limit, err := limitSvc.GetComplianceFrameworkUsage(tenantID); err == nil {
			limits["compliance_frameworks"] = complianceFrameworkUsage{
				Current: current,
				Limit:   limit,
			}
		} else {
			log.Printf("getTenantFeaturesHandler: GetComplianceFrameworkUsage for tenant %s failed: %v", tenantID, err)
		}

		c.JSON(http.StatusOK, gin.H{
			"features": features,
			"limits":   limits,
		})
	}
}
