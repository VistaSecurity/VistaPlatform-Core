package middleware

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
)

// featureChecker is the slice of LimitEnforcementService this middleware needs.
// Declared as an interface so tests can substitute a stub without a database.
type featureChecker interface {
	CheckFeatureAccess(tenantID uuid.UUID, feature string) (bool, error)
}

// RequireFeature gates a route on a tenant's entitlement to a billable item.
//
// This is the RUNTIME half of the two-gate open-core model. The other half is
// the build boundary: Enterprise code lives under services/<svc>/ee/ and is
// absent from a Core build, so in Core these routes are never mounted at all.
// Both gates matter — the build boundary decides which code exists, this decides
// which tenant may reach it. An Enterprise binary still has to refuse a tenant
// whose subscription does not include the capability.
//
// Responds 402 Payment Required, not 403. The caller is authenticated and
// authorized; what is missing is an entitlement. 403 would tell an operator to
// go fix RBAC, which would waste their time. 402 is already this repo's idiom
// for the same situation (inventory-service asset caps, cbom-service download
// formats).
//
// Fails CLOSED. If the entitlement lookup errors we deny, because this guards
// paid capability and the request is a write or an external-system call in every
// current caller. That is the opposite of the branding gate, which fails open —
// there, a false denial locks a paying tenant out of its own logo, and the
// downside of a wrongly-permitted colour change is nil. Match the failure mode
// to what breaks, not to a house style.
func RequireFeature(db *sql.DB, feature string) gin.HandlerFunc {
	return requireFeatureWithChecker(sharedservices.NewLimitEnforcementService(db), feature)
}

// requireFeatureWithChecker is the injectable form used by the tests.
func requireFeatureWithChecker(svc featureChecker, feature string) gin.HandlerFunc {
	// Guard against wiring a route to a key that no edition grants. Such a key
	// resolves to ErrUnknownItem, every gate denies, and the route becomes
	// permanently unreachable — a silent outage that looks like a bug in the
	// feature rather than in its registration.
	if !entitlements.IsEditionGated(feature) {
		log.Printf("RequireFeature: %q is not an edition-gated item — the route will be reachable on every edition, which is probably not what was intended", feature)
	}

	return func(c *gin.Context) {
		tenantID, ok := GetTenantIDFromContext(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
			return
		}

		allowed, err := svc.CheckFeatureAccess(tenantID, feature)
		if err != nil {
			log.Printf("RequireFeature(%s): entitlement lookup failed for tenant %s: %v", feature, tenantID, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify entitlement"})
			return
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{
				"error":   "This capability is not included in your subscription",
				"feature": feature,
			})
			return
		}
		c.Next()
	}
}
