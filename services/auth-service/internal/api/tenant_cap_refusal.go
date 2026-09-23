package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// TenantCapRefusedEventType is the audit event for a tenant creation refused
// by the MSP soft cap (edition-licensing spec §3: cap refusals are audited).
const TenantCapRefusedEventType = "tenant.create_refused_license_limit"

// RespondTenantCapRefused answers a signup refused by the MSP soft cap.
//
// Every signup route that can create a tenant (POST /auth/register,
// /auth/register/complete, and the Enterprise platform-SSO completion) answers
// through here, so the split between the two audiences cannot drift per route:
//
//   - the anonymous visitor gets 409 with the generic PublicMessage — no
//     tenant counts, no vendor name;
//   - the MSP operator gets the counts in the audit trail (untenanted: the
//     tenant was never created), flagged for attention. (createTenant has
//     already written them to the service log.)
//
// The signup's email is deliberately not recorded: the person was turned
// away, and nothing about the refusal depends on who they are.
func RespondTenantCapRefused(c *gin.Context, capErr *entitlements.TenantCapExceededError) {
	if rawMW, exists := c.Get("audit_middleware"); exists {
		if mw, ok := rawMW.(*audithelpers.Middleware); ok {
			msg := capErr.Error()
			resType := "tenant"
			ip := c.ClientIP()
			ua := c.Request.UserAgent()
			_ = mw.LogActivity(c.Request.Context(), &audithelpers.ActivityLogRequest{
				UserType:          "tenant",
				EventType:         TenantCapRefusedEventType,
				EventCategory:     "tenant",
				Action:            "create",
				ResourceType:      &resType,
				Success:           false,
				ErrorMessage:      &msg,
				IPAddress:         &ip,
				UserAgent:         &ua,
				RequiresAttention: true,
				Metadata: map[string]interface{}{
					"licensed_tenants": capErr.Licensed,
					"current_tenants":  capErr.Current,
					"route":            c.FullPath(),
				},
				OccurredAt: time.Now(),
			})
		}
	}

	c.JSON(http.StatusConflict, gin.H{"error": capErr.PublicMessage()})
}
