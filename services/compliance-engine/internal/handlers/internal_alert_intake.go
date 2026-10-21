package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	sharedseverity "github.com/vistasecurity/vistaplatform/shared/severity"
)

// The HTTP rail for alerts.raise.
//
// Any service raises an alert by publishing an events.AlertRaiseEvent onto
// alerts.raise, which AlertSubscriber hands to AlertEngineService.Raise. When
// NATS cannot carry the event, the producer POSTs the same event here instead
// (shared/dcim/changenotify's FallbackPublisher is the first such producer),
// so a NATS outage costs latency, not the notification.
//
// HMAC-only: a signed service call that names its tenant in the signed
// X-Tenant-ID header. A user JWT does not pass, and the event must be for the
// signed tenant, so a call signed for one tenant cannot raise into another.
// The route is under compliance-engine's internal prefix, which the gateway
// denies at the edge (standards/service-registry.yaml internal_prefixes).
//
// It is exactly the subject's surface, no more: Raise, never RaisePolicyRung,
// so an event arriving over HTTP can no more claim policy-rung status than
// one arriving over NATS.

// alertRaiser is the engine behind the route; *services.AlertEngineService in
// production, a stub in the contract test.
type alertRaiser interface {
	Raise(ctx context.Context, ev events.AlertRaiseEvent) (services.RaiseOutcome, error)
}

// alertIntakeMaxBody bounds one event. An event is a title, a message and a
// small metadata map; anything near this is not one.
const alertIntakeMaxBody = 256 << 10

// RegisterInternalAlertIntake mounts POST <api>/compliance-engine/internal/alerts/raise
// on api (the /api/v1 group), gated by a signed service call.
func RegisterInternalAlertIntake(api *gin.RouterGroup, internalSecret string, engine alertRaiser) {
	grp := api.Group("/compliance-engine/internal", RequireSignedServiceCall(internalSecret))
	grp.POST("/alerts/raise", raiseAlertHandler(engine))
}

// RequireSignedServiceCall admits an HMAC-signed service-to-service call that
// names one tenant in its signed X-Tenant-ID header and refuses everything
// else. An empty secret refuses every request — fail closed, never open.
func RequireSignedServiceCall(internalSecret string) gin.HandlerFunc {
	var verifier *serviceauth.Verifier
	if strings.TrimSpace(internalSecret) != "" {
		verifier = serviceauth.NewVerifier(internalSecret)
	}
	return func(c *gin.Context) {
		if verifier == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "internal authentication not configured"})
			return
		}
		if !verifier.Verify(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "a signed service call is required"})
			return
		}
		tenantID, err := uuid.Parse(strings.TrimSpace(c.GetHeader(serviceauth.HeaderTenantID)))
		if err != nil || tenantID == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID must name the tenant the call is for"})
			return
		}
		c.Set("isInternalCall", true)
		c.Set("tenantID", tenantID)
		c.Next()
	}
}

func raiseAlertHandler(engine alertRaiser) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, _ := c.Get("tenantID")
		signed, _ := tenantID.(uuid.UUID)

		var ev events.AlertRaiseEvent
		if err := json.NewDecoder(io.LimitReader(c.Request.Body, alertIntakeMaxBody)).Decode(&ev); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "body must be one alerts.raise event: " + err.Error()})
			return
		}
		if ev.TenantID == uuid.Nil {
			ev.TenantID = signed
		}
		if ev.TenantID != signed {
			c.JSON(http.StatusBadRequest, gin.H{"error": "the event's tenant_id is not the signed X-Tenant-ID"})
			return
		}
		if strings.TrimSpace(ev.AlertType) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "alert_type is required"})
			return
		}
		if _, err := sharedseverity.Parse(ev.Severity); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		outcome, err := engine.Raise(c.Request.Context(), ev)
		if err != nil {
			log.Printf("[AlertIntake] raise over HTTP failed (type=%s tenant=%s): %v", ev.AlertType, ev.TenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "the alert could not be raised"})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"outcome": string(outcome)})
	}
}
