package handlers

// HTTP half of explicit external targets ( W5.13b): how a target
// authorization verdict reaches the caller, and the audit record of a
// confirmed external scan.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// AuditEventExternalTargets is the audit event a confirmed external scan
// writes.
const AuditEventExternalTargets = "discovery.job.external_targets_confirmed"

// writeTargetAuthorizationError answers a target-authorization refusal with a
// status and body a client can act on, and reports whether it did. Each shape
// carries a machine-readable `error` code, a sentence in `message`, and the
// targets concerned:
//
//	400 targets_refused              refused_targets: [{target, reason}] — never scannable as entered
//	403 external_targets_disabled    external_targets: [{target, addresses}] — the operator turned it off
//	422 external_targets_unconfirmed external_targets: [{target, addresses}] — resend with the flag
//
// Before this, every refusal was the generic "failed to create job", so a
// person could not tell a typo from a reserved range from a missing segment.
func writeTargetAuthorizationError(c *gin.Context, err error) bool {
	if refused, ok := dispatchguard.IsRefusedTargetsError(err); ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":           dispatchguard.CodeTargetsRefused,
			"message":         refused.Error(),
			"refused_targets": refused.Targets,
		})
		return true
	}
	if external, ok := dispatchguard.IsExternalTargetsError(err); ok {
		status := http.StatusUnprocessableEntity
		if external.Code == dispatchguard.CodeExternalTargetsDisabled {
			status = http.StatusForbidden
		}
		c.JSON(status, gin.H{
			"error":            external.Code,
			"message":          external.Error(),
			"external_targets": external.Targets,
		})
		return true
	}
	if errors.Is(err, dispatchguard.ErrDenied) {
		c.JSON(http.StatusBadRequest, gin.H{"error": dispatchguard.CodeTargetsRefused, "message": err.Error()})
		return true
	}
	return false
}

// auditExternalTargets records who confirmed which external targets, when,
// and the addresses they resolved to. It goes through the same audit
// middleware every request in this service already uses (main.go puts it on
// the context), as an explicit activity rather than the generic request line,
// because the request line says "POST /discovery/jobs 202" and not what was
// scanned.
//
// Best-effort like every other explicit audit call: the job exists and the
// scan will run; refusing it now because the audit sink hiccupped would be
// worse. The failure is logged loudly instead.
func auditExternalTargets(c *gin.Context, tenantID, userID string, job *models.DiscoveryJob) {
	mwAny, ok := c.Get("audit_middleware")
	mw, typed := mwAny.(*auditmiddleware.Middleware)
	if !ok || !typed || mw == nil {
		log.Printf("[DiscoveryHandler] AUDIT NOT WRITTEN: job %s scans %d external target(s) but no audit middleware is wired", job.ID, len(job.ExternalTargets))
		return
	}
	resourceType := "discovery_job"
	var resourceID *uuid.UUID
	if id, err := uuid.Parse(job.ID); err == nil {
		resourceID = &id
	}
	var tenant, user *uuid.UUID
	if id, err := uuid.Parse(tenantID); err == nil {
		tenant = &id
	}
	if id, err := uuid.Parse(userID); err == nil {
		user = &id
	}
	var email *string
	if e := c.GetString(sharedmw.CtxKeyEmail); e != "" {
		email = &e
	}
	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	targets := make([]string, 0, len(job.ExternalTargets))
	for _, t := range job.ExternalTargets {
		targets = append(targets, t.Target)
	}
	entry := &auditmiddleware.ActivityLogRequest{
		TenantID:      tenant,
		UserID:        user,
		UserType:      "tenant",
		UserEmail:     email,
		EventType:     AuditEventExternalTargets,
		EventCategory: auditmiddleware.EventCategoryDiscovery,
		Action:        "scan_external_targets",
		ResourceType:  &resourceType,
		ResourceID:    resourceID,
		IPAddress:     &ip,
		UserAgent:     &ua,
		Success:       true,
		OccurredAt:    time.Now(),
		Metadata: map[string]interface{}{
			"external_targets": job.ExternalTargets,
			"targets":          targets,
			"execution_mode":   job.ExecutionMode,
		},
	}
	if err := mw.LogActivity(context.Background(), entry); err != nil {
		log.Printf("[DiscoveryHandler] AUDIT NOT WRITTEN for job %s external targets: %v", job.ID, err)
	}
}
