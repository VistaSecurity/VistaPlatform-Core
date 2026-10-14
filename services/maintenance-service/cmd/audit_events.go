package main

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// sharedAuditor records the maintenance write verbs' named events
// (maintenance.backup.created|downloaded|deleted, spec §2) through the same
// audit middleware attachAuditLogging mounts, attributed to the platform user
// on the request. They sit beside the request-level entry for the same call:
// that one says a request happened, this one says what it did (and, for a
// download, how many bytes left).
type sharedAuditor struct{}

func (sharedAuditor) Record(c *gin.Context, ev backups.AuditEvent) {
	mw, ok := auditmiddleware.ExtractAuditMiddleware(c)
	if !ok || mw == nil {
		return
	}
	entry := &auditmiddleware.ActivityLogRequest{
		EventType:     ev.EventType,
		EventCategory: ev.EventCategory,
		Action:        ev.Action,
		UserType:      "platform",
		Success:       ev.Success,
		Metadata:      ev.Metadata,
	}
	rt := "platform_backup"
	entry.ResourceType = &rt
	if id, ok := sharedmw.GetUserIDFromContext(c); ok {
		entry.UserID = &id
	}
	if email := sharedmw.GetEmailFromContext(c); email != "" {
		entry.UserEmail = &email
	}
	ip := c.ClientIP()
	entry.IPAddress = &ip
	if ev.ResourceID != "" {
		if rid, err := uuid.Parse(ev.ResourceID); err == nil {
			entry.ResourceID = &rid
		}
	}
	_ = mw.LogActivity(c.Request.Context(), entry)
}
