package handlers

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// logAuditActivity is a helper function to log audit activities
func logAuditActivity(c *gin.Context, eventType, eventCategory, action string, resourceType *string, resourceID *uuid.UUID, oldValues, newValues map[string]interface{}, changedFields []string, metadata map[string]interface{}) {
	// Get audit middleware from context (set by middleware)
	// For now, we'll get it from a global or pass it through
	// This is a simplified version - in production, you'd get it from context or dependency injection

	userID, _ := c.Get("userID")
	tenantID, _ := c.Get("tenantID")
	email, _ := c.Get("email")
	role, _ := c.Get("role")

	userType := "tenant"
	if role != nil {
		roleStr := role.(string)
		if strings.Contains(roleStr, "platform") || strings.Contains(roleStr, "admin") {
			userType = "platform"
		}
	}

	ipAddress := c.ClientIP()
	if ipAddress == "" {
		ipAddress = c.Request.RemoteAddr
	}

	requestID, _ := c.Get("request_id")
	var requestIDStr *string
	if requestID != nil {
		reqID := requestID.(string)
		requestIDStr = &reqID
	}

	userAgent := c.Request.UserAgent()

	logEntry := &auditmiddleware.ActivityLogRequest{
		TenantID:       getUUIDPtr(tenantID),
		UserID:         getUUIDPtr(userID),
		UserType:       userType,
		UserEmail:      getStringPtr(email),
		EventType:      eventType,
		EventCategory:  eventCategory,
		Action:         action,
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		OldValues:      oldValues,
		NewValues:      newValues,
		ChangedFields:  changedFields,
		IPAddress:      &ipAddress,
		UserAgent:      &userAgent,
		RequestID:      requestIDStr,
		Success:        c.Writer.Status() < 400,
		OccurredAt:     time.Now(),
		ComplianceTags: []string{}, // Will be assigned by audit-service
		Metadata:       metadata,
	}

	// Get audit middleware from Gin context (if stored)
	if auditMW, exists := c.Get("audit_middleware"); exists {
		if mw, ok := auditMW.(*auditmiddleware.Middleware); ok {
			_ = mw.LogActivity(context.Background(), logEntry)
		}
	}
}

// auditProposalDecision records a HUMAN decision on a proposal — a merge, a
// relationship edge, a class (security review X.5, X5-09).
//
// These routes had no explicit audit entry. The global LogRequest middleware
// still recorded method, path, status and actor for all of them, so nothing was
// unaudited — but the record said "POST /approvals/classes/:id/accept, 200" and
// not which class was applied to which asset, which is the only part anyone
// reviewing an approval queue afterwards needs.
//
// The asymmetry is what made it worth closing: the MACHINE path
// (AssetService.auditAutoAcceptedMerge) writes a rich record naming the score,
// the model, the candidates and the reason, precisely because nobody is there
// to ask. The human path — which is the one with a person who can be asked, and
// therefore the one an auditor will actually be reconstructing — wrote less.
//
// Best-effort, like the machine path: a decision that committed and an audit
// event that did not send is bad; refusing the decision afterwards would be
// worse, because it already happened.
func auditProposalDecision(c *gin.Context, eventType, resourceType string, resourceID uuid.UUID, metadata map[string]any) {
	rt := resourceType
	logAuditActivity(c, eventType, auditmiddleware.EventCategoryAsset, decisionAction(eventType),
		&rt, &resourceID, nil, nil, nil, metadata)
}

// decisionAction is the `action` verb, derived from the event type's last
// segment so the two cannot disagree.
func decisionAction(eventType string) string {
	if i := strings.LastIndex(eventType, "."); i >= 0 && i+1 < len(eventType) {
		return eventType[i+1:]
	}
	return eventType
}

// Helper functions
func getUUIDPtr(value interface{}) *uuid.UUID {
	if value == nil {
		return nil
	}
	if id, ok := value.(uuid.UUID); ok {
		return &id
	}
	if idStr, ok := value.(string); ok {
		if id, err := uuid.Parse(idStr); err == nil {
			return &id
		}
	}
	return nil
}

func getStringPtr(value interface{}) *string {
	if value == nil {
		return nil
	}
	if str, ok := value.(string); ok && str != "" {
		return &str
	}
	return nil
}
