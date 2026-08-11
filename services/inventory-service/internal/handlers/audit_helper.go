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
