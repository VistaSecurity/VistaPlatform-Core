package handlers

import (
	"context"
	"fmt"
	stdlog "log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// activityLogService is the slice of *services.ActivityLogService the activity
// handlers depend on. Declaring it as an interface (the concrete service still
// satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
type activityLogService interface {
	LogActivity(ctx context.Context, logEntry *models.ActivityLog) error
	AssignComplianceTags(eventType, eventCategory string) []string
	GetActivityLogs(ctx context.Context, filters models.ActivityLogFilters) ([]models.ActivityLog, int, error)
	GetActivityLogByID(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) (*models.ActivityLog, error)
	GetActivityLogsSummary(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetActivityLogsByUser(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetActivityLogsByResource(ctx context.Context, resourceType string, resourceID uuid.UUID, tenantID *uuid.UUID, startDate, endDate time.Time) ([]models.ActivityLog, int, error)
}

type ActivityLogHandler struct {
	service      activityLogService
	alertService *services.AlertService
	// siemService is the Enterprise SIEM tee (see edition.go). Nil in a Core
	// build — and nil in Enterprise too until an exporter is constructed — so
	// every use of it is nil-guarded. Interface-typed rather than a concrete
	// *SIEMService precisely so the implementation can live outside Core.
	siemService SIEMForwarder
}

func NewActivityLogHandler(service *services.ActivityLogService) *ActivityLogHandler {
	return &ActivityLogHandler{service: service}
}

// NewActivityLogHandlerWithMonitoring wires the alert evaluator and, in an
// Enterprise build, the SIEM forwarder. Pass a nil siemService for Core: audit
// logging is unaffected, the events are simply not forwarded anywhere.
func NewActivityLogHandlerWithMonitoring(service *services.ActivityLogService, alertService *services.AlertService, siemService SIEMForwarder) *ActivityLogHandler {
	return &ActivityLogHandler{
		service:      service,
		alertService: alertService,
		siemService:  siemService,
	}
}

// LogActivity handles POST /api/v1/audit-service/activity-logs (internal use by middleware)
func (h *ActivityLogHandler) LogActivity(c *gin.Context) {
	var logEntry models.ActivityLog
	if err := c.ShouldBindJSON(&logEntry); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid activity log"})
		return
	}

	// Assign compliance tags if not provided
	if len(logEntry.ComplianceTags) == 0 {
		logEntry.ComplianceTags = h.service.AssignComplianceTags(logEntry.EventType, logEntry.EventCategory)
	}

	err := h.service.LogActivity(c.Request.Context(), &logEntry)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log activity"})
		return
	}

	// Evaluate alerts (non-blocking)
	if h.alertService != nil {
		go func() {
			eventMap := map[string]interface{}{
				"id":             logEntry.ID,
				"event_type":     logEntry.EventType,
				"event_category": logEntry.EventCategory,
				"action":         logEntry.Action,
				"success":        logEntry.Success,
				"user_id":        logEntry.UserID,
				"tenant_id":      logEntry.TenantID,
				"occurred_at":    logEntry.OccurredAt,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			h.alertService.EvaluateEvent(ctx, eventMap)
		}()
	}

	// Send to SIEM integrations (non-blocking)
	if h.siemService != nil {
		go func() {
			eventMap := map[string]interface{}{
				"id":              logEntry.ID,
				"event_type":      logEntry.EventType,
				"event_category":  logEntry.EventCategory,
				"action":          logEntry.Action,
				"success":         logEntry.Success,
				"user_id":         logEntry.UserID,
				"tenant_id":       logEntry.TenantID,
				"compliance_tags": logEntry.ComplianceTags,
				"occurred_at":     logEntry.OccurredAt,
			}
			h.siemService.SendEvent(c.Request.Context(), eventMap)
		}()
	}

	c.JSON(http.StatusCreated, gin.H{"id": logEntry.ID, "message": "Activity logged successfully"})
}

// GetActivityLogs handles GET /api/v1/audit-service/activity-logs
func (h *ActivityLogHandler) GetActivityLogs(c *gin.Context) {
	filters := models.ActivityLogFilters{
		Page:      1,
		PageSize:  50,
		SortBy:    "occurred_at",
		SortOrder: "desc", // Standardized to lowercase
	}

	// Get user type and apply appropriate scoping
	userType := middleware.GetUserType(c)

	// Parse tenant_id from query (platform users can filter by tenant)
	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
			filters.TenantID = &tenantID
		}
	}

	// Tenant users are automatically scoped to their own tenant
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		// Override any tenant_id filter with the user's actual tenant
		filters.TenantID = tenantID
	}

	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			filters.UserID = &userID
		}
	}

	if userType := c.Query("user_type"); userType != "" {
		filters.UserType = &userType
	}

	if eventTypes := c.QueryArray("event_type"); len(eventTypes) > 0 {
		filters.EventType = eventTypes
	}

	if categories := c.QueryArray("event_category"); len(categories) > 0 {
		filters.EventCategory = categories
	}

	if actions := c.QueryArray("action"); len(actions) > 0 {
		filters.Action = actions
	}

	if resourceType := c.Query("resource_type"); resourceType != "" {
		filters.ResourceType = &resourceType
	}

	if resourceIDStr := c.Query("resource_id"); resourceIDStr != "" {
		if resourceID, err := uuid.Parse(resourceIDStr); err == nil {
			filters.ResourceID = &resourceID
		}
	}

	if complianceTags := c.QueryArray("compliance_tag"); len(complianceTags) > 0 {
		filters.ComplianceTags = complianceTags
	}

	if successStr := c.Query("success"); successStr != "" {
		if success, err := strconv.ParseBool(successStr); err == nil {
			filters.Success = &success
		}
	}

	if requiresAttentionStr := c.Query("requires_attention"); requiresAttentionStr != "" {
		if requiresAttention, err := strconv.ParseBool(requiresAttentionStr); err == nil {
			filters.RequiresAttention = &requiresAttention
		}
	}

	// Filter for impersonated actions
	if impersonationStr := c.Query("impersonation"); impersonationStr != "" {
		if impersonation, err := strconv.ParseBool(impersonationStr); err == nil {
			filters.Impersonation = &impersonation
		}
	}

	// Filter by tags
	if tags := c.QueryArray("tag"); len(tags) > 0 {
		filters.Tags = tags
	}

	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filters.StartDate = &startDate
		}
	}

	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filters.EndDate = &endDate
		}
	}

	if search := c.Query("search"); search != "" {
		filters.Search = &search
	}

	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			filters.Page = page
		}
	}

	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 {
			filters.PageSize = pageSize
		}
	}

	if sortBy := c.Query("sort_by"); sortBy != "" {
		filters.SortBy = sortBy
	}

	if sortOrder := c.Query("sort_order"); sortOrder != "" {
		// Normalize to lowercase for consistency
		filters.SortOrder = strings.ToLower(sortOrder)
	}

	logs, total, err := h.service.GetActivityLogs(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve activity logs"})
		return
	}

	totalPages := (total + filters.PageSize - 1) / filters.PageSize

	c.JSON(http.StatusOK, gin.H{
		"logs": logs,
		"pagination": gin.H{
			"page":        filters.Page,
			"page_size":   filters.PageSize,
			"total":       total,
			"total_pages": totalPages,
			"has_next":    filters.Page < totalPages,
			"has_prev":    filters.Page > 1,
		},
	})
}

// GetActivityLogByID handles GET /api/v1/audit-service/activity-logs/:id
func (h *ActivityLogHandler) GetActivityLogByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid activity log ID"})
		return
	}

	scope, ok := byIDTenantScope(c)
	if !ok {
		return
	}
	log, err := h.service.GetActivityLogByID(c.Request.Context(), id, scope)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Activity log not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"log": log})
}

// GetActivityLogsSummary handles GET /api/v1/audit-service/activity-logs/summary
func (h *ActivityLogHandler) GetActivityLogsSummary(c *gin.Context) {
	// Parse date range
	now := time.Now()
	startDate := now.AddDate(0, 0, -30) // Default: last 30 days
	endDate := now

	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			startDate = parsed
		}
	}

	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			endDate = parsed
		}
	}

	// Get user type and apply appropriate scoping
	userType := middleware.GetUserType(c)

	// Parse tenant filter (platform users can specify tenant)
	var tenantID *uuid.UUID
	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if id, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &id
		}
	}

	// Tenant users are automatically scoped to their own tenant
	if userType == middleware.UserTypeTenant {
		tenantID = middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
	}

	summary, err := h.service.GetActivityLogsSummary(c.Request.Context(), tenantID, startDate, endDate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate summary"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"summary": summary})
}

// GetActivityLogsByUser handles GET /api/v1/audit-service/activity-logs/by-user
func (h *ActivityLogHandler) GetActivityLogsByUser(c *gin.Context) {
	userIDStr := c.Query("user_id")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id query parameter required"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id"})
		return
	}

	// Tenant scoping: constrain tenant callers to their own tenant so a
	// client-supplied user_id can't read another tenant's audit summary; nil for
	// platform callers (legitimately cross-tenant). 403 already written on !ok.
	scope, ok := byIDTenantScope(c)
	if !ok {
		return
	}

	// Parse date range
	now := time.Now()
	startDate := now.AddDate(0, 0, -30)
	endDate := now

	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			startDate = parsed
		}
	}

	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			endDate = parsed
		}
	}

	summary, err := h.service.GetActivityLogsByUser(c.Request.Context(), userID, scope, startDate, endDate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user activity summary"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"summary": summary})
}

// GetActivityLogsByResource handles GET /api/v1/audit-service/activity-logs/by-resource
func (h *ActivityLogHandler) GetActivityLogsByResource(c *gin.Context) {
	resourceType := c.Query("resource_type")
	resourceIDStr := c.Query("resource_id")

	if resourceType == "" || resourceIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource_type and resource_id query parameters required"})
		return
	}

	resourceID, err := uuid.Parse(resourceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource_id"})
		return
	}

	// Tenant scoping: constrain tenant callers to their own tenant so a
	// client-supplied resource_id can't read another tenant's audit trail; nil
	// for platform callers (legitimately cross-tenant). 403 already written on !ok.
	scope, ok := byIDTenantScope(c)
	if !ok {
		return
	}

	// Parse date range
	now := time.Now()
	startDate := now.AddDate(0, 0, -30)
	endDate := now

	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			startDate = parsed
		}
	}

	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			endDate = parsed
		}
	}

	logs, total, err := h.service.GetActivityLogsByResource(c.Request.Context(), resourceType, resourceID, scope, startDate, endDate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get resource activity logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":          logs,
		"total":         total,
		"resource_type": resourceType,
		"resource_id":   resourceID,
	})
}

// QueryActivityLogs handles POST /api/v1/audit-service/activity-logs/query
func (h *ActivityLogHandler) QueryActivityLogs(c *gin.Context) {
	var req struct {
		Filters models.ActivityLogFilters `json:"filters"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Default pagination when the body omits it — Page/PageSize feed the
	// totalPages division below, so a zero PageSize would panic (divide by
	// zero). Mirrors the defaults GetActivityLogs applies.
	if req.Filters.Page < 1 {
		req.Filters.Page = 1
	}
	if req.Filters.PageSize < 1 || req.Filters.PageSize > 100 {
		req.Filters.PageSize = 50
	}

	// Get user type and apply appropriate scoping
	userType := middleware.GetUserType(c)

	// Tenant users are automatically scoped to their own tenant
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		req.Filters.TenantID = tenantID
	}

	logs, total, err := h.service.GetActivityLogs(c.Request.Context(), req.Filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query activity logs"})
		return
	}

	totalPages := (total + req.Filters.PageSize - 1) / req.Filters.PageSize

	c.JSON(http.StatusOK, gin.H{
		"logs": logs,
		"pagination": gin.H{
			"page":        req.Filters.Page,
			"page_size":   req.Filters.PageSize,
			"total":       total,
			"total_pages": totalPages,
			"has_next":    req.Filters.Page < totalPages,
			"has_prev":    req.Filters.Page > 1,
		},
	})
}

// ExportActivityLogs handles GET /api/v1/audit-service/activity-logs/export
func (h *ActivityLogHandler) ExportActivityLogs(c *gin.Context) {
	format := c.DefaultQuery("format", "json")
	if format != "json" && format != "csv" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format. Supported: json, csv"})
		return
	}

	// Parse filters (same as GetActivityLogs)
	filters := models.ActivityLogFilters{
		Page:      1,
		PageSize:  10000, // Large page size for export
		SortBy:    "occurred_at",
		SortOrder: "DESC",
	}

	// Get user type and apply appropriate scoping
	userType := middleware.GetUserType(c)

	// Parse all filter parameters (same as GetActivityLogs)
	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
			filters.TenantID = &tenantID
		}
	}

	// Tenant users are automatically scoped to their own tenant
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		filters.TenantID = tenantID
	}
	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			filters.UserID = &userID
		}
	}
	if userType := c.Query("user_type"); userType != "" {
		filters.UserType = &userType
	}
	if eventTypes := c.QueryArray("event_type"); len(eventTypes) > 0 {
		filters.EventType = eventTypes
	}
	if categories := c.QueryArray("event_category"); len(categories) > 0 {
		filters.EventCategory = categories
	}
	if actions := c.QueryArray("action"); len(actions) > 0 {
		filters.Action = actions
	}
	if resourceType := c.Query("resource_type"); resourceType != "" {
		filters.ResourceType = &resourceType
	}
	if resourceIDStr := c.Query("resource_id"); resourceIDStr != "" {
		if resourceID, err := uuid.Parse(resourceIDStr); err == nil {
			filters.ResourceID = &resourceID
		}
	}
	if complianceTags := c.QueryArray("compliance_tag"); len(complianceTags) > 0 {
		filters.ComplianceTags = complianceTags
	}
	if successStr := c.Query("success"); successStr != "" {
		if success, err := strconv.ParseBool(successStr); err == nil {
			filters.Success = &success
		}
	}
	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filters.StartDate = &startDate
		}
	}
	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filters.EndDate = &endDate
		}
	}

	logs, _, err := h.service.GetActivityLogs(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export activity logs"})
		return
	}

	if format == "json" {
		c.JSON(http.StatusOK, gin.H{"logs": logs})
	} else {
		// CSV export
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=audit-logs-%s.csv", time.Now().Format("20060102-150405")))

		// Write CSV header. The response is already committed by this point, so
		// a write failure can only mean the client went away — log it and stop
		// rather than streaming the rest into a dead connection.
		if _, err := c.Writer.WriteString("ID,Occurred At,Tenant ID,User ID,User Type,User Email,Event Type,Event Category,Action,Resource Type,Resource ID,Success,Error Message,Compliance Tags\n"); err != nil {
			stdlog.Printf("[ActivityLog] CSV export aborted while writing header: %v", err)
			return
		}

		// Write CSV rows. Every cell goes through escapeCSV, which neutralizes
		// spreadsheet formula injection and quotes embedded commas/quotes.
		for _, log := range logs {
			if _, err := c.Writer.WriteString(strings.Join([]string{
				escapeCSV(log.ID.String()),
				escapeCSV(log.OccurredAt.Format(time.RFC3339)),
				escapeCSV(func() string {
					if log.TenantID != nil {
						return log.TenantID.String()
					}
					return ""
				}()),
				escapeCSV(func() string {
					if log.UserID != nil {
						return log.UserID.String()
					}
					return ""
				}()),
				escapeCSV(log.UserType),
				escapeCSV(func() string {
					if log.UserEmail != nil {
						return *log.UserEmail
					}
					return ""
				}()),
				escapeCSV(log.EventType),
				escapeCSV(log.EventCategory),
				escapeCSV(log.Action),
				escapeCSV(func() string {
					if log.ResourceType != nil {
						return *log.ResourceType
					}
					return ""
				}()),
				escapeCSV(func() string {
					if log.ResourceID != nil {
						return log.ResourceID.String()
					}
					return ""
				}()),
				escapeCSV(fmt.Sprintf("%t", log.Success)),
				escapeCSV(func() string {
					if log.ErrorMessage != nil {
						return *log.ErrorMessage
					}
					return ""
				}()),
				escapeCSV(func() string {
					if len(log.ComplianceTags) > 0 {
						return fmt.Sprintf("%v", log.ComplianceTags)
					}
					return ""
				}()),
			}, ",") + "\n"); err != nil {
				stdlog.Printf("[ActivityLog] CSV export aborted after a partial write: %v", err)
				return
			}
		}
	}
}

// escapeCSV neutralizes spreadsheet formula injection and quotes CSV-special
// characters. A leading =, +, -, @, tab, or CR makes Excel/Sheets execute the
// cell as a formula; audit values (user email, error message, resource type,
// etc.) are attacker-influenceable, so such cells are prefixed with an
// apostrophe to render as literal text. Mirrors the inventory-service
// crypto-risks export helper; for this export path.
func escapeCSV(s string) string {
	if s == "" {
		return ""
	}
	if c := s[0]; c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r' {
		s = "'" + s
	}
	needsQuotes := false
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' || c == '\r' {
			needsQuotes = true
			break
		}
	}
	if needsQuotes {
		escaped := ""
		for _, c := range s {
			if c == '"' {
				escaped += "\"\""
			} else {
				escaped += string(c)
			}
		}
		return "\"" + escaped + "\""
	}
	return s
}

// GetResourceAuditTrail handles GET /api/v1/audit-service/activity-logs/by-resource/:resource_type/:resource_id
// Returns complete audit trail for a specific resource
func (h *ActivityLogHandler) GetResourceAuditTrail(c *gin.Context) {
	resourceType := c.Param("resource_type")
	resourceIDStr := c.Param("resource_id")

	if resourceType == "" || resourceIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Resource type and ID are required"})
		return
	}

	resourceID, err := uuid.Parse(resourceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	filters := models.ActivityLogFilters{
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		Page:         1,
		PageSize:     50,
		SortBy:       "occurred_at",
		SortOrder:    "DESC",
	}

	// Apply tenant scoping for tenant users
	userType := middleware.GetUserType(c)
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		filters.TenantID = tenantID
	} else {
		// Platform users can optionally filter by tenant
		if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
			if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
				filters.TenantID = &tenantID
			}
		}
	}

	// Parse optional date range
	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filters.StartDate = &startDate
		}
	}

	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filters.EndDate = &endDate
		}
	}

	// Parse pagination
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			filters.Page = page
		}
	}

	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 && pageSize <= 100 {
			filters.PageSize = pageSize
		}
	}

	logs, total, err := h.service.GetActivityLogs(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit trail"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"resource_type": resourceType,
		"resource_id":   resourceID,
		"logs":          logs,
		"total":         total,
		"page":          filters.Page,
		"page_size":     filters.PageSize,
	})
}

// GetUserActivityTimeline handles GET /api/v1/audit-service/activity-logs/by-user/:user_id
// Returns activity timeline for a specific user
func (h *ActivityLogHandler) GetUserActivityTimeline(c *gin.Context) {
	userIDStr := c.Param("user_id")

	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	filters := models.ActivityLogFilters{
		UserID:    &userID,
		Page:      1,
		PageSize:  50,
		SortBy:    "occurred_at",
		SortOrder: "DESC",
	}

	// Apply tenant scoping for tenant users
	userType := middleware.GetUserType(c)
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		filters.TenantID = tenantID
	} else {
		// Platform users can optionally filter by tenant
		if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
			if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
				filters.TenantID = &tenantID
			}
		}
	}

	// Parse optional date range
	if startDateStr := c.Query("start_date"); startDateStr != "" {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filters.StartDate = &startDate
		}
	}

	if endDateStr := c.Query("end_date"); endDateStr != "" {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filters.EndDate = &endDate
		}
	}

	// Parse pagination
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			filters.Page = page
		}
	}

	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 && pageSize <= 100 {
			filters.PageSize = pageSize
		}
	}

	logs, total, err := h.service.GetActivityLogs(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user activity"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":   userID,
		"logs":      logs,
		"total":     total,
		"page":      filters.Page,
		"page_size": filters.PageSize,
	})
}
