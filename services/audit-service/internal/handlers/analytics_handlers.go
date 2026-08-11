package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// analyticsService is the narrow surface of *services.AnalyticsService the
// handlers use, so they can run over an in-memory stub in the contract test
// (ADR-0001). The concrete service satisfies it; NewAnalyticsHandler is unchanged.
type analyticsService interface {
	GetUserActivitySummary(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, days int) (*services.UserActivitySummary, error)
	GetAccessPatternAnalysis(ctx context.Context, tenantID *uuid.UUID, days int) (*services.AccessPatternAnalysis, error)
	GetComplianceGapAnalysis(ctx context.Context, framework string, tenantID *uuid.UUID, days int) (*services.ComplianceGapAnalysis, error)
}

type AnalyticsHandler struct {
	service analyticsService
}

func NewAnalyticsHandler(service *services.AnalyticsService) *AnalyticsHandler {
	return &AnalyticsHandler{service: service}
}

// GetUserActivity handles GET /api/v1/audit-service/analytics/user-activity
func (h *AnalyticsHandler) GetUserActivity(c *gin.Context) {
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

	// Enforce tenant scoping: tenant users can only view activity within their own tenant
	var tenantID *uuid.UUID
	if middleware.GetUserType(c) == middleware.UserTypeTenant {
		tenantID = middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
	} else if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if id, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &id
		}
	}

	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	summary, err := h.service.GetUserActivitySummary(c.Request.Context(), userID, tenantID, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user activity"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"summary": summary})
}

// GetAccessPatterns handles GET /api/v1/audit-service/analytics/access-patterns
func (h *AnalyticsHandler) GetAccessPatterns(c *gin.Context) {
	var tenantID *uuid.UUID
	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if id, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &id
		}
	}

	// Enforce tenant scoping for tenant users
	if middleware.GetUserType(c) == middleware.UserTypeTenant {
		tenantID = middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
	}

	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	analysis, err := h.service.GetAccessPatternAnalysis(c.Request.Context(), tenantID, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get access patterns"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"analysis": analysis})
}

// GetComplianceGaps handles GET /api/v1/audit-service/analytics/compliance-gaps
func (h *AnalyticsHandler) GetComplianceGaps(c *gin.Context) {
	framework := c.DefaultQuery("framework", "soc2")

	var tenantID *uuid.UUID
	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if id, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &id
		}
	}

	// Enforce tenant scoping for tenant users
	if middleware.GetUserType(c) == middleware.UserTypeTenant {
		tenantID = middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
	}

	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	analysis, err := h.service.GetComplianceGapAnalysis(c.Request.Context(), framework, tenantID, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get compliance gaps"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"analysis": analysis})
}

// GetDashboardMetrics handles GET /api/v1/audit-service/analytics/dashboard
func (h *AnalyticsHandler) GetDashboardMetrics(c *gin.Context) {
	var tenantID *uuid.UUID
	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if id, err := uuid.Parse(tenantIDStr); err == nil {
			tenantID = &id
		}
	}

	// Enforce tenant scoping for tenant users
	if middleware.GetUserType(c) == middleware.UserTypeTenant {
		tenantID = middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
	}

	// Get access patterns for last 7 days
	analysis, err := h.service.GetAccessPatternAnalysis(c.Request.Context(), tenantID, 7)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get dashboard metrics"})
		return
	}

	// Calculate some quick metrics
	totalEventsToday := 0
	for _, count := range analysis.EventsByHour {
		totalEventsToday += count
	}

	metrics := map[string]interface{}{
		"total_users":            analysis.TotalUsers,
		"active_users_7d":        analysis.ActiveUsers,
		"failure_rate":           analysis.FailureRate,
		"average_events_per_day": analysis.AverageEventsPerDay,
		"top_event_types":        analysis.TopEventTypes,
		"events_by_hour":         analysis.EventsByHour,
		"top_users":              analysis.TopUsers,
	}

	c.JSON(http.StatusOK, gin.H{"metrics": metrics})
}
