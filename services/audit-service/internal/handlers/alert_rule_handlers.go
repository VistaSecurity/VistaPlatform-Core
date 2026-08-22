package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// alertRuleService is the narrow surface of *services.AlertRuleService the alert
// handlers use. Depending on the interface (the concrete service still satisfies
// it) lets the real gin handlers run over in-memory stubs — no database — in the
// spec-first contract test (ADR-0001). Production wiring via NewAlertRuleHandler
// is unchanged.
type alertRuleService interface {
	CreateAlertRule(ctx context.Context, rule *models.AlertRule) error
	GetAlertRules(ctx context.Context, filters models.AlertRuleFilters) ([]models.AlertRule, int, error)
	GetAlertRuleByID(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) (*models.AlertRule, error)
	UpdateAlertRule(ctx context.Context, id uuid.UUID, rule *models.AlertRule, tenantID *uuid.UUID) error
	DeleteAlertRule(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) error
}

type AlertRuleHandler struct {
	service alertRuleService
}

func NewAlertRuleHandler(service *services.AlertRuleService) *AlertRuleHandler {
	return &AlertRuleHandler{service: service}
}

// CreateAlertRule handles POST /api/v1/audit-service/alert-rules
func (h *AlertRuleHandler) CreateAlertRule(c *gin.Context) {
	var rule models.AlertRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user type and apply scoping
	userType := middleware.GetUserType(c)
	userID := middleware.GetUserID(c)

	switch userType {
	case middleware.UserTypeTenant:
		// Tenant users can only create tenant-scoped rules
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		rule.TenantID = tenantID
	case middleware.UserTypePlatform:
		// Platform users can create platform or tenant-scoped rules
		// Use whatever was provided in the request
	default:
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	rule.CreatedBy = userID

	err := h.service.CreateAlertRule(c.Request.Context(), &rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create alert rule"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": rule.ID, "message": "Alert rule created successfully"})
}

// GetAlertRules handles GET /api/v1/audit-service/alert-rules
func (h *AlertRuleHandler) GetAlertRules(c *gin.Context) {
	filters := models.AlertRuleFilters{
		Page:     1,
		PageSize: 50,
	}

	// Get user type and apply scoping
	userType := middleware.GetUserType(c)

	if userType == middleware.UserTypeTenant {
		// Tenant users see their tenant-scoped rules + platform rules
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		filters.TenantID = tenantID
	}
	// Platform users see all rules (no tenant filter)

	// Parse filters
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

	if enabledStr := c.Query("is_enabled"); enabledStr != "" {
		if enabled, err := strconv.ParseBool(enabledStr); err == nil {
			filters.IsEnabled = &enabled
		}
	}

	if severity := c.Query("severity"); severity != "" {
		filters.Severity = severity
	}

	if ruleType := c.Query("rule_type"); ruleType != "" {
		filters.RuleType = ruleType
	}

	rules, total, err := h.service.GetAlertRules(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve alert rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules":     rules,
		"total":     total,
		"page":      filters.Page,
		"page_size": filters.PageSize,
	})
}

// GetAlertRuleByID handles GET /api/v1/audit-service/alert-rules/:id
func (h *AlertRuleHandler) GetAlertRuleByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert rule ID"})
		return
	}

	scope, ok := byIDTenantScope(c)
	if !ok {
		return
	}
	rule, err := h.service.GetAlertRuleByID(c.Request.Context(), id, scope)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Alert rule not found"})
		return
	}

	// Check access
	userType := middleware.GetUserType(c)
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil || (rule.TenantID != nil && *rule.TenantID != *tenantID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
	}

	c.JSON(http.StatusOK, rule)
}

// UpdateAlertRule handles PUT /api/v1/audit-service/alert-rules/:id
func (h *AlertRuleHandler) UpdateAlertRule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert rule ID"})
		return
	}

	// Get existing rule to check permissions
	scope, ok := byIDTenantScope(c)
	if !ok {
		return
	}
	existing, err := h.service.GetAlertRuleByID(c.Request.Context(), id, scope)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Alert rule not found"})
		return
	}

	// Check access
	userType := middleware.GetUserType(c)
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil || (existing.TenantID != nil && *existing.TenantID != *tenantID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
	}

	// Merge the (possibly partial) body onto the existing rule so an
	// optional-fields body — e.g. {"is_enabled": false} to toggle a rule —
	// only changes the fields it carries. Binding into a fresh struct here
	// zero-valued every absent column (name="", severity="", ...) and the
	// service's full-column UPDATE then wrote those zeros, which the DB
	// rejects → 500. The AlertRuleInput contract documents all fields
	// as optional, so partial-update is the contracted behaviour.
	origTenantID := existing.TenantID
	origCreatedBy := existing.CreatedBy
	origCreatedAt := existing.CreatedAt

	if err := c.ShouldBindJSON(existing); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Restore server-owned/immutable fields a client must not be able to
	// reassign through the body (tenant ownership, creator, creation time, id).
	existing.ID = id
	existing.TenantID = origTenantID
	existing.CreatedBy = origCreatedBy
	existing.CreatedAt = origCreatedAt

	err = h.service.UpdateAlertRule(c.Request.Context(), id, existing, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update alert rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Alert rule updated successfully"})
}

// DeleteAlertRule handles DELETE /api/v1/audit-service/alert-rules/:id
func (h *AlertRuleHandler) DeleteAlertRule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert rule ID"})
		return
	}

	// Get existing rule to check permissions
	scope, ok := byIDTenantScope(c)
	if !ok {
		return
	}
	existing, err := h.service.GetAlertRuleByID(c.Request.Context(), id, scope)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Alert rule not found"})
		return
	}

	// Check access
	userType := middleware.GetUserType(c)
	if userType == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil || (existing.TenantID != nil && *existing.TenantID != *tenantID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			return
		}
	}

	err = h.service.DeleteAlertRule(c.Request.Context(), id, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete alert rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Alert rule deleted successfully"})
}
