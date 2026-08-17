package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ComplianceHandlers contains all compliance-related handlers
type ComplianceHandlers struct {
	complianceService *services.ComplianceService
	mappingsService   *services.MappingsService
}

// NewComplianceHandlers creates a new instance of compliance handlers
func NewComplianceHandlers(complianceService *services.ComplianceService, mappingsService *services.MappingsService) *ComplianceHandlers {
	return &ComplianceHandlers{
		complianceService: complianceService,
		mappingsService:   mappingsService,
	}
}

// Health handles health check
func (h *ComplianceHandlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "compliance-engine",
		"version": version.Get(),
	})
}

// GetComplianceRules retrieves all compliance rules
func (h *ComplianceHandlers) GetComplianceRules(c *gin.Context) {
	rules, err := h.complianceService.GetComplianceRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve compliance rules",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
	})
}

// GetComplianceRule retrieves a specific compliance rule
func (h *ComplianceHandlers) GetComplianceRule(c *gin.Context) {
	ruleIDStr := c.Param("id")
	ruleID, err := uuid.Parse(ruleIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid rule ID",
		})
		return
	}

	rule, err := h.complianceService.GetComplianceRule(ruleID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Compliance rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rule": rule,
	})
}

// CreateComplianceRule creates a new compliance rule
func (h *ComplianceHandlers) CreateComplianceRule(c *gin.Context) {
	var input models.ComplianceRuleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	rule, err := h.complianceService.CreateComplianceRule(&input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create compliance rule",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Compliance rule created successfully",
		"rule":    rule,
	})
}

// RunComplianceCheck runs compliance checks for a tenant
func (h *ComplianceHandlers) RunComplianceCheck(c *gin.Context) {
	// Get tenant ID from context (set by middleware)
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Tenant ID not found",
		})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
		})
		return
	}

	var input models.ComplianceReportInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Parse rule IDs from strings to UUIDs
	ruleUUIDs := make([]uuid.UUID, 0, len(input.RuleIDs))
	for _, idStr := range input.RuleIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid rule_id format",
				"details": fmt.Sprintf("Invalid UUID: %s", idStr),
			})
			return
		}
		ruleUUIDs = append(ruleUUIDs, id)
	}

	report, err := h.complianceService.RunComplianceCheck(tenantUUID, ruleUUIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to run compliance check",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Compliance check completed",
		"report":  report,
	})
}

// GetComplianceReports retrieves compliance reports for a tenant
func (h *ComplianceHandlers) GetComplianceReports(c *gin.Context) {
	// Get tenant ID from context (set by middleware)
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Tenant ID not found",
		})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
		})
		return
	}

	// Parse pagination parameters
	page := 1
	pageSize := 20
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	reports, err := h.complianceService.GetComplianceReports(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve compliance reports",
		})
		return
	}

	// Simple pagination
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= len(reports) {
		reports = []models.ComplianceReport{}
	} else if end > len(reports) {
		reports = reports[start:]
	} else {
		reports = reports[start:end]
	}

	c.JSON(http.StatusOK, gin.H{
		"reports": reports,
		"pagination": gin.H{
			"page":      page,
			"page_size": pageSize,
			"total":     len(reports),
		},
	})
}

// GetComplianceSummary retrieves compliance summary for a tenant
func (h *ComplianceHandlers) GetComplianceSummary(c *gin.Context) {
	// Get tenant ID from context (set by middleware)
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Tenant ID not found",
		})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tenant ID",
		})
		return
	}

	// Run a quick compliance check to get current status
	report, err := h.complianceService.RunComplianceCheck(tenantUUID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate compliance summary",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"summary":      report.Summary,
		"report_id":    report.ID,
		"generated_at": report.CompletedAt,
	})
}
