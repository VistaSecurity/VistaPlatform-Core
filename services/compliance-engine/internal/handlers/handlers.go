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

// GetWorkspaceSummary returns a normalized summary for the workspace (single framework)
// Query: framework_id, framework_version, optional filters (environment, severity, owner, tags[])
func (h *ComplianceHandlers) GetWorkspaceSummary(c *gin.Context) {
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

	frameworkID := c.Query("framework_id")
	frameworkVersion := c.Query("framework_version")

	// MVP: reuse RunComplianceCheck to derive KPIs; detailed families/controls to follow
	report, err := h.complianceService.RunComplianceCheck(tenantUUID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate workspace summary",
		})
		return
	}

	score := int(report.Summary.ComplianceRate + 0.5)
	failing := report.Summary.FailedChecks

	// Placeholder families/controls based on framework
	families := []gin.H{}
	controls := []gin.H{}

	switch frameworkID {
	case "pci-dss":
		families = []gin.H{
			{"id": "1", "name": "Access Control", "pass": 8, "warn": 2, "fail": 1},
			{"id": "2", "name": "Cryptography", "pass": 6, "warn": 1, "fail": 3},
			{"id": "3", "name": "Network Security", "pass": 5, "warn": 0, "fail": 2},
		}
		controls = []gin.H{
			{"id": "PCI-4.2.1", "family_id": "2", "name": "Disallow TLS 1.0", "status": "fail", "score": 0, "failing_findings_count": 5, "affected_assets_count": 3, "last_seen": "2026-04-16T14:30:00Z"},
			{"id": "PCI-4.2.2", "family_id": "2", "name": "Disallow weak ciphers", "status": "pass", "score": 100, "failing_findings_count": 0, "affected_assets_count": 0, "last_seen": "2026-04-16T14:30:00Z"},
			{"id": "PCI-8.1.1", "family_id": "1", "name": "Unique user IDs", "status": "warn", "score": 75, "failing_findings_count": 2, "affected_assets_count": 1, "last_seen": "2026-04-16T14:30:00Z"},
		}
	case "nist-800-53":
		families = []gin.H{
			{"id": "1", "name": "Access Control (AC)", "pass": 12, "warn": 3, "fail": 2},
			{"id": "2", "name": "Cryptography (SC)", "pass": 8, "warn": 1, "fail": 4},
		}
		controls = []gin.H{
			{"id": "AC-2", "family_id": "1", "name": "Account Management", "status": "pass", "score": 100, "failing_findings_count": 0, "affected_assets_count": 0, "last_seen": "2026-04-16T14:30:00Z"},
			{"id": "SC-7", "family_id": "2", "name": "Boundary Protection", "status": "fail", "score": 25, "failing_findings_count": 8, "affected_assets_count": 5, "last_seen": "2026-04-16T14:30:00Z"},
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"framework":    gin.H{"id": frameworkID, "version": frameworkVersion},
		"last_updated": report.CompletedAt,
		"kpis": gin.H{
			"score":            score,
			"failing_controls": failing,
			"affected_assets":  0,
		},
		"families": families,
		"controls": controls,
	})
}

// GetControlDetails returns details for a control with findings (placeholder for MVP wiring)
// Path: /controls/:id, Query: framework_id, framework_version, pagination and filters
func (h *ComplianceHandlers) GetControlDetails(c *gin.Context) {
	// Get tenant ID from context (set by middleware)
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	_, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	controlID := c.Param("id")
	// Placeholder payload; real implementation will query mappings and findings
	c.JSON(http.StatusOK, gin.H{
		"control":          gin.H{"id": controlID, "name": controlID, "status": "pass"},
		"rationale":        "Details will be populated once mapping and findings aggregation is implemented",
		"evidence_summary": gin.H{"failing_findings_count": 0, "affected_assets_count": 0},
		"findings":         []gin.H{},
		"pagination":       gin.H{"page": 1, "page_size": 25, "total": 0},
	})
}
