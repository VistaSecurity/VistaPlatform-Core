package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// complianceService / complianceReportService are the narrow surfaces of the
// concrete services the handlers use, so they can run over in-memory stubs in
// the contract test (ADR-0001). The concrete services satisfy them; the
// NewComplianceHandler* constructors are unchanged.
type complianceService interface {
	GetComplianceSummary(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*services.ComplianceSummary, error)
	ValidateRetentionPolicies(ctx context.Context) error
}

type complianceReportService interface {
	GenerateSOC2Report(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*services.ComplianceReport, error)
	GenerateISO27001Report(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*services.ComplianceReport, error)
	GenerateGDPRReport(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*services.ComplianceReport, error)
	GenerateHIPAAReport(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*services.ComplianceReport, error)
	GeneratePCIDSSReport(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) (*services.ComplianceReport, error)
}

type ComplianceHandler struct {
	service       complianceService
	reportService complianceReportService
}

func NewComplianceHandler(service *services.ComplianceService) *ComplianceHandler {
	return &ComplianceHandler{service: service}
}

func NewComplianceHandlerWithReportService(service *services.ComplianceService, reportService *services.ComplianceReportService) *ComplianceHandler {
	return &ComplianceHandler{
		service:       service,
		reportService: reportService,
	}
}

// GetComplianceSummary handles GET /api/v1/audit-service/compliance-reports/summary
func (h *ComplianceHandler) GetComplianceSummary(c *gin.Context) {
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

	// Default to last 30 days if not specified
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

	summary, err := h.service.GetComplianceSummary(c.Request.Context(), tenantID, startDate, endDate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate compliance summary"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"summary": summary})
}

// ValidateRetentionPolicies handles GET /api/v1/audit-service/compliance-reports/validate-retention
func (h *ComplianceHandler) ValidateRetentionPolicies(c *gin.Context) {
	err := h.service.ValidateRetentionPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Retention policy validation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All retention policies are properly configured"})
}

// GetComplianceReportTemplates handles GET /api/v1/audit-service/compliance-reports/templates
func (h *ComplianceHandler) GetComplianceReportTemplates(c *gin.Context) {
	templates := []map[string]interface{}{
		{
			"id":          "soc2",
			"name":        "SOC 2 Type II Audit Trail Report",
			"framework":   "soc2",
			"description": "Comprehensive audit trail for SOC 2 Type II compliance",
			"sections": []string{
				"Authentication Events",
				"Access Control Events",
				"Data Access Events",
				"System Configuration Changes",
				"Security Incident Response",
			},
		},
		{
			"id":          "iso27001",
			"name":        "ISO 27001 Compliance Report",
			"framework":   "iso27001",
			"description": "ISO 27001 compliance monitoring and audit report",
			"sections": []string{
				"Asset Management Activities",
				"Access Control Activities",
				"System Operations",
				"Incident Management",
				"Compliance Monitoring",
			},
		},
		{
			"id":          "gdpr",
			"name":        "GDPR Data Processing Report",
			"framework":   "gdpr",
			"description": "GDPR data processing and access audit report",
			"sections": []string{
				"Data Access Logs",
				"Data Processing Activities",
				"Data Deletion Requests",
				"Consent Management",
			},
		},
		{
			"id":          "hipaa",
			"name":        "HIPAA Access Logs Report",
			"framework":   "hipaa",
			"description": "HIPAA access and activity monitoring report",
			"sections": []string{
				"User Authentication",
				"PHI Access",
				"User Activity Monitoring",
				"System Access Logs",
				"Security Incidents",
			},
		},
		{
			"id":          "pci_dss",
			"name":        "PCI DSS Audit Logs Report",
			"framework":   "pci_dss",
			"description": "PCI DSS compliance audit log report",
			"sections": []string{
				"Authentication Events",
				"Cardholder Data Access",
				"System Component Changes",
				"Security Events",
				"Network Access Logs",
			},
		},
	}

	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

// GenerateComplianceReport handles POST /api/v1/audit-service/compliance-reports/generate
func (h *ComplianceHandler) GenerateComplianceReport(c *gin.Context) {
	if h.reportService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Report service not available"})
		return
	}

	var req struct {
		Framework string     `json:"framework" binding:"required"`
		StartDate time.Time  `json:"start_date" binding:"required"`
		EndDate   time.Time  `json:"end_date" binding:"required"`
		TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
		Format    string     `json:"format"` // 'json', 'pdf', 'excel'
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Enforce tenant scoping for tenant users
	if middleware.GetUserType(c) == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		req.TenantID = tenantID
	}

	if req.Format == "" {
		req.Format = "json"
	}

	var report *services.ComplianceReport
	var err error

	switch req.Framework {
	case "soc2":
		report, err = h.reportService.GenerateSOC2Report(c.Request.Context(), req.TenantID, req.StartDate, req.EndDate)
	case "iso27001":
		report, err = h.reportService.GenerateISO27001Report(c.Request.Context(), req.TenantID, req.StartDate, req.EndDate)
	case "gdpr":
		report, err = h.reportService.GenerateGDPRReport(c.Request.Context(), req.TenantID, req.StartDate, req.EndDate)
	case "hipaa":
		report, err = h.reportService.GenerateHIPAAReport(c.Request.Context(), req.TenantID, req.StartDate, req.EndDate)
	case "pci_dss":
		report, err = h.reportService.GeneratePCIDSSReport(c.Request.Context(), req.TenantID, req.StartDate, req.EndDate)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported framework", "supported": []string{"soc2", "iso27001", "gdpr", "hipaa", "pci_dss"}})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate compliance report"})
		return
	}

	report.Format = req.Format

	c.JSON(http.StatusOK, gin.H{"report": report})
}
