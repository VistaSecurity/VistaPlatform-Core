package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// cryptoRisksService is the slice of *services.CryptoRisksService the crypto-
// risks handlers depend on. Declaring it as an interface (the concrete service
// still satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
type cryptoRisksService interface {
	GetSummary(tenantID uuid.UUID) (*services.CryptoRisksSummary, error)
	ListRisks(tenantID uuid.UUID, filters services.CryptoRiskFilters) (*services.CryptoRisksResponse, error)
	ExportRisks(tenantID uuid.UUID, filters services.CryptoRiskFilters) ([]services.CryptoRisk, error)
	GetRiskByID(tenantID, riskID uuid.UUID) (*services.CryptoRisk, error)
}

// CryptoRisksHandlers handles HTTP requests for crypto risks
type CryptoRisksHandlers struct {
	service cryptoRisksService
}

// NewCryptoRisksHandlers creates a new crypto risks handlers instance
func NewCryptoRisksHandlers(service *services.CryptoRisksService) *CryptoRisksHandlers {
	return &CryptoRisksHandlers{service: service}
}

// GetSummary returns aggregated crypto risk statistics
// @Summary Get crypto risks summary
// @Description Returns aggregated crypto risk statistics for the tenant
// @Tags crypto-risks
// @Produce json
// @Success 200 {object} services.CryptoRisksSummary
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/inventory-service/crypto-risks/summary [get]
func (h *CryptoRisksHandlers) GetSummary(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	summary, err := h.service.GetSummary(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// ListRisks returns a paginated list of crypto risks
// @Summary List crypto risks
// @Description Returns a paginated list of crypto risks for the tenant
// @Tags crypto-risks
// @Produce json
// @Param severity query []string false "Filter by severity (critical, high, medium, info)"
// @Param category query []string false "Filter by category (protocol, algorithm, certificate, key_size)"
// @Param search query string false "Search term"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param sort_by query string false "Sort by field"
// @Param sort_order query string false "Sort order (asc, desc)"
// @Success 200 {object} services.CryptoRisksResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/inventory-service/crypto-risks [get]
func (h *CryptoRisksHandlers) ListRisks(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	var filters services.CryptoRiskFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	response, err := h.service.ListRisks(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetRisk returns a specific crypto risk by ID
// @Summary Get crypto risk by ID
// @Description Returns details of a specific crypto risk
// @Tags crypto-risks
// @Produce json
// @Param id path string true "Risk ID (crypto implementation ID)"
// @Success 200 {object} services.CryptoRisk
// @Failure 400 {object} map[string]string "Invalid ID"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 404 {object} map[string]string "Not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/inventory-service/crypto-risks/{id} [get]
func (h *CryptoRisksHandlers) GetRisk(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	riskIDStr := c.Param("id")
	riskID, err := uuid.Parse(riskIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid risk ID"})
		return
	}

	risk, err := h.service.GetRiskByID(tenantUUID, riskID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Risk not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, risk)
}

// ExportRisks exports crypto risks as CSV
// @Summary Export crypto risks
// @Description Exports crypto risks as CSV file
// @Tags crypto-risks
// @Produce text/csv
// @Param severity query []string false "Filter by severity"
// @Param category query []string false "Filter by category"
// @Success 200 {string} string "CSV data"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /api/v1/inventory-service/crypto-risks/export [get]
func (h *CryptoRisksHandlers) ExportRisks(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	var filters services.CryptoRiskFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	// One read/judgment pass, bounded to the documented 50k export ceiling.
	risks, err := h.service.ExportRisks(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Build CSV
	var csv strings.Builder
	csv.WriteString("ID,Severity,Category,Issue Type,Current Value,Description,Recommendation,Asset Hostname,Asset IP,Asset Port,Protocol,Protocol Version,Detected At,Risk Score,Assessment Basis,Score Sources,Assessment Limitations\n")
	for _, risk := range risks {
		hostname := ""
		if risk.AssetHostname != nil {
			hostname = *risk.AssetHostname
		}
		ip := ""
		if risk.AssetIPAddress != nil {
			ip = *risk.AssetIPAddress
		}
		port := ""
		if risk.AssetPort != nil {
			port = strconv.Itoa(*risk.AssetPort)
		}
		protocolVersion := ""
		if risk.ProtocolVersion != nil {
			protocolVersion = *risk.ProtocolVersion
		}

		csv.WriteString(risk.ID.String() + ",")
		if risk.Severity != nil {
			csv.WriteString(*risk.Severity)
		}
		csv.WriteString(",")
		csv.WriteString(risk.Category + ",")
		csv.WriteString(escapeCSV(risk.IssueType) + ",")
		csv.WriteString(escapeCSV(risk.CurrentValue) + ",")
		csv.WriteString(escapeCSV(risk.Description) + ",")
		csv.WriteString(escapeCSV(risk.Recommendation) + ",")
		csv.WriteString(escapeCSV(hostname) + ",")
		csv.WriteString(escapeCSV(ip) + ",")
		csv.WriteString(port + ",")
		csv.WriteString(escapeCSV(risk.Protocol) + ",")
		csv.WriteString(escapeCSV(protocolVersion) + ",")
		csv.WriteString(risk.DetectedAt.Format("2006-01-02 15:04:05") + ",")
		if risk.RiskScore != nil {
			csv.WriteString(strconv.Itoa(*risk.RiskScore))
		}
		csv.WriteString("," + escapeCSV(risk.AssessmentBasis) + "," + escapeCSV(strings.Join(risk.ScoreSources, "; ")) + "," + escapeCSV(strings.Join(risk.AssessmentLimitations, "; ")) + "\n")
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=crypto-risks.csv")
	c.String(http.StatusOK, csv.String())
}

// escapeCSV escapes a string for CSV output
func escapeCSV(s string) string {
	if s == "" {
		return ""
	}
	// Formula-injection neutralization: a leading = + - @ tab or CR makes
	// Excel/Sheets execute the cell as a formula. Inventory values (hostname,
	// description, issue type, etc.) are attacker-influenceable via discovery —
	// prefix such cells with an apostrophe so they render as literal text.
	if c := s[0]; c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r' {
		s = "'" + s
	}
	// If contains comma, quote, or newline, wrap in quotes and escape quotes
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
