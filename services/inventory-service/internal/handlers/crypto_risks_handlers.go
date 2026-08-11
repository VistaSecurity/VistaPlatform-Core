package handlers

import (
	"net/http"
	"strconv"

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
		if err.Error() == "sql: no rows in result set" {
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

	// Export the full result set. ListRisks clamps PageSize to
	// MaxCryptoRiskPageSize, so page through until a short page signals the
	// end (bounded by exportPageCap so a runaway can't stream unbounded).
	const exportPageCap = 500 // MaxCryptoRiskPageSize * 500 = 50k row ceiling
	filters.PageSize = services.MaxCryptoRiskPageSize
	var risks []services.CryptoRisk
	for page := 1; page <= exportPageCap; page++ {
		filters.Page = page
		response, err := h.service.ListRisks(tenantUUID, filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		risks = append(risks, response.Risks...)
		if len(response.Risks) < services.MaxCryptoRiskPageSize {
			break
		}
	}

	// Build CSV
	csv := "ID,Severity,Category,Issue Type,Current Value,Description,Recommendation,Asset Hostname,Asset IP,Asset Port,Protocol,Protocol Version,Detected At\n"
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

		csv += risk.ID.String() + ","
		csv += risk.Severity + ","
		csv += risk.Category + ","
		csv += escapeCSV(risk.IssueType) + ","
		csv += escapeCSV(risk.CurrentValue) + ","
		csv += escapeCSV(risk.Description) + ","
		csv += escapeCSV(risk.Recommendation) + ","
		csv += escapeCSV(hostname) + ","
		csv += escapeCSV(ip) + ","
		csv += port + ","
		csv += escapeCSV(risk.Protocol) + ","
		csv += escapeCSV(protocolVersion) + ","
		csv += risk.DetectedAt.Format("2006-01-02 15:04:05") + "\n"
	}

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", "attachment; filename=crypto-risks.csv")
	c.String(http.StatusOK, csv)
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
