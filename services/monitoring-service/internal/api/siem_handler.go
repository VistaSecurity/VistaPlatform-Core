package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// defaultCEFVendor is the CEF/LEEF DeviceVendor field emitted in SIEM events.
const defaultCEFVendor = "Vista Platform"

// cefVendor returns the SIEM DeviceVendor string. Defaults to "Vista Platform";
// customers mid-migration whose SIEM parsers/correlation rules still key on the
// pre-rebrand "CryptoInventory" vendor can set SIEM_CEF_VENDOR=CryptoInventory
// until they re-tune their SIEM side. See.
func cefVendor() string {
	if v := os.Getenv("SIEM_CEF_VENDOR"); v != "" {
		return v
	}
	return defaultCEFVendor
}

// SIEMExportResponse represents a SIEM export response
type SIEMExportResponse struct {
	Logs       []SIEMLogEntry `json:"logs"`
	Total      int            `json:"total"`
	Format     string         `json:"format"` // 'json', 'jsonl', 'cef', 'leef'
	ExportedAt time.Time      `json:"exported_at"`
}

// SIEMLogEntry represents a log entry in SIEM format
type SIEMLogEntry struct {
	Timestamp      time.Time              `json:"timestamp"`
	Severity       string                 `json:"severity"`
	EventType      string                 `json:"event_type"`
	Category       string                 `json:"category,omitempty"`
	ServiceName    string                 `json:"service_name"`
	ServiceVersion string                 `json:"service_version,omitempty"`
	Environment    string                 `json:"environment"`
	MessageDigest  string                 `json:"message_digest"`
	MessagePreview string                 `json:"message_preview"`
	LogID          string                 `json:"log_id"`
	CorrelationID  string                 `json:"correlation_id,omitempty"`
	TraceID        string                 `json:"trace_id,omitempty"`
	TenantID       *string                `json:"tenant_id,omitempty"`
	UserID         *string                `json:"user_id,omitempty"`
	UserType       string                 `json:"user_type,omitempty"`
	RequestID      string                 `json:"request_id,omitempty"`
	SourceIP       *string                `json:"source_ip,omitempty"`
	UserAgent      *string                `json:"user_agent,omitempty"`
	RequestMethod  string                 `json:"request_method,omitempty"`
	RequestPath    string                 `json:"request_path,omitempty"`
	ResponseStatus *int                   `json:"response_status,omitempty"`
	DurationMs     *int                   `json:"duration_ms,omitempty"`
	PIIDetected    bool                   `json:"pii_detected"`
	PIITypes       []string               `json:"pii_types,omitempty"`
	ComplianceTags []string               `json:"compliance_tags,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// exportLogsForSIEM handles GET /monitoring-service/logs/siem/export
// Exports logs in SIEM-compatible format (JSON, JSONL, CEF, LEEF)
func (s *Server) exportLogsForSIEM(c *gin.Context) {
	// Get user info from context
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format"})
		return
	}

	userEmail, _ := c.Get("email")
	emailStr := ""
	if email, ok := userEmail.(string); ok {
		emailStr = email
	}

	// Parse format (default: jsonl)
	format := c.Query("format")
	if format == "" {
		format = "jsonl"
	}
	if format != "json" && format != "jsonl" && format != "cef" && format != "leef" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid format. Supported formats: json, jsonl, cef, leef",
		})
		return
	}

	// Parse pagination parameters
	limit := 1000 // Default limit for SIEM exports
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 10000 {
			limit = parsed
		}
	}

	offset := 0
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Parse filters
	filters := make(map[string]interface{})
	if service := c.Query("service"); service != "" {
		filters["service"] = service
	}
	if severity := c.Query("severity"); severity != "" {
		filters["severity"] = severity
	}
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
			filters["start_time"] = parsed
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if parsed, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
			filters["end_time"] = parsed
		}
	}

	// Search logs
	metadataList, totalCount, err := s.logStorageService.SearchLogs(c.Request.Context(), userID, emailStr, filters, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to search logs",
		})
		return
	}

	// Convert to SIEM format
	siemLogs := make([]SIEMLogEntry, 0, len(metadataList))
	for _, metadata := range metadataList {
		siemLog := SIEMLogEntry{
			Timestamp:      metadata.Timestamp,
			Severity:       metadata.Severity,
			EventType:      metadata.EventType,
			Category:       metadata.Category,
			ServiceName:    metadata.ServiceName,
			ServiceVersion: metadata.ServiceVersion,
			Environment:    metadata.Environment,
			MessageDigest:  metadata.MessageDigest,
			MessagePreview: metadata.MessagePreview,
			LogID:          metadata.LogID,
			CorrelationID:  metadata.CorrelationID,
			TraceID:        metadata.TraceID,
			UserType:       metadata.UserType,
			RequestID:      metadata.RequestID,
			RequestMethod:  metadata.RequestMethod,
			RequestPath:    metadata.RequestPath,
			PIIDetected:    metadata.PIIDetected,
			PIITypes:       metadata.PIITypes,
			ComplianceTags: metadata.ComplianceTags,
			Metadata:       metadata.Metadata,
		}

		// Handle nullable fields
		if metadata.TenantID != nil {
			tenantIDStr := metadata.TenantID.String()
			siemLog.TenantID = &tenantIDStr
		}
		if metadata.UserID != nil {
			userIDStr := metadata.UserID.String()
			siemLog.UserID = &userIDStr
		}
		if metadata.SourceIP != nil {
			ipStr := *metadata.SourceIP
			siemLog.SourceIP = &ipStr
		}
		if metadata.UserAgent != nil {
			uaStr := *metadata.UserAgent
			siemLog.UserAgent = &uaStr
		}
		if metadata.ResponseStatus != nil {
			siemLog.ResponseStatus = metadata.ResponseStatus
		}
		if metadata.DurationMs != nil {
			siemLog.DurationMs = metadata.DurationMs
		}

		siemLogs = append(siemLogs, siemLog)
	}

	// Format response based on requested format
	switch format {
	case "json":
		c.JSON(http.StatusOK, SIEMExportResponse{
			Logs:       siemLogs,
			Total:      totalCount,
			Format:     "json",
			ExportedAt: time.Now(),
		})
	case "jsonl":
		// JSONL format: one JSON object per line
		c.Header("Content-Type", "application/x-ndjson")
		c.Writer.WriteHeader(http.StatusOK)
		encoder := json.NewEncoder(c.Writer)
		for _, log := range siemLogs {
			encoder.Encode(log)
		}
	case "cef":
		// CEF format (Common Event Format for ArcSight, Splunk, etc.)
		c.Header("Content-Type", "text/plain")
		c.Writer.WriteHeader(http.StatusOK)
		for _, log := range siemLogs {
			cefLine := formatCEF(log)
			c.Writer.WriteString(cefLine + "\n")
		}
	case "leef":
		// LEEF format (Log Event Extended Format for QRadar, etc.)
		c.Header("Content-Type", "text/plain")
		c.Writer.WriteHeader(http.StatusOK)
		for _, log := range siemLogs {
			leefLine := formatLEEF(log)
			c.Writer.WriteString(leefLine + "\n")
		}
	}
}

// formatCEF formats a log entry as CEF (Common Event Format)
func formatCEF(log SIEMLogEntry) string {
	// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	version := "0"
	vendor := cefVendor()
	product := "Platform"
	deviceVersion := "1.0"
	signatureID := log.LogID
	name := log.EventType
	severity := mapSeverityToCEF(log.Severity)

	// Extension fields (key=value pairs)
	extensions := []string{
		"msg=" + escapeCEF(log.MessagePreview),
		"cs1Label=Service",
		"cs1=" + log.ServiceName,
		"cs2Label=Category",
		"cs2=" + log.Category,
	}

	if log.SourceIP != nil {
		extensions = append(extensions, "src="+*log.SourceIP)
	}
	if log.UserID != nil {
		extensions = append(extensions, "suid="+*log.UserID)
	}

	return fmt.Sprintf("CEF:%s|%s|%s|%s|%s|%s|%s|%s",
		version, vendor, product, deviceVersion, signatureID, name, severity,
		joinCEFExtensions(extensions))
}

// formatLEEF formats a log entry as LEEF (Log Event Extended Format)
func formatLEEF(log SIEMLogEntry) string {
	// LEEF format: LEEF:Version|Vendor|Product|Version|EventID|Name|Severity|...
	version := "2.0"
	vendor := cefVendor()
	product := "Platform"
	deviceVersion := "1.0"
	eventID := log.LogID
	name := log.EventType
	severity := mapSeverityToLEEF(log.Severity)

	// Extension fields
	extensions := []string{
		"Service=" + log.ServiceName,
		"Category=" + log.Category,
		"Message=" + log.MessagePreview,
	}

	if log.SourceIP != nil {
		extensions = append(extensions, "src="+*log.SourceIP)
	}

	return fmt.Sprintf("LEEF:%s|%s|%s|%s|%s|%s|%s|%s",
		version, vendor, product, deviceVersion, eventID, name, severity,
		joinLEEFExtensions(extensions))
}

// Helper functions
func mapSeverityToCEF(severity string) string {
	severityMap := map[string]string{
		"debug":    "1",
		"info":     "3",
		"warn":     "5",
		"error":    "7",
		"critical": "10",
	}
	if mapped, ok := severityMap[severity]; ok {
		return mapped
	}
	return "3"
}

func mapSeverityToLEEF(severity string) string {
	severityMap := map[string]string{
		"debug":    "Low",
		"info":     "Informational",
		"warn":     "Medium",
		"error":    "High",
		"critical": "Critical",
	}
	if mapped, ok := severityMap[severity]; ok {
		return mapped
	}
	return "Informational"
}

func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

func joinCEFExtensions(extensions []string) string {
	return strings.Join(extensions, " ")
}

func joinLEEFExtensions(extensions []string) string {
	return strings.Join(extensions, "\t")
}
