package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// LogsResponse represents paginated log metadata with signed URLs
type LogsResponse struct {
	Logs       []LogMetadataResponse `json:"logs"`
	Total      int                   `json:"total"`
	Limit      int                   `json:"limit"`
	Offset     int                   `json:"offset"`
	HasMore    bool                  `json:"has_more"`
	NextOffset *int                  `json:"next_offset,omitempty"`
}

// LogMetadataResponse represents sanitized log metadata returned to clients
type LogMetadataResponse struct {
	ID              string                 `json:"id"`
	LogID           string                 `json:"log_id"`
	CorrelationID   string                 `json:"correlation_id,omitempty"`
	TraceID         string                 `json:"trace_id,omitempty"`
	ServiceName     string                 `json:"service_name"`
	ServiceVersion  string                 `json:"service_version,omitempty"`
	Environment     string                 `json:"environment"`
	Severity        string                 `json:"severity"`
	EventType       string                 `json:"event_type"`
	Category        string                 `json:"category,omitempty"`
	MessageDigest   string                 `json:"message_digest"`
	MessagePreview  string                 `json:"message_preview"`
	RedactionMask   []string               `json:"redaction_mask,omitempty"`
	TenantID        *string                `json:"tenant_id,omitempty"`
	UserID          *string                `json:"user_id,omitempty"`
	UserType        string                 `json:"user_type,omitempty"`
	RequestID       string                 `json:"request_id,omitempty"`
	SourceIP        *string                `json:"source_ip,omitempty"`
	UserAgent       *string                `json:"user_agent,omitempty"`
	RequestMethod   string                 `json:"request_method,omitempty"`
	RequestPath     string                 `json:"request_path,omitempty"`
	ResponseStatus  *int                   `json:"response_status,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	DurationMs      *int                   `json:"duration_ms,omitempty"`
	Status          string                 `json:"status"`
	RetentionPolicy string                 `json:"retention_policy"`
	PIIDetected     bool                   `json:"pii_detected"`
	PIITypes        []string               `json:"pii_types,omitempty"`
	ComplianceTags  []string               `json:"compliance_tags,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	Tags            map[string]interface{} `json:"tags,omitempty"`
	// Signed URL for accessing raw log from S3
	SignedURL       *string    `json:"signed_url,omitempty"`
	SignedURLExpiry *time.Time `json:"signed_url_expiry,omitempty"`
}

// getLogs handles GET /monitoring-service/logs
// Returns paginated log metadata with optional signed URLs
func (s *Server) getLogs(c *gin.Context) {
	// Get user info from context (set by auth middleware)
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

	// Parse pagination parameters
	limit := 50 // Default limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
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

	// Check if signed URLs should be generated
	includeSignedURLs := c.Query("include_signed_urls") == "true"
	signedURLExpiry := 15 * time.Minute // Default expiry
	if expiryStr := c.Query("signed_url_expiry_seconds"); expiryStr != "" {
		if parsed, err := strconv.Atoi(expiryStr); err == nil && parsed > 0 {
			signedURLExpiry = time.Duration(parsed) * time.Second
		}
	}

	// Search logs (this automatically records access audit)
	metadataList, totalCount, err := s.logStorageService.SearchLogs(c.Request.Context(), userID, emailStr, filters, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to search logs",
		})
		return
	}

	// Convert to response format
	response := LogsResponse{
		Logs:    make([]LogMetadataResponse, 0, len(metadataList)),
		Total:   totalCount,
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+limit < totalCount,
	}

	if response.HasMore {
		nextOffset := offset + limit
		response.NextOffset = &nextOffset
	}

	for _, metadata := range metadataList {
		logResp := LogMetadataResponse{
			ID:              metadata.ID.String(),
			LogID:           metadata.LogID,
			CorrelationID:   metadata.CorrelationID,
			TraceID:         metadata.TraceID,
			ServiceName:     metadata.ServiceName,
			ServiceVersion:  metadata.ServiceVersion,
			Environment:     metadata.Environment,
			Severity:        metadata.Severity,
			EventType:       metadata.EventType,
			Category:        metadata.Category,
			MessageDigest:   metadata.MessageDigest,
			MessagePreview:  metadata.MessagePreview,
			UserType:        metadata.UserType,
			RequestID:       metadata.RequestID,
			RequestMethod:   metadata.RequestMethod,
			RequestPath:     metadata.RequestPath,
			Timestamp:       metadata.Timestamp,
			Status:          metadata.Status,
			RetentionPolicy: metadata.RetentionPolicy,
			PIIDetected:     metadata.PIIDetected,
			PIITypes:        metadata.PIITypes,
			ComplianceTags:  metadata.ComplianceTags,
			Metadata:        metadata.Metadata,
			Tags:            metadata.Tags,
		}

		// Handle nullable fields
		if metadata.TenantID != nil {
			tenantIDStr := metadata.TenantID.String()
			logResp.TenantID = &tenantIDStr
		}
		if metadata.UserID != nil {
			userIDStr := metadata.UserID.String()
			logResp.UserID = &userIDStr
		}
		if metadata.SourceIP != nil {
			ipStr := *metadata.SourceIP
			logResp.SourceIP = &ipStr
		}
		if metadata.UserAgent != nil {
			uaStr := *metadata.UserAgent
			logResp.UserAgent = &uaStr
		}
		if metadata.ResponseStatus != nil {
			logResp.ResponseStatus = metadata.ResponseStatus
		}
		if metadata.DurationMs != nil {
			logResp.DurationMs = metadata.DurationMs
		}

		// Parse redaction mask JSON
		if metadata.RedactionMask != "" && metadata.RedactionMask != "[]" {
			var redactionMask []string
			if err := json.Unmarshal([]byte(metadata.RedactionMask), &redactionMask); err == nil {
				logResp.RedactionMask = redactionMask
			}
		}

		// Generate signed URL if requested
		if includeSignedURLs {
			signedURL, err := s.logStorageService.GetSignedURL(c.Request.Context(), metadata.LogID, userID, emailStr, signedURLExpiry)
			if err == nil {
				logResp.SignedURL = &signedURL
				expiry := time.Now().Add(signedURLExpiry)
				logResp.SignedURLExpiry = &expiry
			}
		}

		response.Logs = append(response.Logs, logResp)
	}

	c.JSON(http.StatusOK, response)
}

// getLog handles GET /monitoring-service/logs/:id
// Returns log metadata and optionally generates a signed URL
func (s *Server) getLog(c *gin.Context) {
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

	logID := c.Param("id")
	if logID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Log ID is required"})
		return
	}

	// Check if signed URL should be generated
	includeSignedURL := c.Query("include_signed_url") != "false" // Default to true
	signedURLExpiry := 15 * time.Minute
	if expiryStr := c.Query("signed_url_expiry_seconds"); expiryStr != "" {
		if parsed, err := strconv.Atoi(expiryStr); err == nil && parsed > 0 {
			signedURLExpiry = time.Duration(parsed) * time.Second
		}
	}

	// Get log metadata (this will record access audit)
	// For single log retrieval, we need to implement a GetLogMetadata method
	// For now, we'll use SearchLogs with a specific log_id filter
	filters := map[string]interface{}{"log_id": logID}
	metadataList, _, err := s.logStorageService.SearchLogs(c.Request.Context(), userID, emailStr, filters, 1, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve log",
		})
		return
	}

	if len(metadataList) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Log not found"})
		return
	}

	metadata := metadataList[0]

	// Convert to response format
	logResp := LogMetadataResponse{
		ID:              metadata.ID.String(),
		LogID:           metadata.LogID,
		CorrelationID:   metadata.CorrelationID,
		TraceID:         metadata.TraceID,
		ServiceName:     metadata.ServiceName,
		ServiceVersion:  metadata.ServiceVersion,
		Environment:     metadata.Environment,
		Severity:        metadata.Severity,
		EventType:       metadata.EventType,
		Category:        metadata.Category,
		MessageDigest:   metadata.MessageDigest,
		MessagePreview:  metadata.MessagePreview,
		UserType:        metadata.UserType,
		RequestID:       metadata.RequestID,
		RequestMethod:   metadata.RequestMethod,
		RequestPath:     metadata.RequestPath,
		Timestamp:       metadata.Timestamp,
		Status:          metadata.Status,
		RetentionPolicy: metadata.RetentionPolicy,
		PIIDetected:     metadata.PIIDetected,
		PIITypes:        metadata.PIITypes,
		ComplianceTags:  metadata.ComplianceTags,
		Metadata:        metadata.Metadata,
		Tags:            metadata.Tags,
	}

	// Handle nullable fields
	if metadata.TenantID != nil {
		tenantIDStr := metadata.TenantID.String()
		logResp.TenantID = &tenantIDStr
	}
	if metadata.UserID != nil {
		userIDStr := metadata.UserID.String()
		logResp.UserID = &userIDStr
	}
	if metadata.SourceIP != nil {
		ipStr := *metadata.SourceIP
		logResp.SourceIP = &ipStr
	}
	if metadata.UserAgent != nil {
		uaStr := *metadata.UserAgent
		logResp.UserAgent = &uaStr
	}
	if metadata.ResponseStatus != nil {
		logResp.ResponseStatus = metadata.ResponseStatus
	}
	if metadata.DurationMs != nil {
		logResp.DurationMs = metadata.DurationMs
	}

	// Generate signed URL if requested
	if includeSignedURL {
		signedURL, err := s.logStorageService.GetSignedURL(c.Request.Context(), metadata.LogID, userID, emailStr, signedURLExpiry)
		if err == nil {
			logResp.SignedURL = &signedURL
			expiry := time.Now().Add(signedURLExpiry)
			logResp.SignedURLExpiry = &expiry
		}
	}

	c.JSON(http.StatusOK, gin.H{"log": logResp})
}
