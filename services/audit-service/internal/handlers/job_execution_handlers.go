package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

type JobExecutionHandler struct {
	service *services.JobExecutionService
}

func NewJobExecutionHandler(service *services.JobExecutionService) *JobExecutionHandler {
	return &JobExecutionHandler{service: service}
}

// LogJobStart handles POST /api/v1/audit-service/job-execution-logs/start (internal use)
func (h *JobExecutionHandler) LogJobStart(c *gin.Context) {
	var req struct {
		JobID       uuid.UUID              `json:"job_id" binding:"required"`
		JobType     string                 `json:"job_type" binding:"required"`
		JobName     *string                `json:"job_name,omitempty"`
		TenantID    *uuid.UUID             `json:"tenant_id,omitempty"`
		InitiatedBy *uuid.UUID             `json:"initiated_by,omitempty"`
		Metadata    map[string]interface{} `json:"metadata,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	logID, err := h.service.LogJobStart(c.Request.Context(), req.JobID, req.JobType, func() string {
		if req.JobName != nil {
			return *req.JobName
		}
		return ""
	}(), req.TenantID, req.InitiatedBy, req.Metadata)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log job start"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": logID, "message": "Job start logged successfully"})
}

// LogJobProgress handles POST /api/v1/audit-service/job-execution-logs/:id/progress (internal use)
func (h *JobExecutionHandler) LogJobProgress(c *gin.Context) {
	logIDStr := c.Param("id")
	logID, err := uuid.Parse(logIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid log ID"})
		return
	}

	var req struct {
		ItemsProcessed int `json:"items_processed"`
		ItemsSucceeded int `json:"items_succeeded"`
		ItemsFailed    int `json:"items_failed"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err = h.service.LogJobProgress(c.Request.Context(), logID, req.ItemsProcessed, req.ItemsSucceeded, req.ItemsFailed)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log job progress"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Job progress logged successfully"})
}

// LogJobCompletion handles POST /api/v1/audit-service/job-execution-logs/:id/complete (internal use)
func (h *JobExecutionHandler) LogJobCompletion(c *gin.Context) {
	logIDStr := c.Param("id")
	logID, err := uuid.Parse(logIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid log ID"})
		return
	}

	var req struct {
		Status       string                 `json:"status" binding:"required"`
		ErrorMessage *string                `json:"error_message,omitempty"`
		ErrorDetails map[string]interface{} `json:"error_details,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err = h.service.LogJobCompletion(c.Request.Context(), logID, req.Status, req.ErrorMessage, req.ErrorDetails)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log job completion"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Job completion logged successfully"})
}

// GetJobExecutionLogs handles GET /api/v1/audit-service/job-execution-logs
func (h *JobExecutionHandler) GetJobExecutionLogs(c *gin.Context) {
	filters := models.JobExecutionLogFilters{
		Page:      1,
		PageSize:  50,
		SortBy:    "started_at",
		SortOrder: "DESC",
	}

	// Parse query parameters
	if jobIDStr := c.Query("job_id"); jobIDStr != "" {
		if jobID, err := uuid.Parse(jobIDStr); err == nil {
			filters.JobID = &jobID
		}
	}

	if jobTypes := c.QueryArray("job_type"); len(jobTypes) > 0 {
		filters.JobType = jobTypes
	}

	if tenantIDStr := c.Query("tenant_id"); tenantIDStr != "" {
		if tenantID, err := uuid.Parse(tenantIDStr); err == nil {
			filters.TenantID = &tenantID
		}
	}

	// Enforce tenant scoping for tenant users
	if middleware.GetUserType(c) == middleware.UserTypeTenant {
		tenantID := middleware.GetTenantID(c)
		if tenantID == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tenant context required"})
			return
		}
		filters.TenantID = tenantID
	}

	if initiatedByStr := c.Query("initiated_by"); initiatedByStr != "" {
		if initiatedBy, err := uuid.Parse(initiatedByStr); err == nil {
			filters.InitiatedBy = &initiatedBy
		}
	}

	if statuses := c.QueryArray("status"); len(statuses) > 0 {
		filters.Status = statuses
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
		filters.SortOrder = sortOrder
	}

	logs, total, err := h.service.GetJobExecutionLogs(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve job execution logs"})
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
