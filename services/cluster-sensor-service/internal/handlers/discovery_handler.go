package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type DiscoveryHandler struct {
	discoveryService *services.DiscoveryService
	rateLimiter      *services.RateLimiter
	alertService     *services.AlertService
	natsClient       *events.NATSClient
}

// NewDiscoveryHandler creates a new handler. The natsClient should be the
// shared NATSClient created at service startup to avoid multiple connections.
func NewDiscoveryHandler(discoveryService *services.DiscoveryService, rateLimiter *services.RateLimiter, alertService *services.AlertService, natsClient *events.NATSClient) *DiscoveryHandler {
	return &DiscoveryHandler{
		discoveryService: discoveryService,
		rateLimiter:      rateLimiter,
		alertService:     alertService,
		natsClient:       natsClient,
	}
}

func (h *DiscoveryHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": "cluster-sensor-service",
		"status":  "healthy",
		"version": version.Get(),
	})
}

// extractTenantID delegates to shared middleware for UUID extraction,
// returning the string representation for handler compatibility.
func extractTenantID(c *gin.Context) (string, error) {
	tid, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		return "", fmt.Errorf("tenant_id required")
	}
	return tid.String(), nil
}

// authorizeJob fetches a discovery job by its :id path param and confirms it
// belongs to the caller's tenant. The underlying DiscoveryService.GetJob runs on
// the BYPASSRLS role (it is also used by the tenant-agnostic NATS job_processor),
// so tenant isolation for the user-facing by-id routes is enforced HERE by
// comparing the row's tenant_id to the JWT tenant. A cross-tenant (or unknown)
// job id returns 404 — never leaking existence — mirroring the sensor-manager
// IDOR fix. On any failure it writes the response and returns ok=false.
func (h *DiscoveryHandler) authorizeJob(c *gin.Context) (*models.DiscoveryJob, bool) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return nil, false
	}
	jobID := c.Param("id")
	job, err := h.discoveryService.GetJob(jobID)
	if err != nil || job == nil || job.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return nil, false
	}
	return job, true
}

// Helper function to extract user ID from context
func extractUserID(c *gin.Context) (string, error) {
	userIDVal, exists := c.Get("userID")
	if !exists {
		return "", fmt.Errorf("user_id required")
	}
	if uid, ok := userIDVal.(string); ok {
		return uid, nil
	}
	if uidUUID, ok := userIDVal.(uuid.UUID); ok {
		return uidUUID.String(), nil
	}
	return "", fmt.Errorf("invalid user_id format")
}

func (h *DiscoveryHandler) CreateJob(c *gin.Context) {
	// Get tenant ID from context (set by auth middleware from JWT)
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user ID from context (set by auth middleware from JWT)
	userID, err := extractUserID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Read raw body for logging
	bodyBytes, _ := c.GetRawData()
	log.Printf("[DiscoveryHandler] Received request body: %s", string(bodyBytes))

	// Create a new reader from the bytes for binding
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var req models.CreateDiscoveryJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[DiscoveryHandler] JSON binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	log.Printf("[DiscoveryHandler] Successfully parsed request: targets=%v, protocols=%v, ports=%v", req.Targets, req.Protocols, req.Ports)

	// Check rate limits
	err = h.rateLimiter.CheckRateLimit(tenantID)
	if err != nil {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
		return
	}

	// Create job
	job, err := h.discoveryService.CreateJob(tenantID, userID, req)
	if err != nil {
		log.Printf("[DiscoveryHandler] CreateJob error: %v", err)
		// Sensor dispatch is not implemented; say so instead of collapsing it
		// into the generic message. A caller must be able to tell "you asked
		// for something that does not exist" from "your request was malformed",
		// because the previous behaviour was to accept it and run the scan
		// somewhere else entirely.
		if errors.Is(err, services.ErrSensorDispatchUnsupported) {
			sharedapi.BadRequest(c, err.Error())
			return
		}
		sharedapi.BadRequest(c, "failed to create job")
		return
	}

	// Publish job to NATS queue
	if h.natsClient != nil && h.natsClient.IsConnected() {
		tenantUUID, _ := uuid.Parse(tenantID)
		if err := events.PublishJSON(h.natsClient, events.SubjectDiscoveryJobsSubmit, events.DiscoveryJobEvent{
			EventID:   uuid.New(),
			TenantID:  tenantUUID,
			JobID:     job.ID,
			Timestamp: job.CreatedAt,
		}); err != nil {
			log.Printf("[DiscoveryHandler] Failed to publish job %s to NATS: %v", job.ID, err)
		}
	}

	c.JSON(http.StatusAccepted, models.DiscoveryJobResponse{Job: *job})
}

func (h *DiscoveryHandler) GetJobs(c *gin.Context) {
	// Get tenant ID from context (set by auth middleware from JWT)
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Parse pagination parameters
	page := 1
	pageSize := 20
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Parse status filter
	status := c.Query("status")

	// Parse date range filters
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	jobs, total, err := h.discoveryService.GetJobs(tenantID, page, pageSize, status, startDate, endDate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get jobs"})
		return
	}

	response := models.DiscoveryJobsResponse{
		Jobs:       jobs,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: (total + pageSize - 1) / pageSize,
	}

	c.JSON(http.StatusOK, response)
}

func (h *DiscoveryHandler) GetJob(c *gin.Context) {
	job, ok := h.authorizeJob(c)
	if !ok {
		return
	}

	c.JSON(http.StatusOK, job)
}

func (h *DiscoveryHandler) GetJobStatus(c *gin.Context) {
	job, ok := h.authorizeJob(c)
	if !ok {
		return
	}

	// Calculate progress (simplified)
	progress := 0
	switch job.Status {
	case "running":
		progress = 50
	case "completed":
		progress = 100
	}

	status := models.DiscoveryJobStatusResponse{
		JobID:       job.ID,
		Status:      job.Status,
		Progress:    progress,
		Message:     getStatusMessage(job.Status),
		StartedAt:   job.StartedAt,
		CompletedAt: job.CompletedAt,
	}

	c.JSON(http.StatusOK, status)
}

func (h *DiscoveryHandler) CancelJob(c *gin.Context) {
	job, ok := h.authorizeJob(c)
	if !ok {
		return
	}

	if err := h.discoveryService.UpdateJobStatus(job.ID, "cancelled", nil); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "job cancelled"})
}

// RetryJob manually triggers processing of a queued job by republishing to NATS
func (h *DiscoveryHandler) RetryJob(c *gin.Context) {
	job, ok := h.authorizeJob(c)
	if !ok {
		return
	}
	jobID := job.ID

	if job.Status != "queued" && job.Status != "failed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "job can only be retried if status is queued or failed"})
		return
	}

	// Republish to NATS
	if h.natsClient != nil && h.natsClient.IsConnected() {
		if err := events.PublishJSON(h.natsClient, events.SubjectDiscoveryJobsSubmit, events.DiscoveryJobEvent{
			EventID: uuid.New(),
			JobID:   jobID,
		}); err != nil {
			log.Printf("[DiscoveryHandler] Failed to republish job %s: %v", jobID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to republish job"})
			return
		}
		log.Printf("[DiscoveryHandler] Republished job %s to NATS for processing", jobID)
		c.JSON(http.StatusOK, gin.H{"message": "job republished for processing", "job_id": jobID})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "NATS connection not available"})
	}
}

func (h *DiscoveryHandler) GetJobResults(c *gin.Context) {
	job, ok := h.authorizeJob(c)
	if !ok {
		return
	}
	jobID := job.ID

	// Parse pagination parameters
	page := 1
	pageSize := 20
	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	results, err := h.discoveryService.GetJobResults(jobID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "results not found"})
		return
	}

	c.JSON(http.StatusOK, results)
}

func (h *DiscoveryHandler) ApproveResults(c *gin.Context) {
	// Approval is now handled through the unified sensor_discoveries pipeline
	// and the asset approval workflow in inventory-service
	c.JSON(http.StatusGone, gin.H{"error": "deprecated", "message": "Discovery approval is now handled through the unified discovery pipeline. Use the asset approval workflow instead."})
}

func (h *DiscoveryHandler) RejectResults(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{"error": "deprecated", "message": "Discovery rejection is now handled through the unified discovery pipeline. Use the asset approval workflow instead."})
}

func (h *DiscoveryHandler) GetApprovalQueue(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{"error": "deprecated", "message": "The discovery approval queue has been replaced by the unified discovery pipeline. Use the asset approval workflow instead."})
}

func (h *DiscoveryHandler) BulkApprove(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{"error": "deprecated", "message": "Bulk approval is now handled through the unified discovery pipeline. Use the asset approval workflow instead."})
}

func (h *DiscoveryHandler) BulkReject(c *gin.Context) {
	c.JSON(http.StatusGone, gin.H{"error": "deprecated", "message": "Bulk rejection is now handled through the unified discovery pipeline. Use the asset approval workflow instead."})
}

func (h *DiscoveryHandler) GetRateLimits(c *gin.Context) {
	// Get tenant ID from context (set by auth middleware from JWT)
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	rateLimit, err := h.rateLimiter.GetRateLimit(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get rate limits"})
		return
	}

	c.JSON(http.StatusOK, rateLimit)
}

func (h *DiscoveryHandler) UpdateRateLimits(c *gin.Context) {
	// Get tenant ID from context (set by auth middleware from JWT)
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var req models.RateLimitConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	err = h.rateLimiter.UpdateRateLimit(tenantID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update rate limits"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "rate limits updated"})
}

func (h *DiscoveryHandler) GetAlertConfigs(c *gin.Context) {
	// Get tenant ID from context (set by auth middleware from JWT)
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	configs, err := h.alertService.GetAlertConfigs(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get alert configs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

func (h *DiscoveryHandler) UpdateAlertConfigs(c *gin.Context) {
	// Get tenant ID from context (set by auth middleware from JWT)
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var req models.AlertConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	err = h.alertService.UpdateAlertConfig(tenantID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update alert config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "alert config updated"})
}

func getStatusMessage(status string) string {
	switch status {
	case "queued":
		return "Job is queued for processing"
	case "running":
		return "Job is currently running"
	case "completed":
		return "Job completed successfully"
	case "failed":
		return "Job failed to complete"
	case "cancelled":
		return "Job was cancelled"
	default:
		return "Unknown status"
	}
}
