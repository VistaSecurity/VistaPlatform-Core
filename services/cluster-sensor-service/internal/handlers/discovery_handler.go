package handlers

import (
	"errors"
	"fmt"
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

// MaxRequestBytes caps every request body cluster-sensor-service accepts.
//
// Derived from the largest request the service will actually process, not
// picked round. DiscoveryService.CreateJob refuses more than 1000 targets
// (matching the `max_targets_per_job` rate-limit default), and the longest
// plausible target token is an IPv6 CIDR — 43 characters, ~46 bytes once
// JSON-quoted and comma-separated — so a maximal target list is ~46 KiB. The
// only other list that can grow is `ports`: every TCP port, all 65,535 of them,
// is ~400 KiB. 1 MiB is therefore more than twice the largest legitimate
// request, and three orders of magnitude below the pod's 256 MiB limit.
//
// Raising it is a decision about what the service accepts, not a tuning knob:
// anything near the pod limit puts a handful of concurrent requests back within
// reach of the OOM killer, which is the bug this closes (H10).
const MaxRequestBytes = 1 << 20

// maxRequestBytesMessage is what a refused caller reads. It names the number,
// because "too large" is not actionable.
const maxRequestBytesMessage = "the request body exceeds the 1 MiB limit"

// serverAuthorityJobOptions are the job options whose value selects which
// authorization path a discovery job is judged by. They are the server's to
// state, not the caller's to claim, so CreateJob strips them from any request
// that is not an HMAC-verified internal service call.
//
//   - origin: dispatchguard.IsAutomaticScan keys on "auto_scan".
//   - identity_*: select the identity-enrichment dispatch path, whose replay
//     token and observation/scope ids are minted by the coordinator.
var serverAuthorityJobOptions = []string{
	"origin",
	"identity_enrichment_request_id",
	"identity_observation_id",
	"identity_network_scope",
}

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

// bindJSON binds the request body, answering 413 when the router's MaxBody
// ceiling was reached and 400 for anything else.
//
// The 413 branch is not cosmetic. MaxBytesReader surfaces as a read error, so
// without it every over-cap request — the exact thing the cap exists to refuse
// — would be reported to the caller as a malformed document, which is both
// wrong and unactionable. The Content-Length path is refused by the middleware
// before a handler runs; this covers a chunked body, which declares no length.
func bindJSON(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		if sharedapi.RequestBodyTooLarge(err) {
			sharedapi.PayloadTooLarge(c, maxRequestBytesMessage)
			return false
		}
		log.Printf("[DiscoveryHandler] JSON binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return false
	}
	return true
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

	// The body is bound straight from the request. It used to be read whole
	// with c.GetRawData(), string()ed into a log line, and then copied into a
	// fresh bytes.Buffer for binding — three live copies of a body the caller
	// chose the size of, in a pod limited to 256 MiB (H10). The router's
	// MaxBody middleware now caps it, and nothing here holds a second copy.
	//
	// The log line is gone rather than truncated: a discovery job request is
	// tenant input, it reaches pod logs verbatim, and the parsed summary below
	// is what anyone debugging this actually reads.
	var req models.CreateDiscoveryJobRequest
	if !bindJSON(c, &req) {
		return
	}

	// ORIGIN IS SERVER-DERIVED (#H5).
	//
	// `options.origin` decides which policy engine a job is judged by:
	// dispatchguard.IsAutomaticScan keys on it, and the enrichment keys below
	// select the identity-enrichment dispatch path. Both were read straight out
	// of caller-supplied JSON, which let a browser choose its own guard.
	//
	// Only an HMAC-verified internal service call — inventory-service's
	// unattended sweep, which has no browser behind it — may DECLARE an
	// origin. Anything carrying a person's JWT is "manual" by construction,
	// whatever it asked for.
	if !sharedmw.IsInternalCall(c) {
		for _, reserved := range serverAuthorityJobOptions {
			delete(req.Options, reserved)
		}
		if req.Options == nil {
			req.Options = map[string]interface{}{}
		}
		req.Options["origin"] = "manual"
	}
	log.Printf("[DiscoveryHandler] Parsed request: %d target(s), %d protocol(s), %d port(s)", len(req.Targets), len(req.Protocols), len(req.Ports))

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
		// A `sensors` job that cannot run is refused with a reason and a
		// status a caller can act on, not collapsed into the generic message.
		// A caller must be able to tell "that sensor is offline" (409, try
		// later or pick another) from "that sensor does not exist" (404) from
		// "your request was malformed" (400), because the previous behaviour
		// was to accept the job and run the scan somewhere else entirely.
		if writeTargetAuthorizationError(c, err) {
			return
		}
		switch {
		case errors.Is(err, services.ErrSensorNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case errors.Is(err, services.ErrSensorOffline):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case errors.Is(err, services.ErrSensorDispatchInvalid):
			sharedapi.BadRequest(c, err.Error())
		default:
			sharedapi.BadRequest(c, "failed to create job")
		}
		return
	}

	// A person confirmed targets outside the tenant's registered networks:
	// record who, when, what they named and what it resolved to ( W5.13b).
	if len(job.ExternalTargets) > 0 {
		auditExternalTargets(c, tenantID, userID, job)
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

	// kind: "automatic" (the sweep) or "manual" (everything else).
	kind := c.Query("kind")

	// Parse date range filters
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	jobs, total, err := h.discoveryService.GetJobs(tenantID, page, pageSize, status, kind, startDate, endDate)
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
	if !bindJSON(c, &req) {
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
	if !bindJSON(c, &req) {
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
