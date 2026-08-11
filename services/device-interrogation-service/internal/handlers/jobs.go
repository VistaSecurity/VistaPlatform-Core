package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// jobResultsPayload is used to parse device_jobs.results JSON for assets_discovered
type jobResultsPayload struct {
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// assetsDiscoveredFromResults extracts assets_discovered from job results JSON.
// Prefers metadata.assets_count; falls back to metadata.devices_count for cloud discovery.
func assetsDiscoveredFromResults(resultsJSON string) *int {
	if resultsJSON == "" {
		return nil
	}
	var payload jobResultsPayload
	if err := json.Unmarshal([]byte(resultsJSON), &payload); err != nil {
		return nil
	}
	if payload.Metadata == nil {
		return nil
	}
	// Prefer assets_count (crypto assets created), then devices_count (devices/resources found)
	for _, key := range []string{"assets_count", "devices_count"} {
		if v, ok := payload.Metadata[key]; ok && v != nil {
			switch n := v.(type) {
			case float64:
				val := int(n)
				return &val
			case int:
				return &n
			case int64:
				val := int(n)
				return &val
			}
		}
	}
	return nil
}

// InterrogationJob represents a job for the API response
type InterrogationJob struct {
	ID               uuid.UUID              `json:"id"`
	TenantID         uuid.UUID              `json:"tenant_id"`
	JobType          string                 `json:"job_type"`
	Status           string                 `json:"status"`
	DeviceID         *uuid.UUID             `json:"device_id,omitempty"`
	DeviceName       *string                `json:"device_name,omitempty"`
	DeviceType       *string                `json:"device_type,omitempty"`
	IntegrationID    *uuid.UUID             `json:"integration_id,omitempty"`
	IntegrationName  *string                `json:"integration_name,omitempty"`
	CloudProvider    *string                `json:"cloud_provider,omitempty"`
	StartedAt        *time.Time             `json:"started_at,omitempty"`
	CompletedAt      *time.Time             `json:"completed_at,omitempty"`
	ErrorMessage     *string                `json:"error_message,omitempty"`
	Progress         *int                   `json:"progress,omitempty"`
	AssetsDiscovered *int                   `json:"assets_discovered,omitempty"`
	DurationSeconds  *int                   `json:"duration_seconds,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// AdminInterrogationJob is the cross-tenant view of an interrogation job for the
// platform-admin "Jobs & Queues" view (read-only). It carries the same telemetry
// as InterrogationJob plus per-row tenant identity (name/slug from a cheap join)
// and the assigned worker (device_jobs.agent_id). Gated by RequirePlatformAdmin.
type AdminInterrogationJob struct {
	ID               uuid.UUID  `json:"id"`
	TenantID         uuid.UUID  `json:"tenant_id"`
	TenantName       string     `json:"tenant_name"`
	TenantSlug       string     `json:"tenant_slug"`
	JobType          string     `json:"job_type"`
	Status           string     `json:"status"`
	DeviceID         *uuid.UUID `json:"device_id,omitempty"`
	DeviceName       *string    `json:"device_name,omitempty"`
	DeviceType       *string    `json:"device_type,omitempty"`
	IntegrationID    *uuid.UUID `json:"integration_id,omitempty"`
	IntegrationName  *string    `json:"integration_name,omitempty"`
	CloudProvider    *string    `json:"cloud_provider,omitempty"`
	Worker           *uuid.UUID `json:"worker,omitempty"` // device_jobs.agent_id — the agent executing the job
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	ErrorMessage     *string    `json:"error_message,omitempty"`
	AssetsDiscovered *int       `json:"assets_discovered,omitempty"`
	DurationSeconds  *int       `json:"duration_seconds,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// JobStats represents job statistics
type JobStats struct {
	Total                  int          `json:"total"`
	Pending                int          `json:"pending"`
	InProgress             int          `json:"in_progress"`
	Completed              int          `json:"completed"`
	Failed                 int          `json:"failed"`
	Last24h                Last24hStats `json:"last_24h"`
	AverageDurationSeconds *float64     `json:"average_duration_seconds,omitempty"`
}

// Last24hStats represents stats for the last 24 hours
type Last24hStats struct {
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// JobHandlers handles job-related operations. It depends on the jobStore
// interface (the SQL-backed jobRepository in jobs_repository.go satisfies it),
// which is what makes these handlers contract-testable without a database.
type JobHandlers struct {
	store jobStore
}

// NewJobHandlers creates a new JobHandlers backed by the SQL job repository. db
// is the RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS
// (crypto_bypass) connection used by the cross-tenant admin paths.
func NewJobHandlers(db, bypassDB *sql.DB) *JobHandlers {
	return &JobHandlers{store: newJobRepository(db, bypassDB)}
}

// ListJobs lists interrogation jobs with optional filters
func (h *JobHandlers) ListJobs(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	f := JobListFilters{
		Page:          page,
		PageSize:      pageSize,
		Status:        c.QueryArray("status"),
		JobType:       c.Query("job_type"),
		DeviceID:      c.Query("device_id"),
		IntegrationID: c.Query("integration_id"),
	}

	jobs, total, err := h.store.ListJobs(c.Request.Context(), tenantID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query jobs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"jobs":      jobs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ListAdminJobs lists interrogation jobs across ALL tenants for the platform-admin
// Jobs & Queues view (read-only). It takes no tenant from context — the cross-tenant
// roll-up is the whole point — and must be gated by RequirePlatformAdmin in the router.
// Same optional filters as ListJobs (status, job_type, device_id, integration_id) and
// pagination, just without tenant scoping.
func (h *JobHandlers) ListAdminJobs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	// Optional operator-scope narrowing: filter the cross-tenant roll-up to one
	// tenant server-side, so other tenants' rows are never shipped to the client.
	// Validate as a UUID (reject a malformed value with 400 rather than letting it
	// surface as a 500 from the typed tenant_id column).
	tenantFilter := c.Query("tenant_id")
	if tenantFilter != "" {
		if _, err := uuid.Parse(tenantFilter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
			return
		}
	}

	f := JobListFilters{
		Page:          page,
		PageSize:      pageSize,
		Status:        c.QueryArray("status"),
		JobType:       c.Query("job_type"),
		DeviceID:      c.Query("device_id"),
		IntegrationID: c.Query("integration_id"),
		TenantID:      tenantFilter,
	}

	jobs, total, err := h.store.ListAdminJobs(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query jobs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"jobs":      jobs,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetJob retrieves a single job by ID
func (h *JobHandlers) GetJob(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	job, err := h.store.GetJob(c.Request.Context(), tenantID, jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get job"})
		return
	}
	if job == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"job": job})
}

// GetJobStats returns job statistics
func (h *JobHandlers) GetJobStats(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	stats, err := h.store.GetJobStats(c.Request.Context(), tenantID)
	if err != nil {
		// Preserve prior behavior: return empty stats (200) rather than 500.
		c.JSON(http.StatusOK, gin.H{"stats": JobStats{}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// GetJobResults retrieves results for a completed job
func (h *JobHandlers) GetJobResults(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	status, found, err := h.store.GetJobResultStatus(c.Request.Context(), tenantID, jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get job"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	// Return results (placeholder shape; may be empty if job not completed).
	result := map[string]interface{}{
		"job_id":  jobID.String(),
		"status":  status,
		"assets":  []interface{}{},
		"summary": map[string]int{"total_assets": 0, "new_assets": 0, "updated_assets": 0},
	}

	c.JSON(http.StatusOK, result)
}

// RetryJob retries a failed job
func (h *JobHandlers) RetryJob(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	status, found, err := h.store.GetJobStatus(c.Request.Context(), tenantID, jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get job"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	if status != "failed" && status != "cancelled" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only failed or cancelled jobs can be retried"})
		return
	}

	if err := h.store.ResetJobToPending(c.Request.Context(), tenantID, jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retry job"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Job queued for retry",
		"job": map[string]interface{}{
			"id":     jobID,
			"status": "pending",
		},
	})
}

// CancelJob cancels a pending or in-progress job
func (h *JobHandlers) CancelJob(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	status, found, err := h.store.GetJobStatus(c.Request.Context(), tenantID, jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get job"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	if status != "pending" && status != "in_progress" && status != "assigned" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only pending or in-progress jobs can be cancelled"})
		return
	}

	if err := h.store.CancelJobByID(c.Request.Context(), tenantID, jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel job"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Job cancelled"})
}

// RetryJobAdmin retries a failed/cancelled job across ANY tenant. Unlike RetryJob
// it is not tenant-scoped — the router gates it behind RequirePlatformAdmin and the
// job is looked up by id alone. This backs the Support cockpit's "Job Repair" action.
func (h *JobHandlers) RetryJobAdmin(c *gin.Context) {
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	status, jobTenantID, found, err := h.store.GetJobStatusAdmin(c.Request.Context(), jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get job"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}
	if status != "failed" && status != "cancelled" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only failed or cancelled jobs can be retried"})
		return
	}
	// The mutation is scoped to the job's resolved owning tenant (RLS).
	if err := h.store.ResetJobToPending(c.Request.Context(), jobTenantID, jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retry job"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Job queued for retry",
		"job":     map[string]interface{}{"id": jobID, "status": "pending"},
	})
}

// CancelJobAdmin cancels a pending/assigned/in-progress job across ANY tenant.
// Router-gated by RequirePlatformAdmin; looked up by id alone. Backs Job Repair.
func (h *JobHandlers) CancelJobAdmin(c *gin.Context) {
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	status, jobTenantID, found, err := h.store.GetJobStatusAdmin(c.Request.Context(), jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get job"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}
	if status != "pending" && status != "in_progress" && status != "assigned" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only pending or in-progress jobs can be cancelled"})
		return
	}
	// The mutation is scoped to the job's resolved owning tenant (RLS).
	if err := h.store.CancelJobByID(c.Request.Context(), jobTenantID, jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel job"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Job cancelled"})
}

// GetActiveJobs returns currently active (pending or in-progress) jobs
func (h *JobHandlers) GetActiveJobs(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	jobs, err := h.store.GetActiveJobs(c.Request.Context(), tenantID)
	if err != nil {
		// Preserve prior behavior: degrade to an empty list (200) on error.
		c.JSON(http.StatusOK, gin.H{"jobs": []interface{}{}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"jobs": jobs})
}
