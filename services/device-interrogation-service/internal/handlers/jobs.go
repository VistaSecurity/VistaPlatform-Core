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

// jobResultsPayload is used to parse device_jobs.results JSON for assets_discovered.
// Processing is the post-processing verdict ResultProcessor.persist writes under
// the "processing" key (see processing_log.go) — when present, its "materialized"
// field is the honest count of what actually landed (findings created this run
// plus any the run's discovery job already carried), independent of which
// execution path (in-cluster router, platform agent, device agent) produced it.
type jobResultsPayload struct {
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Processing map[string]interface{} `json:"processing,omitempty"`
}

// assetsDiscoveredFromResults extracts assets_discovered from job results JSON.
//
// Prefers processing.materialized: it is written by ResultProcessor after the
// findings pipeline actually ran, so it reflects what was materialized rather
// than what the executor merely counted in its own payload. Falls back to
// metadata.assets_count then metadata.devices_count for job types /
// execution paths that never go through ResultProcessor (e.g. the direct
// in-service cloud discovery handler, which writes sensor_discoveries itself
// without a processing log).
// CloudEnumerationCounts is what a cloud discovery run's enumeration half found
// — compute instances, virtual networks, subnets and the distinct security
// groups it saw membership of (BUILD_PLAN 2.4).
//
// It is surfaced on the job row rather than left inside `results` because the
// Job Logs stream's one line per run is where an operator looks to see whether
// a run did what they expected, and "42 assets" does not say whether the
// enumeration ran at all.
type CloudEnumerationCounts struct {
	Instances      int `json:"instances"`
	Networks       int `json:"networks"`
	Subnets        int `json:"subnets"`
	SecurityGroups int `json:"security_groups"`
}

// HostInventoryCounts is what a host-inventory run put into the inventory
// (asset-inventory workstream 2.11b), surfaced on the job row for the same
// reason the enumeration counts are: the Job Logs stream's one line per run is
// where an operator looks to see whether a run did what they expected, and
// "1 asset" says nothing about whether the package list or the sockets landed.
//
// It is a narrower projection than services.HostInventoryCounts on purpose.
// That type is the consumer's full record and lives on the job row; this is the
// handful a log line can show, and widening it means deciding what a log line
// is for rather than copying a struct.
type HostInventoryCounts struct {
	// AssetID is the asset the collection landed on, empty when the identity
	// was contested and nothing was created.
	AssetID   string `json:"asset_id,omitempty"`
	Facts     int    `json:"facts"`
	Endpoints int    `json:"endpoints"`
	// Packages is the number of ACTIVE measured installs after the run — the
	// number an inventory query would return — not the number the collector
	// enumerated. Absent when the package step failed, which is not the same as
	// zero.
	Packages        *int `json:"packages,omitempty"`
	InstallsCreated int  `json:"installs_created"`
	InstallsRemoved int  `json:"installs_removed"`
	// Contested says a merge proposal is waiting because the identity could not
	// be settled. Neither a failure nor a success, and the log line must not
	// read as either.
	Contested bool `json:"contested,omitempty"`
}

// hostInventoryFromResults extracts the host-inventory counts from a job's
// results JSON, or nil when the run recorded none.
//
// Nil and a zeroed struct are different answers, as with the enumeration
// counts: nil means this was not a host inventory (or it never reached the
// consumer), while zeros mean one ran and landed nothing.
func hostInventoryFromResults(resultsJSON string) *HostInventoryCounts {
	if resultsJSON == "" {
		return nil
	}
	var payload jobResultsPayload
	if err := json.Unmarshal([]byte(resultsJSON), &payload); err != nil {
		return nil
	}
	raw, ok := payload.Processing["host_inventory"]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var stored struct {
		AssetID         string `json:"asset_id"`
		Facts           int    `json:"facts"`
		Endpoints       int    `json:"endpoints"`
		InstallsActive  *int   `json:"installs_active"`
		PackagesCounted *int   `json:"packages_enumerated"`
		InstallsCreated int    `json:"installs_created"`
		InstallsRemoved int    `json:"installs_removed"`
		Contested       bool   `json:"contested"`
	}
	if err := json.Unmarshal(encoded, &stored); err != nil {
		return nil
	}
	out := &HostInventoryCounts{
		AssetID:         stored.AssetID,
		Facts:           stored.Facts,
		Endpoints:       stored.Endpoints,
		InstallsCreated: stored.InstallsCreated,
		InstallsRemoved: stored.InstallsRemoved,
		Contested:       stored.Contested,
	}
	// `installs_active` is only meaningful when the package step succeeded,
	// which is exactly what `packages_enumerated` being present says. Reading
	// the first without checking the second would report 0 packages for a host
	// whose dpkg could not be read.
	if stored.PackagesCounted != nil {
		active := 0
		if stored.InstallsActive != nil {
			active = *stored.InstallsActive
		}
		out.Packages = &active
	}
	return out
}

// enumerationFromResults extracts the enumeration counts from a job's results
// JSON, or nil when the run recorded none.
//
// Nil and a zeroed struct are different answers and both occur: a run with
// enumeration switched off writes no block at all, while a run that enumerated
// an empty account writes four zeros. Flattening them would make "we did not
// look" and "there was nothing there" the same row, which is the three-valued
// mistake this codebase keeps paying for.
func enumerationFromResults(resultsJSON string) *CloudEnumerationCounts {
	if resultsJSON == "" {
		return nil
	}
	var payload jobResultsPayload
	if err := json.Unmarshal([]byte(resultsJSON), &payload); err != nil {
		return nil
	}
	raw, ok := payload.Metadata["enumeration"]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var counts CloudEnumerationCounts
	if err := json.Unmarshal(encoded, &counts); err != nil {
		return nil
	}
	return &counts
}

func assetsDiscoveredFromResults(resultsJSON string) *int {
	if resultsJSON == "" {
		return nil
	}
	var payload jobResultsPayload
	if err := json.Unmarshal([]byte(resultsJSON), &payload); err != nil {
		return nil
	}
	if payload.Processing != nil {
		if v, ok := payload.Processing["materialized"]; ok && v != nil {
			if n, ok := numberFromInterface(v); ok {
				return &n
			}
		}
	}
	if payload.Metadata == nil {
		return nil
	}
	// Prefer assets_count (crypto assets created), then devices_count (devices/resources found)
	for _, key := range []string{"assets_count", "devices_count"} {
		if v, ok := payload.Metadata[key]; ok && v != nil {
			if n, ok := numberFromInterface(v); ok {
				return &n
			}
		}
	}
	return nil
}

// numberFromInterface coerces a JSON-decoded numeric value (always float64 from
// encoding/json, but int/int64 are accepted too for callers that build the map
// in Go rather than round-tripping through JSON) into an int.
func numberFromInterface(v interface{}) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

// executorLabel resolves device_jobs.agent_id (+ the joined device_agents.name,
// when present) into the human-readable string the UI shows for "which
// executor ran this job". A NULL agent_id means the in-cluster platform agent
// ran it — there is no row to name, and the job's Sensors & Agents fleet entry
// (the platform agent) carries no job-count columns of its own, so this label
// is the only place that attribution is visible.
func executorLabel(agentID *uuid.UUID, agentName *string) string {
	if agentID == nil {
		return "Platform Agent"
	}
	if agentName != nil && *agentName != "" {
		return *agentName
	}
	return "Device Agent"
}

// firstQuery returns the first non-empty value among the given query
// parameters, so a filter can be renamed without breaking the clients still
// sending the old name.
func firstQuery(c *gin.Context, names ...string) string {
	for _, n := range names {
		if v := c.Query(n); v != "" {
			return v
		}
	}
	return ""
}

// InterrogationJob represents a job for the API response
type InterrogationJob struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`
	JobType  string    `json:"job_type"`
	Status   string    `json:"status"`
	// AssetID is device_jobs.asset_id — the asset the job targets.
	AssetID *uuid.UUID `json:"asset_id,omitempty"`
	// DeviceID carries the SAME value as AssetID, for one release, so a client
	// that has not moved off the old name keeps working.
	//
	// Deprecated: use AssetID.
	DeviceID         *uuid.UUID `json:"device_id,omitempty"`
	DeviceName       *string    `json:"device_name,omitempty"`
	DeviceType       *string    `json:"device_type,omitempty"`
	IntegrationID    *uuid.UUID `json:"integration_id,omitempty"`
	IntegrationName  *string    `json:"integration_name,omitempty"`
	CloudProvider    *string    `json:"cloud_provider,omitempty"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	ErrorMessage     *string    `json:"error_message,omitempty"`
	Progress         *int       `json:"progress,omitempty"`
	AssetsDiscovered *int       `json:"assets_discovered,omitempty"`
	// Enumeration is present only on a cloud discovery run whose enumeration
	// half actually ran (BUILD_PLAN 2.4). Absent means it did not run; four
	// zeros mean it ran and found nothing.
	Enumeration *CloudEnumerationCounts `json:"enumeration,omitempty"`
	// HostInventory is present only on a host_inventory run that reached the
	// consumer (BUILD_PLAN 2.11b). Absent means it did not; zeros mean it ran
	// and landed nothing.
	HostInventory *HostInventoryCounts `json:"host_inventory,omitempty"`
	// AgentID is device_jobs.agent_id — nil means the in-cluster platform agent
	// executed the job rather than a named device agent.
	AgentID *uuid.UUID `json:"agent_id,omitempty"`
	// Executor is the human-readable resolution of AgentID: "Platform Agent" or
	// the executing device agent's name. Always populated so the Jobs page and
	// job detail modal can show attribution without duplicating the fallback
	// logic client-side (see M-9: a completed job otherwise has no row on
	// Sensors & Agents that owns it, so "Never run" on that agent looks
	// contradicted by a job nothing on screen claims).
	Executor        string                 `json:"executor"`
	DurationSeconds *int                   `json:"duration_seconds,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// AdminInterrogationJob is the cross-tenant view of an interrogation job for the
// platform-admin "Jobs & Queues" view (read-only). It carries the same telemetry
// as InterrogationJob plus per-row tenant identity (name/slug from a cheap join)
// and the assigned worker (device_jobs.agent_id). Gated by RequirePlatformAdmin.
type AdminInterrogationJob struct {
	ID         uuid.UUID `json:"id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	TenantName string    `json:"tenant_name"`
	TenantSlug string    `json:"tenant_slug"`
	JobType    string    `json:"job_type"`
	Status     string    `json:"status"`
	// AssetID is device_jobs.asset_id; DeviceID is the deprecated alias carrying
	// the same value for one release.
	AssetID          *uuid.UUID `json:"asset_id,omitempty"`
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
		Page:     page,
		PageSize: pageSize,
		Status:   c.QueryArray("status"),
		JobType:  c.Query("job_type"),
		// `asset_id` is the current name; `device_id` is accepted for one release.
		DeviceID:      firstQuery(c, "asset_id", "device_id"),
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
		Page:     page,
		PageSize: pageSize,
		Status:   c.QueryArray("status"),
		JobType:  c.Query("job_type"),
		// `asset_id` is the current name; `device_id` is accepted for one release.
		DeviceID:      firstQuery(c, "asset_id", "device_id"),
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

	status, resultsJSON, found, err := h.store.GetJobResultStatus(c.Request.Context(), tenantID, jobID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get job"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	// Projected, never passed through — see job_results.go. Assets is empty
	// rather than absent when the job has not produced results yet.
	c.JSON(http.StatusOK, buildJobResults(jobID.String(), status, resultsJSON))
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
