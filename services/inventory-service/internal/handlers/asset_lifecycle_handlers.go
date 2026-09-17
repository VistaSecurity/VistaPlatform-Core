package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// lifecycleStore and revalidationStore are the slices of
// *services.AssetLifecycleService / *services.RevalidationService the lifecycle
// handlers depend on. Declaring them as interfaces (the concrete services still
// satisfy them) lets the contract test drive the real handlers with in-memory
// stubs — no database — per the spec-first contract recipe (ADR-0001).
type lifecycleStore interface {
	GetStaleAssets(tenantID uuid.UUID, filters models.StaleAssetFilters) ([]models.StaleAsset, int, error)
	UpdateStaleStatus(tenantID uuid.UUID, assetIDs []uuid.UUID, status string, actorUserID uuid.UUID) error
	GetLifecyclePolicy(tenantID uuid.UUID) (*models.AssetLifecyclePolicy, error)
	UpdateLifecyclePolicy(tenantID uuid.UUID, input models.AssetLifecyclePolicyInput) (*models.AssetLifecyclePolicy, error)
}

type revalidationStore interface {
	CreateRevalidationJob(tenantID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string) (string, error)
	CreateActiveScanJob(tenantID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string, runFrom services.RunFrom) (services.ActiveScanResult, error)
}

type AssetLifecycleHandler struct {
	lifecycleService    lifecycleStore
	revalidationService revalidationStore
	assetService        *services.AssetService
}

func NewAssetLifecycleHandler(
	lifecycleService *services.AssetLifecycleService,
	revalidationService *services.RevalidationService,
	assetService *services.AssetService,
) *AssetLifecycleHandler {
	return &AssetLifecycleHandler{
		lifecycleService:    lifecycleService,
		revalidationService: revalidationService,
		assetService:        assetService,
	}
}

// s2sAuthHeader returns the Authorization value to forward on an internal dispatch to
// another service (e.g. cluster-sensor-service for a scan/revalidation job). Browser auth
// on this platform is httpOnly-cookie based, so the inbound request usually carries NO
// Authorization header — only the access_token cookie. The peer's RequireJWTAuth checks
// Bearer first (and skips CSRF on the Bearer path), so we convert the access-token cookie
// into a Bearer token. Without this the dispatch goes out unauthenticated and the peer
// returns 401 ().
func s2sAuthHeader(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); h != "" {
		return h
	}
	for _, name := range []string{"access_token", "platform_access_token"} {
		if tok, err := c.Cookie(name); err == nil && tok != "" {
			return "Bearer " + tok
		}
	}
	return ""
}

// GetStaleAssets handles GET /api/v1/inventory-service/assets/stale
func (h *AssetLifecycleHandler) GetStaleAssets(c *gin.Context) {
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

	var filters models.StaleAssetFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	// Apply shared pagination defaults and bounds; stale list historically defaulted to 50 per page
	pg := sharedapi.ParsePagination(c)
	if ps := c.Query("page_size"); ps == "" {
		pg.PageSize = 50
	} else if n, err := strconv.Atoi(ps); err != nil || n <= 0 {
		pg.PageSize = 50
	}
	pg.Offset = (pg.Page - 1) * pg.PageSize
	filters.Page = pg.Page
	filters.PageSize = pg.PageSize

	staleAssets, total, err := h.lifecycleService.GetStaleAssets(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get stale assets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"assets":     staleAssets,
		"pagination": sharedapi.BuildPaginationMeta(pg, int64(total)),
	})
}

// RescanAssets handles POST /api/v1/inventory-service/assets/stale/rescan
func (h *AssetLifecycleHandler) RescanAssets(c *gin.Context) {
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

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	var req struct {
		AssetIDs []string `json:"asset_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	assetIDs := make([]uuid.UUID, 0, len(req.AssetIDs))
	for _, idStr := range req.AssetIDs {
		if id, err := uuid.Parse(idStr); err == nil {
			assetIDs = append(assetIDs, id)
		}
	}

	if len(assetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid asset IDs provided"})
		return
	}

	authHeader := s2sAuthHeader(c)
	jobID, err := h.revalidationService.CreateRevalidationJob(tenantUUID, userUUID, assetIDs, authHeader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create revalidation job"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Revalidation job created",
		"job_id":  jobID,
		"count":   len(assetIDs),
	})
}

// ScanAssets handles POST /api/v1/inventory-service/assets/scan — the Active Scan action
// (). It approves the targeted assets, stamps scan freshness, and dispatches an
// active TLS probe whose results flow back through the discovery pipeline to catalog crypto.
func (h *AssetLifecycleHandler) ScanAssets(c *gin.Context) {
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

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	// run_from chooses the executor: auto (the observing sensor, else
	// a segment sensor, else the platform), platform, or one named sensor.
	// The permission is the same for all three — assets.update, checked on
	// the route — because the permission follows the action, not the executor.
	var req struct {
		AssetIDs []string `json:"asset_ids" binding:"required"`
		RunFrom  string   `json:"run_from"`
		SensorID string   `json:"sensor_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	assetIDs := make([]uuid.UUID, 0, len(req.AssetIDs))
	for _, idStr := range req.AssetIDs {
		if id, err := uuid.Parse(idStr); err == nil {
			assetIDs = append(assetIDs, id)
		}
	}
	if len(assetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid asset IDs provided"})
		return
	}

	runFrom := services.RunFrom{Mode: strings.ToLower(strings.TrimSpace(req.RunFrom))}
	if runFrom.Mode == services.RunFromSensor {
		id, err := uuid.Parse(strings.TrimSpace(req.SensorID))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "run_from \"sensor\" needs a sensor_id"})
			return
		}
		runFrom.SensorID = id
	}

	authHeader := s2sAuthHeader(c)
	result, err := h.revalidationService.CreateActiveScanJob(tenantUUID, userUUID, assetIDs, authHeader, runFrom)
	if err != nil {
		// The executor refusals are the caller's to act on — pick another
		// sensor, wait for it, or run from the platform — so they keep their
		// status and their reason rather than collapsing into a 500.
		switch {
		case errors.Is(err, services.ErrInvalidRunFrom), errors.Is(err, sensorrouting.ErrSensorNotDispatchable):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case errors.Is(err, sensorrouting.ErrSensorNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case errors.Is(err, sensorrouting.ErrSensorOffline):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		default:
			log.Printf("[ERROR] ScanAssets - tenantID: %v, run_from: %s, error: %v", tenantUUID, runFrom.Mode, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start active scan"})
		}
		return
	}

	c.JSON(http.StatusOK, activeScanResponse(result))
}

// activeScanResponse renders an ActiveScanResult on the wire: the original
// `job_id`/`count` summary plus every job with its executor and every asset
// that was skipped, so a caller can name the executor and say what did not
// run.
func activeScanResponse(r services.ActiveScanResult) gin.H {
	jobs := make([]gin.H, 0, len(r.Jobs))
	for _, j := range r.Jobs {
		job := gin.H{"job_id": j.JobID, "executor": j.Executor, "count": j.Count}
		if j.SensorID != nil {
			job["sensor_id"] = j.SensorID.String()
			job["sensor_name"] = j.SensorName
		}
		jobs = append(jobs, job)
	}
	skipped := make([]gin.H, 0, len(r.Skipped))
	for _, s := range r.Skipped {
		skipped = append(skipped, gin.H{"asset_id": s.AssetID.String(), "reason": s.Reason})
	}
	message := "Active scan started"
	if len(r.Jobs) == 0 {
		message = "No scan was started"
	}
	return gin.H{
		"message": message,
		"job_id":  r.FirstJobID(),
		"count":   r.Scanned,
		"jobs":    jobs,
		"skipped": skipped,
	}
}

// ArchiveAssets handles POST /api/v1/inventory-service/assets/stale/archive
func (h *AssetLifecycleHandler) ArchiveAssets(c *gin.Context) {
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

	var req struct {
		AssetIDs []string `json:"asset_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	assetIDs := make([]uuid.UUID, 0, len(req.AssetIDs))
	for _, idStr := range req.AssetIDs {
		if id, err := uuid.Parse(idStr); err == nil {
			assetIDs = append(assetIDs, id)
		}
	}

	if len(assetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid asset IDs provided"})
		return
	}

	if err := h.lifecycleService.UpdateStaleStatus(tenantUUID, assetIDs, "archived", lifecycleActor(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to archive assets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Assets archived",
		"count":   len(assetIDs),
	})
}

// RevalidateAssets handles POST /api/v1/inventory-service/assets/revalidate
func (h *AssetLifecycleHandler) RevalidateAssets(c *gin.Context) {
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

	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	userUUID, ok := userID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if userIDStr, okStr := userID.(string); okStr {
			var err error
			userUUID, err = uuid.Parse(userIDStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID type"})
			return
		}
	}

	var req struct {
		AssetIDs []string `json:"asset_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	assetIDs := make([]uuid.UUID, 0, len(req.AssetIDs))
	for _, idStr := range req.AssetIDs {
		if id, err := uuid.Parse(idStr); err == nil {
			assetIDs = append(assetIDs, id)
		}
	}

	if len(assetIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid asset IDs provided"})
		return
	}

	authHeader := s2sAuthHeader(c)
	jobID, err := h.revalidationService.CreateRevalidationJob(tenantUUID, userUUID, assetIDs, authHeader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create revalidation job"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Revalidation job created",
		"job_id":  jobID,
		"count":   len(assetIDs),
	})
}

// GetPolicy handles GET /api/v1/inventory-service/lifecycle/policy
func (h *AssetLifecycleHandler) GetPolicy(c *gin.Context) {
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

	policy, err := h.lifecycleService.GetLifecyclePolicy(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get lifecycle policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policy": policy})
}

// UpdatePolicy handles PUT /api/v1/inventory-service/lifecycle/policy
func (h *AssetLifecycleHandler) UpdatePolicy(c *gin.Context) {
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

	var input models.AssetLifecyclePolicyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	policy, err := h.lifecycleService.UpdateLifecyclePolicy(tenantUUID, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update lifecycle policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policy": policy})
}

// lifecycleActor is the person archiving, or uuid.Nil when no session is
// attached — which is what the automatic staleness sweep passes, and is the
// honest value: empty is "no person was involved", not "the system".
func lifecycleActor(c *gin.Context) uuid.UUID {
	v, ok := c.Get("userID")
	if !ok {
		return uuid.Nil
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}
