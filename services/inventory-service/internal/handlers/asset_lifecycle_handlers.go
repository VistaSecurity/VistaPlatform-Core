package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
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
	UpdateStaleStatus(tenantID uuid.UUID, assetIDs []uuid.UUID, status string) error
	GetLifecyclePolicy(tenantID uuid.UUID) (*models.AssetLifecyclePolicy, error)
	UpdateLifecyclePolicy(tenantID uuid.UUID, input models.AssetLifecyclePolicyInput) (*models.AssetLifecyclePolicy, error)
}

type revalidationStore interface {
	CreateRevalidationJob(tenantID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string) (string, error)
	CreateActiveScanJob(tenantID, userID uuid.UUID, assetIDs []uuid.UUID, authHeader string) (string, int, error)
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
	jobID, scanned, err := h.revalidationService.CreateActiveScanJob(tenantUUID, userUUID, assetIDs, authHeader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start active scan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Active scan started",
		"job_id":  jobID,
		"count":   scanned,
	})
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

	if err := h.lifecycleService.UpdateStaleStatus(tenantUUID, assetIDs, "archived"); err != nil {
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
