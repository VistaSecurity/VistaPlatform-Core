package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	sharedservices "github.com/vistasecurity/vistaplatform/shared/services"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// maxBulkImportRows caps a single spreadsheet import. Matches the Discover
// Assets target cap (1000) so the two ingestion paths agree on batch size.
const maxBulkImportRows = 1000

// assetStore is the persistence surface the AssetHandler needs. *services.AssetService
// is the production implementation; depending on the interface (rather than the
// concrete type) lets the HTTP layer be exercised by the contract test with an
// in-memory stub, no database required (mirrors cbom-service/scopes' scopeStore).
// Keep this in sync with the AssetService methods the handlers below call.
type assetStore interface {
	GetAssets(tenantID uuid.UUID, filters models.AssetFilters) ([]models.Asset, int, error)
	GetAssetByID(tenantID, assetID uuid.UUID) (*models.Asset, error)
	GetCryptoImplementations(tenantID, assetID uuid.UUID) ([]models.CryptoImplementation, error)
	GetAssetHistory(tenantID, assetID uuid.UUID) ([]models.AssetHistory, error)
	GetRiskSummary(tenantID uuid.UUID) (*models.RiskSummary, error)
	GetPostureTrend(tenantID uuid.UUID, days int) ([]models.PostureTrendPoint, error)
	GetPQCReadinessSummary(tenantID uuid.UUID) (*models.PQCReadinessSummary, error)
	GetAssetStats(tenantID uuid.UUID, period string) (*models.AssetStats, error)
	GetRecentAssetsCount(tenantID uuid.UUID, days int, filters models.AssetFilters) (int, error)
	GetAssetFacets(tenantID uuid.UUID, filters models.AssetFilters, level string, limit int) ([]models.AssetFacetBucket, error)
	GetTenantActivitySummary(tenantID uuid.UUID) (*services.TenantActivitySummary, error)
	CreateAsset(tenantID uuid.UUID, input models.AssetInput) (*models.Asset, error)
	BulkCreateAssets(tenantID uuid.UUID, inputs []models.AssetInput) *models.BulkImportResult
	UpdateAsset(tenantID, assetID uuid.UUID, input models.AssetInput) (*models.Asset, error)
	UpdateAssetService(tenantID, assetID uuid.UUID, input models.UpdateAssetServiceInput) (*models.Asset, error)
	EnrichAllAssets(tenantID uuid.UUID) (int, error)
	DeleteAsset(tenantID, assetID uuid.UUID) error
	RestoreAsset(tenantID, assetID uuid.UUID) error
	HardDeleteAsset(tenantID, assetID uuid.UUID) error
	ElevateExternalConnection(tenantID, connID uuid.UUID) (*models.Asset, error)
	Health() error
}

// permissionChecker abstracts the tenant-RBAC lookup HardDeleteAsset performs
// before permanently removing an asset. Depending on the interface (rather than
// a raw *database.DB) lets the contract test drive the handler with an in-memory
// stub — no database — per the spec-first contract recipe (ADR-0001).
type permissionChecker interface {
	CheckPermission(tenantID, userID uuid.UUID, permission string) (bool, error)
}

// assetPermissionRepository is the production permissionChecker. The SQL is the
// verbatim tenant_permissions → roles → user_tenant_roles join that previously
// lived inline in AssetHandler.checkPermission.
type assetPermissionRepository struct {
	db *database.DB
}

func (r *assetPermissionRepository) CheckPermission(tenantID, userID uuid.UUID, permission string) (bool, error) {
	query := `
		SELECT COUNT(*) > 0
		FROM tenant_permissions p
		JOIN tenant_role_permissions rp ON p.id = rp.permission_id
		JOIN tenant_roles r ON rp.role_id = r.id
		JOIN user_tenant_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.tenant_id = $2 AND p.name = $3 AND ur.is_active = true
	`

	// RLS-scoped tables (tenant_permissions, tenant_role_permissions, tenant_roles,
	// user_tenant_roles) filtered by r.tenant_id — scope the read to the tenant so
	// the join only sees this tenant's roles under RLS.
	var hasPermission bool
	if err := database.WithTenantTx(context.Background(), r.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, userID, tenantID, permission).Scan(&hasPermission)
	}); err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}
	return hasPermission, nil
}

// assetLimitChecker abstracts the subscription asset-cap check CreateAsset runs
// before inserting a new asset. Depending on the interface (rather than the
// concrete *sharedservices.LimitEnforcementService) keeps the contract test
// DB-free, mirroring permissionChecker. *sharedservices.LimitEnforcementService
// is the production implementation.
type assetLimitChecker interface {
	CheckAssetLimit(tenantID uuid.UUID, additionalCount int) (*sharedservices.LimitCheckResult, error)
}

type AssetHandler struct {
	assetService assetStore
	perms        permissionChecker
	limits       assetLimitChecker
}

func NewAssetHandler(assetService assetStore, db *database.DB) *AssetHandler {
	h := &AssetHandler{
		assetService: assetService,
		perms:        &assetPermissionRepository{db: db},
	}
	// Wire subscription-limit enforcement only when a real DB is present. The
	// contract test constructs the handler with a nil DB (it exercises the HTTP
	// layer with in-memory stubs); CreateAsset skips the cap check when limits
	// is nil so those DB-free tests keep working, while production always wires it.
	if db != nil {
		h.limits = sharedservices.NewLimitEnforcementService(db.DB.DB)
	}
	return h
}

// GetAssets handles GET /api/v1/assets
// Binds query params into filters and returns paginated assets with pagination metadata.
func (h *AssetHandler) GetAssets(c *gin.Context) {
	// Removed development mode bypass to ensure seed data is accessible
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

	// Parse filters
	var filters models.AssetFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	// Apply shared pagination defaults and bounds
	pg := sharedapi.ParsePagination(c)
	filters.Page = pg.Page
	filters.PageSize = pg.PageSize

	assets, total, err := h.assetService.GetAssets(tenantUUID, filters)
	if err != nil {
		// Check if it's a validation error (bad request)
		errStr := err.Error()
		if strings.Contains(errStr, "invalid asset_type") {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":      "Invalid filter parameter",
				"message":    errStr,
				"suggestion": "Use 'has_certificates=true' to find assets with certificates, or visit /crypto-inventory for certificate views",
			})
			return
		}
		if strings.Contains(errStr, "invalid last_seen_before") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filter parameter", "message": errStr})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve assets"})
		return
	}

	response := gin.H{
		"assets":     assets,
		"pagination": sharedapi.BuildPaginationMeta(pg, int64(total)),
	}

	c.JSON(http.StatusOK, response)
}

// GetAssetByID handles GET /api/v1/assets/:id
// Returns a single asset with its crypto configurations and calculated risk.
func (h *AssetHandler) GetAssetByID(c *gin.Context) {
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

	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	asset, err := h.assetService.GetAssetByID(tenantUUID, assetID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"asset": asset})
}

// GetAssetCrypto handles GET /api/v1/assets/:id/crypto
// Returns crypto configurations for a given asset, ordered by risk and recency.
func (h *AssetHandler) GetAssetCrypto(c *gin.Context) {
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

	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	cryptoImpls, err := h.assetService.GetCryptoImplementations(tenantUUID, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve crypto configurations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"crypto_implementations": cryptoImpls})
}

// GetAssetHistory handles GET /api/v1/assets/:id/history
// Returns the history of changes for a given asset.
func (h *AssetHandler) GetAssetHistory(c *gin.Context) {
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

	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	history, err := h.assetService.GetAssetHistory(tenantUUID, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get asset history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"history": history})
}

// SearchAssets handles GET /api/v1/assets/search
// Uses GetAssets under the hood with a search query and limit to return quick results.
func (h *AssetHandler) SearchAssets(c *gin.Context) {
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

	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required"})
		return
	}

	// Parse optional parameters
	limitStr := c.DefaultQuery("limit", "10")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}

	filters := models.AssetFilters{
		Search:   query,
		PageSize: limit,
		Page:     1,
	}

	assets, total, err := h.assetService.GetAssets(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Search failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"query":   query,
		"assets":  assets,
		"total":   total,
		"showing": len(assets),
	})
}

// GetRiskSummary handles GET /api/v1/risk/summary
// Returns aggregate risk statistics for the tenant.
func (h *AssetHandler) GetRiskSummary(c *gin.Context) {
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

	summary, err := h.assetService.GetRiskSummary(tenantUUID)
	if err != nil {
		log.Printf("[ERROR] GetRiskSummary handler - Service error: %v, tenantID: %v", err, tenantUUID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get risk summary"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"risk_summary": summary})
}

// GetPostureTrend handles GET /api/v1/inventory-service/risk/posture/trend?days=30
// Returns a day-by-day risk-index series for the dashboard posture trend line
// (ADR-0007). New tenants get a flat seeded baseline at their current posture
// rather than a blank chart — see AssetService.GetPostureTrend.
func (h *AssetHandler) GetPostureTrend(c *gin.Context) {
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

	days := 30
	if v, err := strconv.Atoi(c.DefaultQuery("days", "30")); err == nil && v > 0 {
		days = v
	}

	trend, err := h.assetService.GetPostureTrend(tenantUUID, days)
	if err != nil {
		log.Printf("[ERROR] GetPostureTrend handler - Service error: %v, tenantID: %v", err, tenantUUID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get posture trend"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"trend": trend})
}

// GetPQCReadinessSummary handles GET /api/v1/inventory-service/pqc/summary
// Returns tenant-scoped PQC readiness based on actual crypto implementations,
// not the global algorithm catalog.
func (h *AssetHandler) GetPQCReadinessSummary(c *gin.Context) {
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

	summary, err := h.assetService.GetPQCReadinessSummary(tenantUUID)
	if err != nil {
		log.Printf("[ERROR] GetPQCReadinessSummary handler - Service error: %v, tenantID: %v", err, tenantUUID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PQC readiness summary"})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// GetAssetStats handles GET /api/v1/inventory-service/assets/stats
// Returns asset statistics with trend data for the specified period
func (h *AssetHandler) GetAssetStats(c *gin.Context) {
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

	// Get period from query param (default to 7d)
	period := c.DefaultQuery("period", "7d")
	if period != "7d" && period != "30d" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period. Must be '7d' or '30d'"})
		return
	}

	stats, err := h.assetService.GetAssetStats(tenantUUID, period)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get asset stats"})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetRecentAssetsCount handles GET /api/v1/inventory-service/assets/recent-count
// Returns the count of assets created within the specified number of days with optional filters applied
func (h *AssetHandler) GetRecentAssetsCount(c *gin.Context) {
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

	// Get days parameter (default to 7)
	daysStr := c.DefaultQuery("days", "7")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid days parameter. Must be a non-negative integer"})
		return
	}

	// Parse filters from query parameters (same as GetAssets)
	var filters models.AssetFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	count, err := h.assetService.GetRecentAssetsCount(tenantUUID, days, filters)
	if err != nil {
		log.Printf("[ERROR] GetRecentAssetsCount handler - Service error: %v, tenantID: %v, days: %d", err, tenantUUID, days)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get recent assets count"})
		return
	}

	// Build response with applied filters for transparency
	response := gin.H{
		"count": count,
		"days":  days,
	}

	// Include filters_applied if any filters were provided
	filtersApplied := gin.H{}
	if len(filters.Environment) > 0 {
		filtersApplied["environment"] = filters.Environment
	}
	if len(filters.AssetType) > 0 {
		filtersApplied["asset_type"] = filters.AssetType
	}
	if len(filters.AssetStatus) > 0 {
		filtersApplied["asset_status"] = filters.AssetStatus
	}
	if len(filters.RiskLevel) > 0 {
		filtersApplied["risk_level"] = filters.RiskLevel
	}
	if len(filters.BusinessUnit) > 0 {
		filtersApplied["business_unit"] = filters.BusinessUnit
	}
	if len(filters.OperatingSystem) > 0 {
		filtersApplied["operating_system"] = filters.OperatingSystem
	}
	if len(filters.OwnerEmail) > 0 {
		filtersApplied["owner_email"] = filters.OwnerEmail
	}
	if filters.Search != "" {
		filtersApplied["search"] = filters.Search
	}

	if len(filtersApplied) > 0 {
		response["filters_applied"] = filtersApplied
	}

	c.JSON(http.StatusOK, response)
}

// Health check handler
func (h *AssetHandler) Health(c *gin.Context) {
	// Test database connection
	if err := h.assetService.Health(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "unhealthy",
			"service": "inventory-service",
			"error":   "Service health check failed",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "inventory-service",
		"version": version.Get(),
	})
}

// CreateAsset handles POST /api/v1/assets
// Validates and creates a new asset.
func (h *AssetHandler) CreateAsset(c *gin.Context) {
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

	var input models.AssetInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Enforce the tenant's subscription asset cap before inserting.
	// Plan limits are otherwise display-only, so an over-limit tenant could
	// keep creating assets via this endpoint.
	if h.limits != nil {
		result, err := h.limits.CheckAssetLimit(tenantUUID, 1)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check asset limit"})
			return
		}
		if !result.Allowed {
			c.JSON(http.StatusPaymentRequired, gin.H{
				"error":          result.Message,
				"current_usage":  result.CurrentUsage,
				"limit":          result.Limit,
				"upgrade_prompt": result.UpgradePrompt,
			})
			return
		}
	}

	asset, err := h.assetService.CreateAsset(tenantUUID, input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create asset"})
		return
	}

	// Log audit event
	resourceType := "asset"
	logAuditActivity(c, "asset.created", "asset", "create", &resourceType, &asset.ID, nil, map[string]interface{}{
		"hostname":   asset.Hostname,
		"ip_address": asset.IPAddress,
		"asset_type": asset.AssetType,
		"status":     asset.AssetStatus,
	}, []string{}, map[string]interface{}{
		"created_via": "manual",
	})

	c.JSON(http.StatusCreated, gin.H{"asset": asset})
}

// CreateAssetsBulk handles POST /api/v{1,2}/.../infrastructure-assets/bulk.
// It creates many assets from a parsed spreadsheet in one request, returning a
// per-row result so the UI can show created / skipped / failed counts. The whole
// batch is checked against the subscription asset cap up front; per-row dedupe
// and validation happen in the service.
func (h *AssetHandler) CreateAssetsBulk(c *gin.Context) {
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

	var req models.AssetBulkImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if len(req.Rows) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No rows to import"})
		return
	}
	if len(req.Rows) > maxBulkImportRows {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"error": fmt.Sprintf("Too many rows: %d (max %d per import)", len(req.Rows), maxBulkImportRows),
		})
		return
	}

	// Enforce the tenant's subscription asset cap for the whole batch before
	// inserting anything, mirroring single-asset creation. v1 rejects the
	// entire import if it would exceed the cap; filling up to the remaining
	// headroom is a possible follow-up.
	if h.limits != nil {
		result, err := h.limits.CheckAssetLimit(tenantUUID, len(req.Rows))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check asset limit"})
			return
		}
		if !result.Allowed {
			c.JSON(http.StatusPaymentRequired, gin.H{
				"error":          result.Message,
				"current_usage":  result.CurrentUsage,
				"limit":          result.Limit,
				"upgrade_prompt": result.UpgradePrompt,
			})
			return
		}
	}

	res := h.assetService.BulkCreateAssets(tenantUUID, req.Rows)

	resourceType := "asset"
	logAuditActivity(c, "asset.bulk_imported", "asset", "create", &resourceType, nil, nil, map[string]interface{}{
		"created": res.Created,
		"skipped": res.Skipped,
		"failed":  res.Failed,
	}, []string{}, map[string]interface{}{
		"created_via": "spreadsheet_import",
	})

	c.JSON(http.StatusOK, res)
}

// UpdateAsset handles PUT /api/v1/assets/:id
// Partially updates an existing asset.
func (h *AssetHandler) UpdateAsset(c *gin.Context) {
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

	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	// Get old asset for audit logging
	oldAsset, _ := h.assetService.GetAssetByID(tenantUUID, assetID)

	var input models.AssetInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	asset, err := h.assetService.UpdateAsset(tenantUUID, assetID, input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to update asset"})
		return
	}

	// Log audit event with changed fields
	resourceType := "asset"
	oldValues := make(map[string]interface{})
	newValues := make(map[string]interface{})
	changedFields := []string{}

	if oldAsset != nil {
		if input.Hostname != nil && oldAsset.Hostname != nil && *input.Hostname != *oldAsset.Hostname {
			oldValues["hostname"] = *oldAsset.Hostname
			newValues["hostname"] = *input.Hostname
			changedFields = append(changedFields, "hostname")
		}
		if input.IPAddress != nil && oldAsset.IPAddress != nil && *input.IPAddress != *oldAsset.IPAddress {
			oldValues["ip_address"] = *oldAsset.IPAddress
			newValues["ip_address"] = *input.IPAddress
			changedFields = append(changedFields, "ip_address")
		}
		if input.AssetStatus != nil && *input.AssetStatus != oldAsset.AssetStatus {
			oldValues["asset_status"] = oldAsset.AssetStatus
			newValues["asset_status"] = *input.AssetStatus
			changedFields = append(changedFields, "asset_status")
		}
		// Add other field comparisons as needed
	}

	logAuditActivity(c, "asset.updated", "asset", "update", &resourceType, &assetID, oldValues, newValues, changedFields, nil)

	c.JSON(http.StatusOK, gin.H{"asset": asset})
}

// UpdateAssetService handles PUT /inventory-service/infrastructure-assets/:id/service (manual service override).
func (h *AssetHandler) UpdateAssetService(c *gin.Context) {
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
	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}
	var input models.UpdateAssetServiceInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	asset, err := h.assetService.UpdateAssetService(tenantUUID, assetID, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset service"})
		return
	}
	if asset == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"asset": asset})
}

// EnrichAllAssets handles POST /inventory-service/infrastructure-assets/enrich-all (backfill segment + service ID).
func (h *AssetHandler) EnrichAllAssets(c *gin.Context) {
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
	updated, err := h.assetService.EnrichAllAssets(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enrich assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"updated": updated})
}

// DeleteAsset handles DELETE /api/v1/assets/:id
// Soft-deletes the asset and returns 204 on success.
func (h *AssetHandler) DeleteAsset(c *gin.Context) {
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

	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	// Get asset before deletion for audit logging
	oldAsset, _ := h.assetService.GetAssetByID(tenantUUID, assetID)

	if err := h.assetService.DeleteAsset(tenantUUID, assetID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete asset"})
		return
	}

	// Log audit event
	resourceType := "asset"
	oldValues := make(map[string]interface{})
	if oldAsset != nil {
		oldValues["hostname"] = oldAsset.Hostname
		oldValues["ip_address"] = oldAsset.IPAddress
		oldValues["asset_status"] = oldAsset.AssetStatus
	}
	logAuditActivity(c, "asset.deleted", "asset", "delete", &resourceType, &assetID, oldValues, nil, []string{"deleted_at"}, nil)

	c.Status(http.StatusNoContent)
}

// RestoreAsset handles POST /api/v1/assets/:id/restore
func (h *AssetHandler) RestoreAsset(c *gin.Context) {
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

	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	if err := h.assetService.RestoreAsset(tenantUUID, assetID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore asset"})
		return
	}

	// Return the restored asset
	asset, err := h.assetService.GetAssetByID(tenantUUID, assetID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"restored": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"asset": asset})
}

// ElevateExternalConnection handles POST /external-connections/:id/elevate.
// Promotes a 3rd-party connection to a managed/monitored asset, with its
// leaf certificate materialized so it is tracked like an internal asset.
func (h *AssetHandler) ElevateExternalConnection(c *gin.Context) {
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

	connID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid connection ID"})
		return
	}

	asset, err := h.assetService.ElevateExternalConnection(tenantUUID, connID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to elevate connection"})
		return
	}
	if asset == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "External connection not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"asset": asset})
}

// HardDeleteAsset handles DELETE /api/v1/assets/:id/hard
// Permanently deletes an asset (admin-only, requires assets.hard_delete permission)
func (h *AssetHandler) HardDeleteAsset(c *gin.Context) {
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

	// Check for hard_delete permission
	hasPermission, err := h.perms.CheckPermission(tenantUUID, userUUID, "assets.hard_delete")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check permission"})
		return
	}
	if !hasPermission {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions", "required_permission": "assets.hard_delete"})
		return
	}

	assetIDStr := c.Param("id")
	assetID, err := uuid.Parse(assetIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	if err := h.assetService.HardDeleteAsset(tenantUUID, assetID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hard delete asset"})
		return
	}

	c.Status(http.StatusNoContent)
}

// GetAssetFacets handles GET /api/v1/assets/facets
// Query params: level (string), limit (int, optional), plus normal filters.
// Provides counts per facet level for building the hierarchical navigation.
func (h *AssetHandler) GetAssetFacets(c *gin.Context) {
	// Removed development mode bypass to ensure seed data is accessible
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

	level := c.Query("level")
	if level == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "level is required"})
		return
	}

	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 50
	}

	var filters models.AssetFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	buckets, err := h.assetService.GetAssetFacets(tenantUUID, filters, level, limit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get facets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"level": level, "buckets": buckets})
}

// GetTenantActivitySummary handles GET /api/v1/inventory-service/tenant/:id/activity-summary
// Returns activity metrics for a specific tenant (for tenant health service)
func (h *AssetHandler) GetTenantActivitySummary(c *gin.Context) {
	tenantIDStr := c.Param("id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	summary, err := h.assetService.GetTenantActivitySummary(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get tenant activity summary",
		})
		return
	}

	c.JSON(http.StatusOK, summary)
}
