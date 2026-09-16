package handlers

import (
	"context"
	"errors"
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
	GetAssetClassHistory(tenantID, assetID uuid.UUID) ([]models.AssetClassChange, error)
	GetRiskSummary(tenantID uuid.UUID) (*models.RiskSummary, error)
	GetPostureTrend(tenantID uuid.UUID, days int) ([]models.PostureTrendPoint, error)
	GetPQCReadinessSummary(tenantID uuid.UUID) (*models.PQCReadinessSummary, error)
	GetAssetStats(tenantID uuid.UUID, period string) (*models.AssetStats, error)
	GetRecentAssetsCount(tenantID uuid.UUID, days int, filters models.AssetFilters) (int, error)
	GetAssetFacets(tenantID uuid.UUID, filters models.AssetFilters, level string, limit int) ([]models.AssetFacetBucket, error)
	GetTenantActivitySummary(tenantID uuid.UUID) (*services.TenantActivitySummary, error)
	CreateAsset(tenantID uuid.UUID, input models.AssetInput) (*models.Asset, error)
	BulkCreateAssets(tenantID uuid.UUID, inputs []models.AssetInput) *models.BulkImportResult
	UpdateAsset(tenantID, assetID uuid.UUID, input models.AssetInput, actorUserID uuid.UUID) (*models.Asset, *models.IdentifierUpdateReport, error)
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

// enforceAssetCap runs the subscription asset-cap check for a user-initiated
// addition of `additional` managed assets and writes the response when the
// request must stop. It reports whether the handler may proceed.
//
// Fails CLOSED: a check that cannot be answered is a 500, not a pass — the
// connectors used to treat a resolver error as permission and that is the
// fail-open the review flagged. Skipped only when no checker is wired
// (DB-free contract tests), which is the one deliberately optional case.
func (h *AssetHandler) enforceAssetCap(c *gin.Context, tenantUUID uuid.UUID, additional int) bool {
	if h.limits == nil {
		return true
	}
	result, err := h.limits.CheckAssetLimit(tenantUUID, additional)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check asset limit"})
		return false
	}
	if !result.Allowed {
		c.JSON(http.StatusPaymentRequired, gin.H{
			"error":          result.Message,
			"current_usage":  result.CurrentUsage,
			"limit":          result.Limit,
			"upgrade_prompt": result.UpgradePrompt,
		})
		return false
	}
	return true
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
		// A query the user typed answers 400 with the FULL diagnostic list of
		// QUERY_LANGUAGE §10 — code, message, span, suggestion, one per error —
		// because the caller is a person with a caret in a text box. Collapsing
		// them into one string is what "invalid query" looks like from inside.
		if writeQueryError(c, err) {
			return
		}
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
	addCanonicalQuery(response, filters)

	c.JSON(http.StatusOK, response)
}

// addCanonicalQuery attaches the canonical form of the predicate that selected
// the rows, so the caller can show the query it got rather than the query it
// typed. The facet rail renders it; an MCP agent repeats it beside its answer
// (ADR-0008 D4.4).
//
// A failure here is silently omitted rather than surfaced: the read that just
// succeeded compiled the identical predicate, so the only way this can fail is
// a bug, and turning a bug in the echo into a failed read would be the worse
// outcome. An empty canonical (an empty predicate) is omitted for the same
// reason it is empty — there is nothing to show.
func addCanonicalQuery(response gin.H, filters models.AssetFilters) {
	canonical, err := services.CanonicalAssetQuery(filters)
	if err != nil {
		log.Printf("[AssetHandler] canonicalizing the query for the echo failed (rows were returned anyway): %v", err)
		return
	}
	if canonical != "" {
		response["query"] = canonical
	}
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

// GetAssetClassHistory handles GET /api/v{1,2}/.../assets/:id/class-history.
//
// Read-only. A class change is made through Approvals (accepting a proposal) or
// through the asset edit form; there is no write here, and there should not be
// — a history you can POST to is not a history.
func (h *AssetHandler) GetAssetClassHistory(c *gin.Context) {
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
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	changes, err := h.assetService.GetAssetClassHistory(tenantUUID, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get asset class history"})
		return
	}
	// An asset nobody has reclassified still has the row its creation wrote, so
	// an empty list means the asset is gone or was written before this table
	// existed — not "it has always been what it is". The UI says so rather than
	// rendering an empty panel that reads as a claim.
	if changes == nil {
		changes = []models.AssetClassChange{}
	}
	c.JSON(http.StatusOK, gin.H{"class_history": changes})
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

	// Parse optional parameters. CAPPED at the platform page size: `limit` went
	// straight into PageSize, so `?limit=100000` asked Postgres for a hundred
	// thousand rows, each carrying its protocol-summary sub-select, over a
	// tenant-scoped connection — a denial of service one query string long.
	limitStr := c.DefaultQuery("limit", "10")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}
	if limit > sharedapi.MaxPageSize {
		limit = sharedapi.MaxPageSize
	}

	filters := models.AssetFilters{
		Search:   query,
		PageSize: limit,
		Page:     1,
	}

	assets, total, err := h.assetService.GetAssets(tenantUUID, filters)
	if err != nil {
		// A malformed query is the CALLER's, and it comes back as the 400 with
		// spans and suggestions that §10 specifies. Flattening it into a 500
		// "Search failed" told a person typing a query that the server had
		// broken, and gave them nothing to correct.
		if writeQueryError(c, err) {
			return
		}
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
		// Same as the search: an invalid `?query=` is the caller's, with a caret.
		if writeQueryError(c, err) {
			return
		}
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
	if len(filters.DiscoverySource) > 0 {
		// Named here because the canonical `query` echo CANNOT carry it:
		// discovery_source is pipeline state inside assets.metadata and is not
		// a field of the query language, so a caller reading the echo back
		// would be reading a predicate narrower than the one that ran. See
		// discoverySourcePredicate.
		filtersApplied["discovery_source"] = filters.DiscoverySource
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
	// The class is required on CREATE and optional on UPDATE, so it is checked
	// here rather than with a `binding:"required"` tag on the shared input
	// struct — one struct serves both, and requiring it on update would force
	// every owner-email edit to restate the class.
	if strings.TrimSpace(input.ClassKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "class_key is required"})
		return
	}

	// Enforce the tenant's subscription asset cap before inserting.
	// Plan limits are otherwise display-only, so an over-limit tenant could
	// keep creating assets via this endpoint.
	if !h.enforceAssetCap(c, tenantUUID, 1) {
		return
	}

	asset, err := h.assetService.CreateAsset(tenantUUID, input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create asset"})
		return
	}

	// Log audit event
	resourceType := "asset"
	logAuditActivity(c, "asset.created", "asset", "create", &resourceType, &asset.ID, nil, map[string]interface{}{
		"hostname":  asset.Hostname,
		"address":   asset.PrimaryAddress,
		"class_key": asset.ClassKey,
		"status":    asset.AssetStatus,
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

	// The actor, when the session has one. An identifier edit is attributable:
	// "somebody declared this serial" is not an audit trail.
	var actorUserID uuid.UUID
	if v, ok := c.Get("userID"); ok {
		if id, ok := v.(uuid.UUID); ok {
			actorUserID = id
		}
	}

	asset, identifierReport, err := h.assetService.UpdateAsset(tenantUUID, assetID, input, actorUserID)
	if err != nil {
		if conflict, ok := services.AsIdentifierConflict(err); ok {
			// 409, not 400: the request was well-formed and the server
			// understood it. The answer is that two assets now claim one
			// identifier, and a human has to say whether they are one thing —
			// so the proposal that asks them is named here. It was committed
			// separately and survives this refusal.
			c.JSON(http.StatusConflict, gin.H{
				"error": "Identifier already belongs to another asset",
				"message": fmt.Sprintf(
					"%s %q is already an identifier of another asset. A merge proposal was opened in Approvals so you can say whether these are the same thing.",
					conflict.Kind, conflict.Value),
				"kind":                 conflict.Kind,
				"value":                conflict.Value,
				"conflicting_asset_id": conflict.OwnerAssetID.String(),
				"merge_proposal_id":    conflict.ProposalID.String(),
			})
			return
		}
		if errors.Is(err, services.ErrIdentifierFloor) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "An asset must keep at least one identifier",
				"message": "removing these identifiers would leave the asset with none, and it could never be matched again",
			})
			return
		}
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
		if input.IPAddress != nil && oldAsset.PrimaryAddress != nil && *input.IPAddress != *oldAsset.PrimaryAddress {
			oldValues["primary_address"] = *oldAsset.PrimaryAddress
			newValues["primary_address"] = *input.IPAddress
			changedFields = append(changedFields, "primary_address")
		}
		if input.AssetStatus != nil && *input.AssetStatus != oldAsset.AssetStatus {
			oldValues["asset_status"] = oldAsset.AssetStatus
			newValues["asset_status"] = *input.AssetStatus
			changedFields = append(changedFields, "asset_status")
		}
		// Add other field comparisons as needed
	}

	logAuditActivity(c, "asset.updated", "asset", "update", &resourceType, &assetID, oldValues, newValues, changedFields, nil)

	body := gin.H{"asset": asset}
	if identifierReport != nil {
		// Always present, even when empty: a client that has to distinguish
		// "nothing was kept back" from "this server does not report" would have
		// to guess, and guessing is how a refused deletion reads as a
		// successful one.
		body["identifiers"] = normalizeIdentifierReport(identifierReport)
	}
	c.JSON(http.StatusOK, body)
}

// normalizeIdentifierReport gives the three lists their empty-array form. A
// null where an array is documented is the difference between "none" and "the
// server did not say".
func normalizeIdentifierReport(r *models.IdentifierUpdateReport) *models.IdentifierUpdateReport {
	out := *r
	if out.Attached == nil {
		out.Attached = []models.IdentifierChange{}
	}
	if out.Removed == nil {
		out.Removed = []models.IdentifierChange{}
	}
	if out.Kept == nil {
		out.Kept = []models.IdentifierChange{}
	}
	return &out
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
		oldValues["primary_address"] = oldAsset.PrimaryAddress
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

	// Restoring un-soft-deletes the row, which raises the enforced count
	// (`deleted_at IS NULL`) by one exactly as a create does. Without this a
	// tenant at the cap could delete and restore freely — the same
	// user-initiated managed-asset increase, through a door the cap forgot.
	if !h.enforceAssetCap(c, tenantUUID, 1) {
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

	// Elevation creates a NEW managed asset from a third-party connection —
	// a user-initiated addition, same class as manual create, same cap. (The
	// service is idempotent for an already-elevated connection; charging the
	// check there too is the conservative side of that edge.)
	if !h.enforceAssetCap(c, tenantUUID, 1) {
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
	if limit > sharedapi.MaxPageSize {
		limit = sharedapi.MaxPageSize
	}

	var filters models.AssetFilters
	if err := c.ShouldBindQuery(&filters); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	// The facets endpoint takes the SAME ?query= the list takes, so the counts
	// describe the filtered set rather than the whole inventory. A rail whose
	// numbers do not move when you filter is a rail nobody trusts twice.
	buckets, err := h.assetService.GetAssetFacets(tenantUUID, filters, level, limit)
	if err != nil {
		if writeQueryError(c, err) {
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to get facets",
			"message": err.Error(),
			"levels":  services.AssetFacetLevels(),
		})
		return
	}

	response := gin.H{"level": level, "buckets": buckets}
	addCanonicalQuery(response, filters)
	addFiltersOutsideTheLanguage(response, filters)
	c.JSON(http.StatusOK, response)
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

// addFiltersOutsideTheLanguage names every honoured filter the canonical
// `query` echo cannot express.
//
// Today that is exactly one: `discovery_source`, which reads pipeline state out
// of `assets.metadata` rather than a modelled property, so it has no field in
// the catalogue and cannot appear in the compiled predicate a read echoes back.
// A caller that trusted the echo as "the query I ran" would be trusting a
// predicate WIDER than the one that ran.
//
// Saying so is the honest interim. The field belongs in the catalogue — a jsonb
// accessor over `metadata` translates exactly as `attr.*` already does — and
// when it lands this function should go.
func addFiltersOutsideTheLanguage(response gin.H, filters models.AssetFilters) {
	if len(filters.DiscoverySource) == 0 {
		return
	}
	response["filters_applied"] = gin.H{"discovery_source": filters.DiscoverySource}
}
