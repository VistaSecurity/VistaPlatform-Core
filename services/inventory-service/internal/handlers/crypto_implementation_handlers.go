package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// maxLinkIDs caps how many asset_ids or certificate_ids the asset-certificate-links
// endpoint will accept per request. Large lists indicate a misuse (the caller
// probably wants the full graph, not edge-scoping) and would also bloat the
// pq.Array binding.
const maxLinkIDs = 500

// cryptoConfigStore is the persistence surface the CryptoImplementationHandler
// needs. *services.CryptoImplementationService is the production implementation;
// depending on the interface (rather than the concrete type) lets the HTTP
// layer be exercised by the contract test with an in-memory stub, no database
// required (mirrors the assetStore + certificateStore + cbom-service/scopes
// scopeStore pattern). Keep this in sync with the CryptoImplementationService
// methods the handlers below call.
type cryptoConfigStore interface {
	GetCryptoImplementations(tenantID uuid.UUID, filters models.CryptoImplementationFilters) ([]models.CryptoImplementation, int, error)
	GetCryptoImplementationByID(tenantID, id uuid.UUID) (*models.CryptoImplementation, error)
	GetAssetCertificateLinks(tenantID uuid.UUID, assetIDs []uuid.UUID, certIDs []uuid.UUID) ([]models.AssetCertificateLink, error)
	GetCryptoImplementationComponents(tenantID, implID uuid.UUID) ([]models.CryptoComponentAssessment, error)
}

type CryptoImplementationHandler struct {
	cryptoImplService cryptoConfigStore
}

func NewCryptoImplementationHandler(cryptoImplService cryptoConfigStore) *CryptoImplementationHandler {
	return &CryptoImplementationHandler{
		cryptoImplService: cryptoImplService,
	}
}

// GetCryptoImplementations handles GET /api/v1/inventory-service/crypto-implementations
// Returns a list of crypto configurations with optional filters
func (h *CryptoImplementationHandler) GetCryptoImplementations(c *gin.Context) {
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

	// Parse filters with shared pagination
	pg := sharedapi.ParsePagination(c)
	filters := models.CryptoImplementationFilters{
		Page:      pg.Page,
		PageSize:  pg.PageSize,
		SortBy:    "last_verified_at",
		SortOrder: "desc",
	}

	// Parse array filters
	if protocols := c.QueryArray("protocol"); len(protocols) > 0 {
		filters.Protocol = protocols
	}

	if protocolVersions := c.QueryArray("protocol_version"); len(protocolVersions) > 0 {
		filters.ProtocolVersion = protocolVersions
	}

	if cipherSuites := c.QueryArray("cipher_suite"); len(cipherSuites) > 0 {
		filters.CipherSuite = cipherSuites
	}

	if hashAlgorithms := c.QueryArray("hash_algorithm"); len(hashAlgorithms) > 0 {
		filters.HashAlgorithm = hashAlgorithms
	}

	if riskLevels := c.QueryArray("risk_level"); len(riskLevels) > 0 {
		filters.RiskLevel = riskLevels
	}

	if discoveryMethods := c.QueryArray("discovery_method"); len(discoveryMethods) > 0 {
		filters.DiscoveryMethod = discoveryMethods
	}

	// Parse single value filters
	if keySizeMinStr := c.Query("key_size_min"); keySizeMinStr != "" {
		if keySize, err := strconv.Atoi(keySizeMinStr); err == nil {
			filters.KeySizeMin = &keySize
		}
	}

	if certIDStr := c.Query("certificate_id"); certIDStr != "" {
		if certID, err := uuid.Parse(certIDStr); err == nil {
			filters.CertificateID = &certID
		}
	}

	if assetIDStr := c.Query("asset_id"); assetIDStr != "" {
		if assetID, err := uuid.Parse(assetIDStr); err == nil {
			filters.AssetID = &assetID
		}
	}

	if usesDeprecatedStr := c.Query("uses_deprecated_algorithms"); usesDeprecatedStr != "" {
		if usesDeprecated, err := strconv.ParseBool(usesDeprecatedStr); err == nil {
			filters.UsesDeprecatedAlgorithms = &usesDeprecated
		}
	}

	if search := c.Query("search"); search != "" {
		filters.Search = search
	}

	// Parse sorting
	if sortBy := c.Query("sort_by"); sortBy != "" {
		filters.SortBy = sortBy
	}

	if sortOrder := c.Query("sort_order"); sortOrder != "" {
		filters.SortOrder = sortOrder
	}

	// Get crypto configurations
	implementations, total, err := h.cryptoImplService.GetCryptoImplementations(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve crypto configurations"})
		return
	}

	response := gin.H{
		"crypto_implementations": implementations,
		"pagination":             sharedapi.BuildPaginationMeta(pg, int64(total)),
	}

	c.JSON(http.StatusOK, response)
}

// GetCryptoImplementationByID handles GET /api/v1/inventory-service/crypto-implementations/:id
// Returns a single crypto configuration with full details
func (h *CryptoImplementationHandler) GetCryptoImplementationByID(c *gin.Context) {
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

	implIDStr := c.Param("id")
	implID, err := uuid.Parse(implIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid crypto configuration ID"})
		return
	}

	implementation, err := h.cryptoImplService.GetCryptoImplementationByID(tenantUUID, implID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Crypto configuration not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"crypto_implementation": implementation})
}

// GetCryptoImplementationComponents handles
// GET /api/v[12]/inventory-service/crypto-configurations/:id/components.
//
// Returns the catalogue assessment of every algorithm linked to the
// configuration, worst first, so the drawer can answer "why is this High?" with
// the catalogue row that says so instead of a bare number.
//
// A 200 with an EMPTY `components` array means NOT ASSESSED — nothing on this
// configuration resolved against the catalogue. That is deliberately NOT a 404
// and deliberately not an error: "we could not assess this" is an answer, and
// conflating it with "assessed clean" is the failure mode this endpoint exists
// to prevent.
func (h *CryptoImplementationHandler) GetCryptoImplementationComponents(c *gin.Context) {
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

	implID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid crypto configuration ID"})
		return
	}

	components, err := h.cryptoImplService.GetCryptoImplementationComponents(tenantUUID, implID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve crypto configuration components"})
		return
	}
	if components == nil {
		components = []models.CryptoComponentAssessment{}
	}

	c.JSON(http.StatusOK, gin.H{"components": components})
}

// GetAssetCertificateLinks handles GET /api/v2/inventory-service/asset-certificate-links.
// Returns asset→certificate edges sourced from crypto_implementations, scoped
// to the asset_ids and/or certificate_ids passed in the query string. At least
// one of the two must be supplied. IDs are comma-separated UUIDs; both
// parameters may be combined to intersect.
func (h *CryptoImplementationHandler) GetAssetCertificateLinks(c *gin.Context) {
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

	assetIDs, err := parseUUIDList(c.Query("asset_ids"))
	if err != nil {
		sharedapi.BadRequest(c, "invalid asset_ids")
		return
	}
	certIDs, err := parseUUIDList(c.Query("certificate_ids"))
	if err != nil {
		sharedapi.BadRequest(c, "invalid certificate_ids")
		return
	}
	if len(assetIDs) == 0 && len(certIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one of asset_ids or certificate_ids must be provided"})
		return
	}
	if len(assetIDs) > maxLinkIDs || len(certIDs) > maxLinkIDs {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many ids; max 500 per parameter"})
		return
	}

	links, err := h.cryptoImplService.GetAssetCertificateLinks(tenantUUID, assetIDs, certIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve asset-certificate links"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"links": links})
}

// parseUUIDList parses a comma-separated list of UUIDs. An empty input yields
// a nil slice (the caller decides whether that's allowed).
func parseUUIDList(raw string) ([]uuid.UUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	ids := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := uuid.Parse(p)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
