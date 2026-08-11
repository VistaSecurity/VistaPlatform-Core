package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// certificateStore is the persistence surface the CertificateHandler needs.
// *services.CertificateService is the production implementation; depending on
// the interface (rather than the concrete type) lets the HTTP layer be
// exercised by the contract test with an in-memory stub, no database required
// (mirrors the assetStore + cbom-service/scopes scopeStore pattern). Keep this
// in sync with the CertificateService methods the handlers below call.
type certificateStore interface {
	GetCertificates(tenantID uuid.UUID, filters models.CertificateFilters) ([]models.Certificate, int, error)
	GetCertificateByID(tenantID, certID uuid.UUID) (*models.Certificate, error)
	GetCertificatesByAssetID(tenantID, assetID uuid.UUID) ([]models.Certificate, error)
	GetExpiringCertificates(tenantID uuid.UUID, days int, limit int, lookbackDays ...int) ([]models.Certificate, error)
	GetCertificateChain(tenantID, certID uuid.UUID) ([]models.Certificate, error)
	RebuildCertificateChain(tenantID, certID uuid.UUID) (*services.RebuildChainResult, error)
	RebuildAllCertificateChains(ctx context.Context, tenantID uuid.UUID) (*services.RebuildAllChainsResult, error)
	CreateCertificate(tenantID uuid.UUID, certData models.CertificateData) (*models.Certificate, error)
	UpdateCertificate(tenantID, certID uuid.UUID, certData models.CertificateData) (*models.Certificate, error)
	GetCertificateHistory(tenantID, certID uuid.UUID) ([]models.CertificateHistory, error)
}

type CertificateHandler struct {
	certificateService certificateStore
}

func NewCertificateHandler(certificateService certificateStore) *CertificateHandler {
	return &CertificateHandler{
		certificateService: certificateService,
	}
}

// GetCertificates handles GET /api/v1/inventory-service/certificates
// Returns a list of certificates with optional filters
func (h *CertificateHandler) GetCertificates(c *gin.Context) {
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
	filters := models.CertificateFilters{
		Page:      pg.Page,
		PageSize:  pg.PageSize,
		SortBy:    "not_after",
		SortOrder: "asc",
	}

	if expiringDaysStr := c.Query("expiring_days"); expiringDaysStr != "" {
		if days, err := strconv.Atoi(expiringDaysStr); err == nil {
			filters.ExpiringDays = &days
		}
	}

	if keySizeMinStr := c.Query("key_size_min"); keySizeMinStr != "" {
		if keySize, err := strconv.Atoi(keySizeMinStr); err == nil {
			filters.KeySizeMin = &keySize
		}
	}

	if algorithm := c.Query("algorithm"); algorithm != "" {
		filters.Algorithm = &algorithm
	}

	if issuer := c.Query("issuer"); issuer != "" {
		filters.Issuer = &issuer
	}

	if search := c.Query("search"); search != "" {
		filters.Search = &search
	}

	// ownership: filter certs by their owning asset's ownership — powers
	// the cert lens "3rd-party / vendor" view. Ignore unrecognized values.
	switch ownership := c.Query("ownership"); ownership {
	case "internal", "third_party", "unknown":
		filters.Ownership = &ownership
	}

	if certIDStr := c.Query("cert_id"); certIDStr != "" {
		if certID, err := uuid.Parse(certIDStr); err == nil {
			filters.CertificateID = &certID
		}
	}

	if selfSignedStr := c.Query("self_signed"); selfSignedStr != "" {
		switch selfSignedStr {
		case "true", "1":
			v := true
			filters.SelfSigned = &v
		case "false", "0":
			v := false
			filters.SelfSigned = &v
		}
	}

	filters.SortBy = c.DefaultQuery("sort_by", "not_after")
	filters.SortOrder = c.DefaultQuery("sort_order", "asc")

	certificates, total, err := h.certificateService.GetCertificates(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve certificates"})
		return
	}

	response := gin.H{
		"certificates": certificates,
		"pagination":   sharedapi.BuildPaginationMeta(pg, int64(total)),
	}

	c.JSON(http.StatusOK, response)
}

// GetCertificatesByAsset handles GET /api/v2/inventory-service/infrastructure-assets/:id/certificates
// Returns the full certificate records linked to a single asset via
// crypto_implementations, in the { "certificates": [...] } envelope the web-ui
// client expects. Tenant-scoped from context like every other handler here.
func (h *CertificateHandler) GetCertificatesByAsset(c *gin.Context) {
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

	certificates, err := h.certificateService.GetCertificatesByAssetID(tenantUUID, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve certificates for asset"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"certificates": certificates})
}

// GetCertificateByID handles GET /api/v1/inventory-service/certificates/:id
// Returns a single certificate with its relationships
func (h *CertificateHandler) GetCertificateByID(c *gin.Context) {
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

	certIDStr := c.Param("id")
	certID, err := uuid.Parse(certIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	certificate, err := h.certificateService.GetCertificateByID(tenantUUID, certID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Certificate not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"certificate": certificate})
}

// GetExpiringCertificates handles GET /api/v1/inventory-service/certificates/expiring
// Returns certificates expiring within a specified number of days
func (h *CertificateHandler) GetExpiringCertificates(c *gin.Context) {
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

	// Default to 30 days if not specified
	days := 30
	if daysStr := c.Query("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	limit := 100
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// lookback_days: include certs that expired within this many days in the past (default 30)
	lookbackDays := 30
	if lbStr := c.Query("lookback_days"); lbStr != "" {
		if lb, err := strconv.Atoi(lbStr); err == nil && lb >= 0 {
			lookbackDays = lb
		}
	}

	certificates, err := h.certificateService.GetExpiringCertificates(tenantUUID, days, limit, lookbackDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve expiring certificates"})
		return
	}

	// Format response for compatibility with existing dashboard endpoint
	formattedCerts := make([]gin.H, 0, len(certificates))
	for _, cert := range certificates {
		daysUntilExpiry := 0
		if cert.NotAfter != nil {
			daysUntilExpiry = int(time.Until(*cert.NotAfter).Hours() / 24)
		}

		// Get first associated asset ID if available
		assetID := ""
		if len(cert.RelatedAssets) > 0 {
			assetID = cert.RelatedAssets[0].ID.String()
		}

		formattedCerts = append(formattedCerts, gin.H{
			"id":                cert.ID.String(),
			"asset_id":          assetID,
			"common_name":       cert.CommonName,
			"issuer":            cert.IssuerDN,
			"not_after":         cert.NotAfter,
			"days_until_expiry": daysUntilExpiry,
		})
	}

	c.JSON(http.StatusOK, gin.H{"certificates": formattedCerts})
}

// GetCertificateChain handles GET /api/v1/inventory-service/certificates/:id/chain
// Returns the certificate chain for a given certificate
func (h *CertificateHandler) GetCertificateChain(c *gin.Context) {
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

	certIDStr := c.Param("id")
	certID, err := uuid.Parse(certIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	chain, err := h.certificateService.GetCertificateChain(tenantUUID, certID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificate chain"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"chain":        chain,
		"chain_length": len(chain),
		"is_complete":  len(chain) > 0 && (chain[len(chain)-1].IsSelfSigned || chain[len(chain)-1].SubjectDN == chain[len(chain)-1].IssuerDN),
	})
}

// RebuildCertificateChain handles POST /api/v1/inventory-service/certificates/:id/rebuild-chain
// Attempts to rebuild the certificate chain by matching issuer DNs
func (h *CertificateHandler) RebuildCertificateChain(c *gin.Context) {
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

	certIDStr := c.Param("id")
	certID, err := uuid.Parse(certIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate ID"})
		return
	}

	result, err := h.certificateService.RebuildCertificateChain(tenantUUID, certID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rebuild certificate chain"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result":         result,
		"message":        "Certificate chain rebuild completed",
		"links_created":  result.LinksCreated,
		"chain_length":   result.ChainLength,
		"chain_complete": result.ChainComplete,
	})
}

// RebuildAllCertificateChains handles POST /api/v1/inventory-service/certificates/rebuild-all-chains
// Attempts to rebuild certificate chains for all certificates in the tenant
func (h *CertificateHandler) RebuildAllCertificateChains(c *gin.Context) {
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

	result, err := h.certificateService.RebuildAllCertificateChains(c.Request.Context(), tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rebuild certificate chains"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"result":             result,
		"message":            "Bulk certificate chain rebuild completed",
		"total_certificates": result.TotalCertificates,
		"chains_rebuilt":     result.ChainsRebuilt,
		"links_created":      result.LinksCreated,
		"completed_chains":   result.CompletedChains,
		"errors":             result.Errors,
	})
}
