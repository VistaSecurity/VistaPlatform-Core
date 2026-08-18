package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// cryptoApplicationsStore is the slice of *services.AssetService this handler
// depends on, declared as an interface so the contract test can drive the real
// handler with an in-memory stub (ADR-0001 recipe, same as cryptoAssetsStore).
type cryptoApplicationsStore interface {
	ListCryptoApplications(tenantID uuid.UUID, f services.CryptoApplicationFilter) ([]models.CryptoApplication, int, error)
}

type CryptoApplicationsHandler struct {
	svc cryptoApplicationsStore
}

func NewCryptoApplicationsHandler(svc *services.AssetService) *CryptoApplicationsHandler {
	return &CryptoApplicationsHandler{svc: svc}
}

// ListCryptoApplications serves GET /crypto-applications — the Data Protection
// lens. Defaults to the at_rest context: at-rest posture is the only context
// with a producer today, and defaulting to "all" would render an empty lens the
// moment another context is populated.
func (h *CryptoApplicationsHandler) ListCryptoApplications(c *gin.Context) {
	tenantID, ok := c.Get("tenantID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	f := services.CryptoApplicationFilter{
		EncryptionContext: c.DefaultQuery("encryption_context", "at_rest"),
		ResourceType:      c.Query("resource_type"),
		RiskAtLeast:       c.Query("risk_at_least"),
		Search:            c.Query("search"),
	}

	// determined is a TRI-state: absent means "no filter". Parsed explicitly
	// rather than through a bool default, because defaulting it to false would
	// silently hide every measured resource.
	if raw := strings.TrimSpace(c.Query("determined")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "determined must be true or false"})
			return
		}
		f.Determined = &v
	}

	if raw := c.Query("limit"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be a positive integer"})
			return
		}
		f.Limit = v
	}
	if raw := c.Query("offset"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "offset must be a non-negative integer"})
			return
		}
		f.Offset = v
	}

	items, total, err := h.svc.ListCryptoApplications(tenantUUID, f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if items == nil {
		items = []models.CryptoApplication{}
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total})
}
