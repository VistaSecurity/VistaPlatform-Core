package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// cryptoAssetsStore is the slice of *services.AssetService the crypto-materials
// handlers depend on. Declaring it as an interface (the concrete service still
// satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
// It is the union of every service method these handlers call.
type cryptoAssetsStore interface {
	ListKeys(tenantID uuid.UUID) ([]models.Key, error)
	GetKeyByID(tenantID, keyID uuid.UUID) (*models.Key, error)
	GetKeyImplementations(tenantID, keyID uuid.UUID) ([]models.KeyImplementation, error)
	ListLibraries(tenantID uuid.UUID) ([]models.CryptoLibrary, error)
	GetExternalMappings(tenantID uuid.UUID, localType string, localID uuid.UUID) ([]models.ExternalAssetMapping, error)
	AttachLibrary(tenantID, implementationID, libraryID uuid.UUID) error
	AttachKey(tenantID, implementationID, keyID uuid.UUID) error
	CreateLibrary(tenantID uuid.UUID, input models.CryptoLibrary) (*models.CryptoLibrary, error)
}

type CryptoAssetsHandler struct {
	svc cryptoAssetsStore
}

func NewCryptoAssetsHandler(svc *services.AssetService) *CryptoAssetsHandler {
	return &CryptoAssetsHandler{svc: svc}
}

// ListKeys returns keys for the tenant (metadata only)
func (h *CryptoAssetsHandler) ListKeys(c *gin.Context) {
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
	keys, err := h.svc.ListKeys(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// GetKeyByID returns a single key (metadata only) for the tenant
func (h *CryptoAssetsHandler) GetKeyByID(c *gin.Context) {
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
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key ID"})
		return
	}
	key, err := h.svc.GetKeyByID(tenantUUID, keyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Key not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"key": key})
}

// GetKeyImplementations returns the crypto configurations (with asset context)
// that reference a given key. Drives the Keys-lens drawer drilldown.
func (h *CryptoAssetsHandler) GetKeyImplementations(c *gin.Context) {
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
	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key ID"})
		return
	}
	impls, err := h.svc.GetKeyImplementations(tenantUUID, keyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"implementations": impls})
}

// ListLibraries returns crypto libraries for the tenant
func (h *CryptoAssetsHandler) ListLibraries(c *gin.Context) {
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
	libs, err := h.svc.ListLibraries(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"libraries": libs})
}

// GetMappings returns external mappings for a local entity
func (h *CryptoAssetsHandler) GetMappings(c *gin.Context) {
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
	localType := c.Query("local_type")
	localIDStr := c.Query("local_id")
	if localType == "" || localIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "local_type and local_id are required"})
		return
	}
	localID, err := uuid.Parse(localIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid local_id"})
		return
	}
	maps, err := h.svc.GetExternalMappings(tenantUUID, localType, localID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"mappings": maps})
}

// AttachLibrary links a library to a crypto implementation
func (h *CryptoAssetsHandler) AttachLibrary(c *gin.Context) {
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
	implID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid implementation id"})
		return
	}
	var body struct {
		LibraryID string `json:"library_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	libID, err := uuid.Parse(body.LibraryID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid library_id"})
		return
	}
	if err := h.svc.AttachLibrary(tenantUUID, implID, libID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// AttachKey links a key to a crypto implementation
func (h *CryptoAssetsHandler) AttachKey(c *gin.Context) {
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
	implID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid implementation id"})
		return
	}
	var body struct {
		KeyID string `json:"key_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	keyID, err := uuid.Parse(body.KeyID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key_id"})
		return
	}
	if err := h.svc.AttachKey(tenantUUID, implID, keyID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// CreateLibrary allows manual creation of a library record
func (h *CryptoAssetsHandler) CreateLibrary(c *gin.Context) {
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
	var input models.CryptoLibrary
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	lib, err := h.svc.CreateLibrary(tenantUUID, input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"library": lib})
}
