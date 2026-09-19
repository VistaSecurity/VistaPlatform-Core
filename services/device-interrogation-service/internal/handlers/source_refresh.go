package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// RegisterSourceRefresh exposes only signed service-to-service orchestration.
// No JWT, spoofable tenant header, or caller-supplied credential enables probes.
func (h *DeviceHandlers) RegisterSourceRefresh(router *gin.Engine, service *services.ConfiguredSourceRefresh) {
	verifier := serviceauth.NewVerifier(os.Getenv("INTERNAL_AUTH_SECRET"))
	group := router.Group("/internal/enrichment/refresh")
	group.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
		if !verifier.Verify(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "internal authentication required"})
			return
		}
		tenant, err := uuid.Parse(c.GetHeader(serviceauth.HeaderTenantID))
		if err != nil || tenant == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "tenant required"})
			return
		}
		c.Set("refreshTenant", tenant)
		c.Next()
	})
	group.POST("", func(c *gin.Context) {
		tenant := c.MustGet("refreshTenant").(uuid.UUID)
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
		var req services.SourceRefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.TenantID != tenant {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid refresh request"})
			return
		}
		result, err := service.Refresh(c.Request.Context(), req)
		sourceRefreshResponse(c, result, err)
	})
	group.GET("/:id", func(c *gin.Context) {
		tenant := c.MustGet("refreshTenant").(uuid.UUID)
		id, err := uuid.Parse(c.Param("id"))
		if err != nil || c.Query("tenant_id") != tenant.String() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid refresh request"})
			return
		}
		result, err := service.Status(c.Request.Context(), tenant, id)
		sourceRefreshResponse(c, result, err)
	})
}
func sourceRefreshResponse(c *gin.Context, result services.SourceRefreshStatus, err error) {
	if errors.Is(err, services.ErrRefreshNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "refresh not found"})
		return
	}
	if errors.Is(err, services.ErrRefreshConflict) {
		c.JSON(http.StatusConflict, gin.H{"error": "refresh evidence changed"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh unavailable"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// PrepareSourceRefreshJob shares the existing configured-credential builder.
func (h *DeviceHandlers) PrepareSourceRefreshJob(ctx context.Context, tenant, asset uuid.UUID) (models.CreateDeviceJobRequest, error) {
	req := models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &asset}
	device, err := h.deviceService.GetDevice(ctx, tenant, asset)
	if err != nil {
		return req, err
	}
	key := os.Getenv("ENCRYPTION_MASTER_KEY")
	if key == "" {
		return req, services.ErrRefreshCredentialsUnavailable
	}
	req.Credentials, err = h.buildJobCredentials(ctx, tenant, device, key)
	if errors.Is(err, errNoDeviceCredentials) || errors.Is(err, sql.ErrNoRows) {
		return req, services.ErrRefreshCredentialsUnavailable
	}
	if err != nil {
		return req, err
	}
	// Verify decryption now. A damaged envelope is blocked, never tried as a
	// password against the device or downgraded to default credentials.
	if _, err = services.NormalizeJobCredentials(req.Credentials, key); err != nil {
		return req, services.ErrRefreshCredentialsUnavailable
	}
	req.Parameters = buildJobParameters(device, nil)
	return req, nil
}
