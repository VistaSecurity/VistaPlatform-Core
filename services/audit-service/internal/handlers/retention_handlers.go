package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// retentionService is the narrow surface of *services.RetentionService the
// handlers use, so they can run over an in-memory stub in the contract test
// (ADR-0001). The concrete service satisfies it; NewRetentionHandler is unchanged.
type retentionService interface {
	GetRetentionPolicies(ctx context.Context) ([]services.RetentionPolicy, error)
	GetRetentionPolicyByID(ctx context.Context, id uuid.UUID) (*services.RetentionPolicy, error)
	CreateRetentionPolicy(ctx context.Context, policy *services.RetentionPolicy) error
	UpdateRetentionPolicy(ctx context.Context, policy *services.RetentionPolicy) error
}

type RetentionHandler struct {
	service retentionService
}

func NewRetentionHandler(service *services.RetentionService) *RetentionHandler {
	return &RetentionHandler{service: service}
}

// GetRetentionPolicies handles GET /api/v1/audit-service/retention-policies
func (h *RetentionHandler) GetRetentionPolicies(c *gin.Context) {
	policies, err := h.service.GetRetentionPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve retention policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// GetRetentionPolicyByID handles GET /api/v1/audit-service/retention-policies/:id
func (h *RetentionHandler) GetRetentionPolicyByID(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid retention policy ID"})
		return
	}

	policy, err := h.service.GetRetentionPolicyByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Retention policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policy": policy})
}

// CreateRetentionPolicy handles POST /api/v1/audit-service/retention-policies
func (h *RetentionHandler) CreateRetentionPolicy(c *gin.Context) {
	var policy services.RetentionPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err := h.service.CreateRetentionPolicy(c.Request.Context(), &policy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create retention policy"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"policy": policy})
}

// UpdateRetentionPolicy handles PUT /api/v1/audit-service/retention-policies/:id
func (h *RetentionHandler) UpdateRetentionPolicy(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid retention policy ID"})
		return
	}

	var policy services.RetentionPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	policy.ID = id

	err = h.service.UpdateRetentionPolicy(c.Request.Context(), &policy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update retention policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policy": policy})
}
