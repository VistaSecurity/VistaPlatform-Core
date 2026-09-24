package handlers

import (
	"context"
	"fmt"
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

// validateRetentionDays rejects a policy whose ages cannot mean anything
// (security-staff-16): both must be at least one day, and the total cannot be
// shorter than the hot period. A 0 or negative age used to be accepted, and a
// total of 0 makes every matching log eligible for deletion on the next sweep.
// The table's valid_retention_days CHECK (total >= hot) stays as the backstop;
// checking it here too turns that case into a 400 that says why instead of a
// 500. Returns "" when the policy is valid.
func validateRetentionDays(p *services.RetentionPolicy) string {
	if p.HotStorageDays < 1 {
		return fmt.Sprintf("hot_storage_days must be at least 1 (got %d)", p.HotStorageDays)
	}
	if p.TotalRetentionDays < 1 {
		return fmt.Sprintf("total_retention_days must be at least 1 (got %d)", p.TotalRetentionDays)
	}
	if p.TotalRetentionDays < p.HotStorageDays {
		return fmt.Sprintf("total_retention_days (%d) cannot be shorter than hot_storage_days (%d)", p.TotalRetentionDays, p.HotStorageDays)
	}
	return ""
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
	if reason := validateRetentionDays(&policy); reason != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": reason})
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
	if reason := validateRetentionDays(&policy); reason != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": reason})
		return
	}

	err = h.service.UpdateRetentionPolicy(c.Request.Context(), &policy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update retention policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"policy": policy})
}
