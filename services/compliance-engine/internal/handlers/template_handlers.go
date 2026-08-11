package handlers

import (
	"errors"
	"net/http"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TemplateHandlers contains all template handlers
type TemplateHandlers struct {
	templateService *services.TemplateService
}

// NewTemplateHandlers creates a new instance of template handlers
func NewTemplateHandlers(templateService *services.TemplateService) *TemplateHandlers {
	return &TemplateHandlers{
		templateService: templateService,
	}
}

// ListTemplates lists all templates with optional filtering
func (h *TemplateHandlers) ListTemplates(c *gin.Context) {
	filters := make(map[string]interface{})

	// Parse query parameters
	if category := c.Query("category"); category != "" {
		filters["category"] = category
	}
	if frameworkTag := c.Query("framework_tag"); frameworkTag != "" {
		filters["framework_tag"] = frameworkTag
	}
	if isActive := c.Query("is_active"); isActive != "" {
		filters["is_active"] = isActive == "true"
	}

	templates, err := h.templateService.ListTemplates(filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list templates",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
	})
}

// GetTemplate gets a template by ID
func (h *TemplateHandlers) GetTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	template, err := h.templateService.GetTemplate(id)
	if err != nil {
		if err.Error() == "template not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get template",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"template": template,
	})
}

// CreateTemplate creates a new template
func (h *TemplateHandlers) CreateTemplate(c *gin.Context) {
	var input models.MeasurementTemplateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Get user ID from context
	userIDStr, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	template, err := h.templateService.CreateTemplate(&input, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create template",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":  "Template created successfully",
		"template": template,
	})
}

// UpdateTemplate updates a template
func (h *TemplateHandlers) UpdateTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	var input models.MeasurementTemplateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	template, err := h.templateService.UpdateTemplate(id, &input)
	if err != nil {
		if err.Error() == "template not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update template",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Template updated successfully",
		"template": template,
	})
}

// DeleteTemplate deletes a template (soft delete)
func (h *TemplateHandlers) DeleteTemplate(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	err = h.templateService.DeleteTemplate(id)
	if err != nil {
		if err.Error() == "template not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete template",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Template deleted successfully",
	})
}

// ApplyTemplate applies a template to a control
func (h *TemplateHandlers) ApplyTemplate(c *gin.Context) {
	templateIDStr := c.Param("id")
	templateID, err := uuid.Parse(templateIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	var input struct {
		ControlID     uuid.UUID  `json:"control_id" binding:"required"`
		FrameworkType string     `json:"framework_type" binding:"required,oneof=platform tenant"`
		TenantID      *uuid.UUID `json:"tenant_id"` // Required for tenant frameworks
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// For tenant frameworks, we need to use tenant service
	if input.FrameworkType == "tenant" {
		if input.TenantID == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required for tenant frameworks"})
			return
		}

		// Apply template using tenant framework service
		measurement, err := h.templateService.ApplyTemplateToTenant(templateID, input.ControlID, *input.TenantID)
		if err != nil {
			// Custom policies are an Enterprise feature; a Core build has no
			// authoring backend to apply the template with. That is a 403
			// ("this edition can't"), not a 500 ("something broke").
			if errors.Is(err, services.ErrCustomPoliciesUnavailable) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Custom policies require an Enterprise subscription",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to apply template to tenant framework",
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message":     "Template applied successfully",
			"measurement": measurement,
		})
		return
	}

	// For platform frameworks
	measurement, err := h.templateService.ApplyTemplate(templateID, input.ControlID, input.FrameworkType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to apply template",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":     "Template applied successfully",
		"measurement": measurement,
	})
}
