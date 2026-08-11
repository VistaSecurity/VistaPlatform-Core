package handlers

import (
	"net/http"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ListMappings returns rule→finding mappings
func (h *ComplianceHandlers) ListMappings(c *gin.Context) {
	var ruleID *uuid.UUID
	var frameworkID *string

	// Parse optional query parameters
	if ruleIDStr := c.Query("rule_id"); ruleIDStr != "" {
		if id, err := uuid.Parse(ruleIDStr); err == nil {
			ruleID = &id
		}
	}

	if frameworkIDStr := c.Query("framework_id"); frameworkIDStr != "" {
		frameworkID = &frameworkIDStr
	}

	mappings, err := h.mappingsService.ListMappings(ruleID, frameworkID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve mappings",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"mappings": mappings})
}

// GetMapping retrieves a specific mapping by ID
func (h *ComplianceHandlers) GetMapping(c *gin.Context) {
	mappingIDStr := c.Param("id")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mapping ID"})
		return
	}

	mapping, err := h.mappingsService.GetMapping(mappingID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Mapping not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"mapping": mapping})
}

// CreateMapping creates a new rule→finding mapping
func (h *ComplianceHandlers) CreateMapping(c *gin.Context) {
	var input models.RuleVulnerabilityMapping
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	// Validate required fields
	if input.RuleID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_id is required"})
		return
	}
	if input.FindingType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "finding_type is required"})
		return
	}

	mapping, err := h.mappingsService.CreateMapping(input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create mapping",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"mapping": mapping})
}

// UpdateMapping updates an existing mapping
func (h *ComplianceHandlers) UpdateMapping(c *gin.Context) {
	mappingIDStr := c.Param("id")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mapping ID"})
		return
	}

	var input models.RuleVulnerabilityMapping
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	mapping, err := h.mappingsService.UpdateMapping(mappingID, input)
	if err != nil {
		if err.Error() == "mapping not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Mapping not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update mapping",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"mapping": mapping})
}

// DeleteMapping deletes a mapping by ID
func (h *ComplianceHandlers) DeleteMapping(c *gin.Context) {
	mappingIDStr := c.Param("id")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid mapping ID"})
		return
	}

	err = h.mappingsService.DeleteMapping(mappingID)
	if err != nil {
		if err.Error() == "mapping not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Mapping not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to delete mapping",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Mapping deleted successfully"})
}
