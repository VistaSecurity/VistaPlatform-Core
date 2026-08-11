package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// frameworkContextStore is the slice of *services.FrameworkContextService the
// context handlers depend on. Declaring it as an interface (the concrete
// service satisfies it) lets the contract test drive the real handlers with an
// in-memory stub — no database — per the spec-first contract recipe (ADR-0001).
type frameworkContextStore interface {
	GetFrameworkContext(tenantID, userID uuid.UUID) (*services.FrameworkContextResponse, error)
	BatchEvaluateFrameworks(tenantID uuid.UUID, request *services.BatchEvaluateRequest, includeDetails bool) (*services.BatchEvaluateResponse, error)
}

// FrameworkContextHandlers contains all framework context handlers
type FrameworkContextHandlers struct {
	frameworkContextService frameworkContextStore
}

// NewFrameworkContextHandlers creates a new instance of framework context handlers
func NewFrameworkContextHandlers(frameworkContextService *services.FrameworkContextService) *FrameworkContextHandlers {
	return &FrameworkContextHandlers{
		frameworkContextService: frameworkContextService,
	}
}

// GetFrameworkContext returns consolidated framework data for the current tenant
// This single endpoint replaces multiple separate API calls for:
// - Licensed frameworks
// - Default framework
// - Framework status/compliance scores
// - Subscription info
// - User preferences
func (h *FrameworkContextHandlers) GetFrameworkContext(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				log.Printf("ERROR: Invalid tenant ID format: %v (type: %T)\n", tenantID, tenantID)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			log.Printf("ERROR: Invalid tenant ID type: %T, value: %v\n", tenantID, tenantID)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Check if tenantID is nil/empty
	if tenantUUID == uuid.Nil {
		log.Printf("ERROR: Tenant ID is nil/empty\n")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	// Get user ID from context (optional, for user preferences)
	var userUUID uuid.UUID
	userID, exists := c.Get("userID")
	if exists {
		if uid, ok := userID.(uuid.UUID); ok {
			userUUID = uid
		} else if userIDStr, ok := userID.(string); ok {
			userUUID, _ = uuid.Parse(userIDStr)
		}
	}

	context, err := h.frameworkContextService.GetFrameworkContext(tenantUUID, userUUID)
	if err != nil {
		log.Printf("ERROR: Failed to get framework context for tenant %s: %v\n", tenantUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get framework context",
		})
		return
	}

	c.JSON(http.StatusOK, context)
}

// BatchEvaluateFrameworks evaluates multiple frameworks in a single request
// This endpoint is designed for the workbench where multiple visualizers
// need evaluation data for the same set of frameworks
func (h *FrameworkContextHandlers) BatchEvaluateFrameworks(c *gin.Context) {
	tenantID, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		// Try to parse as string if it's not a UUID
		if tenantIDStr, okStr := tenantID.(string); okStr {
			var err error
			tenantUUID, err = uuid.Parse(tenantIDStr)
			if err != nil {
				log.Printf("ERROR: Invalid tenant ID format: %v (type: %T)\n", tenantID, tenantID)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
				return
			}
		} else {
			log.Printf("ERROR: Invalid tenant ID type: %T, value: %v\n", tenantID, tenantID)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID type"})
			return
		}
	}

	// Check if tenantID is nil/empty
	if tenantUUID == uuid.Nil {
		log.Printf("ERROR: Tenant ID is nil/empty\n")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	var request services.BatchEvaluateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	if len(request.FrameworkIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one framework_id is required"})
		return
	}

	// Check if details should be included
	includeDetails := c.Query("include_details") == "true"

	response, err := h.frameworkContextService.BatchEvaluateFrameworks(tenantUUID, &request, includeDetails)
	if err != nil {
		log.Printf("ERROR: Failed to batch evaluate frameworks for tenant %s: %v\n", tenantUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to evaluate frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, response)
}
