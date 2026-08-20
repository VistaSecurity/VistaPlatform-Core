package handlers

import (
	"log"
	"net/http"
	"strings"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PlatformFrameworkHandlers contains all platform framework handlers
type PlatformFrameworkHandlers struct {
	platformFrameworkService *services.PlatformFrameworkService
}

// NewPlatformFrameworkHandlers creates a new instance of platform framework handlers
func NewPlatformFrameworkHandlers(platformFrameworkService *services.PlatformFrameworkService) *PlatformFrameworkHandlers {
	return &PlatformFrameworkHandlers{
		platformFrameworkService: platformFrameworkService,
	}
}

// CreateFramework creates a new platform framework
func (h *PlatformFrameworkHandlers) CreateFramework(c *gin.Context) {
	var input models.PlatformFrameworkInput
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

	framework, err := h.platformFrameworkService.CreateFramework(&input, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create framework",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Framework created successfully",
		"framework": framework,
	})
}

// UpdateFramework updates a platform framework
func (h *PlatformFrameworkHandlers) UpdateFramework(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	var input models.PlatformFrameworkInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	framework, err := h.platformFrameworkService.UpdateFramework(id, &input)
	if err != nil {
		if err.Error() == "framework not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Framework not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update framework",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Framework updated successfully",
		"framework": framework,
	})
}

// PublishFramework publishes or archives a framework
func (h *PlatformFrameworkHandlers) PublishFramework(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	var input models.PublishFrameworkInput
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

	framework, err := h.platformFrameworkService.PublishFramework(id, &input, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to publish framework",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Framework published successfully",
		"framework": framework,
	})
}

// ListFrameworks lists all platform frameworks
func (h *PlatformFrameworkHandlers) ListFrameworks(c *gin.Context) {
	statusFilter := c.Query("status") // Optional filter: draft, published, archived

	frameworks, err := h.platformFrameworkService.ListFrameworks(statusFilter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list frameworks",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"frameworks": frameworks,
	})
}

// GetFramework gets a platform framework by ID
func (h *PlatformFrameworkHandlers) GetFramework(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	framework, err := h.platformFrameworkService.GetFramework(id)
	if err != nil {
		if err.Error() == "framework not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Framework not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get framework",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"framework": framework,
	})
}

// DeleteFramework deletes a platform framework
func (h *PlatformFrameworkHandlers) DeleteFramework(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	err = h.platformFrameworkService.DeleteFramework(id)
	if err != nil {
		if err.Error() == "framework not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Framework not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete framework",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Framework deleted successfully",
	})
}

// CreateControl creates a control for a platform framework
func (h *PlatformFrameworkHandlers) CreateControl(c *gin.Context) {
	frameworkIDStr := c.Param("id")
	frameworkID, err := uuid.Parse(frameworkIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	var input models.PlatformFrameworkControlInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	control, err := h.platformFrameworkService.CreateControl(frameworkID, &input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create control",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Control created successfully",
		"control": control,
	})
}

// UpdateControl updates a platform framework control
func (h *PlatformFrameworkHandlers) UpdateControl(c *gin.Context) {
	frameworkIDStr := c.Param("id")
	controlIDStr := c.Param("controlId")

	_, err := uuid.Parse(frameworkIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	controlID, err := uuid.Parse(controlIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}

	var input models.PlatformFrameworkControlInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	control, err := h.platformFrameworkService.UpdateControl(controlID, &input)
	if err != nil {
		if err.Error() == "control not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Control not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update control",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Control updated successfully",
		"control": control,
	})
}

// DeleteControl deletes a platform framework control
func (h *PlatformFrameworkHandlers) DeleteControl(c *gin.Context) {
	frameworkIDStr := c.Param("id")
	controlIDStr := c.Param("controlId")

	_, err := uuid.Parse(frameworkIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	controlID, err := uuid.Parse(controlIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}

	err = h.platformFrameworkService.DeleteControl(controlID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete control",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Control deleted successfully",
	})
}

// ListFrameworkVersions lists version snapshots for a framework
func (h *PlatformFrameworkHandlers) ListFrameworkVersions(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}

	versions, err := h.platformFrameworkService.ListFrameworkVersions(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list framework versions",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"versions": versions,
	})
}

// GetFrameworkVersion gets a specific version snapshot detail
func (h *PlatformFrameworkHandlers) GetFrameworkVersion(c *gin.Context) {
	versionIDStr := c.Param("versionId")
	versionID, err := uuid.Parse(versionIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid version ID"})
		return
	}

	version, err := h.platformFrameworkService.GetFrameworkVersion(versionID)
	if err != nil {
		if err.Error() == "version not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Version not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get framework version",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"version": version,
	})
}

// ListControlMeasurements lists the measurement rules mapped to a control.
func (h *PlatformFrameworkHandlers) ListControlMeasurements(c *gin.Context) {
	controlID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}

	measurements, err := h.platformFrameworkService.ListControlMeasurements(controlID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list control measurements"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"measurements": measurements})
}

// measurementError classifies a measurement-rule write failure.
//
// Everything used to collapse to a bare 500, which was harmless only while the
// endpoint could not succeed at all: now that it can, a rejected rule is the
// normal failure and the admin has to be told WHICH rule type or operator the
// measurement type allows. The rule builder shows the details verbatim, so
// only the validator's own messages are surfaced — anything else stays a 500
// with the reason in the log. Mirrors the tenant custom-policy handler.
func measurementError(c *gin.Context, verb string, err error, fallback string) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "validation failed"):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Validation failed", "details": msg})
	case strings.Contains(msg, "measurement type not found"):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Measurement type not found", "details": msg})
	default:
		log.Printf("%s control measurement: %v", verb, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fallback})
	}
}

// AddControlMeasurement adds a measurement mapping to a control
func (h *PlatformFrameworkHandlers) AddControlMeasurement(c *gin.Context) {
	controlIDStr := c.Param("id")
	controlID, err := uuid.Parse(controlIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}

	var input models.ControlMeasurementInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	measurement, err := h.platformFrameworkService.AddControlMeasurement(controlID, &input)
	if err != nil {
		measurementError(c, "add", err, "Failed to add control measurement")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":     "Control measurement added successfully",
		"measurement": measurement,
	})
}

// UpdateControlMeasurement updates a control measurement mapping
func (h *PlatformFrameworkHandlers) UpdateControlMeasurement(c *gin.Context) {
	controlIDStr := c.Param("id")
	measurementIDStr := c.Param("measurementId")

	_, err := uuid.Parse(controlIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}

	measurementID, err := uuid.Parse(measurementIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid measurement ID"})
		return
	}

	var input models.ControlMeasurementInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
		})
		return
	}

	measurement, err := h.platformFrameworkService.UpdateControlMeasurement(measurementID, &input)
	if err != nil {
		if err.Error() == "measurement not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Measurement not found"})
			return
		}
		measurementError(c, "update", err, "Failed to update control measurement")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Control measurement updated successfully",
		"measurement": measurement,
	})
}

// DeleteControlMeasurement deletes a control measurement mapping
func (h *PlatformFrameworkHandlers) DeleteControlMeasurement(c *gin.Context) {
	controlIDStr := c.Param("id")
	measurementIDStr := c.Param("measurementId")

	_, err := uuid.Parse(controlIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}

	measurementID, err := uuid.Parse(measurementIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid measurement ID"})
		return
	}

	err = h.platformFrameworkService.DeleteControlMeasurement(measurementID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete control measurement",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Control measurement deleted successfully",
	})
}
