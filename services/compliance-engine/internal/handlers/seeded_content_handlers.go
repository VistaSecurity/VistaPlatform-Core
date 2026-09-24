package handlers

// Catalog ▸ Frameworks — "Update available" → Accept (decision 4, RC-12).
//
// Upgrades keep a platform admin's edits to the frameworks, controls and
// measurement rules Vista ships, and store the content they would otherwise
// have written as an offer on the row. These three routes accept one. Each is
// scoped to its parent in the URL, like the edit routes beside it, and answers:
//
//	200  the row, updated, with its seeded-content state
//	404  no such row under that parent
//	409  the row has no update to accept
//
// Every accept is audited with the accepted values before and after: it
// rewrites content every tenant is evaluated against.

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// AcceptFrameworkUpdate serves POST /admin/frameworks/:id/accept-update.
func (h *PlatformFrameworkHandlers) AcceptFrameworkUpdate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}
	accepted, ok := h.acceptSeeded(c, services.SeededFramework, id, uuid.Nil, "Framework")
	if !ok {
		return
	}
	framework, err := h.platformFrameworkService.GetFramework(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update accepted, but the framework could not be reloaded"})
		return
	}
	auditSeededAccept(c, "platform_framework", id, framework.Name, accepted)
	c.JSON(http.StatusOK, gin.H{"message": "Update accepted", "framework": framework})
}

// AcceptControlUpdate serves POST /admin/frameworks/:id/controls/:controlId/accept-update.
func (h *PlatformFrameworkHandlers) AcceptControlUpdate(c *gin.Context) {
	frameworkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid framework ID"})
		return
	}
	controlID, err := uuid.Parse(c.Param("controlId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}
	accepted, ok := h.acceptSeeded(c, services.SeededControl, controlID, frameworkID, "Control")
	if !ok {
		return
	}
	control, err := h.platformFrameworkService.GetPlatformControl(controlID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update accepted, but the control could not be reloaded"})
		return
	}
	auditSeededAccept(c, "platform_framework_control", controlID, control.ControlID, accepted)
	c.JSON(http.StatusOK, gin.H{"message": "Update accepted", "control": control})
}

// AcceptMeasurementUpdate serves POST /admin/controls/:id/measurements/:measurementId/accept-update.
func (h *PlatformFrameworkHandlers) AcceptMeasurementUpdate(c *gin.Context) {
	controlID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid control ID"})
		return
	}
	measurementID, err := uuid.Parse(c.Param("measurementId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid measurement ID"})
		return
	}
	accepted, ok := h.acceptSeeded(c, services.SeededMeasurement, measurementID, controlID, "Measurement")
	if !ok {
		return
	}
	measurement, err := h.platformFrameworkService.GetPlatformMeasurement(measurementID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update accepted, but the measurement rule could not be reloaded"})
		return
	}
	auditSeededAccept(c, "control_measurement", measurementID, "", accepted)
	c.JSON(http.StatusOK, gin.H{"message": "Update accepted", "measurement": measurement})
}

// acceptSeeded runs the accept and writes the error response when it fails.
func (h *PlatformFrameworkHandlers) acceptSeeded(c *gin.Context, entity services.SeededEntity, id, parentID uuid.UUID, noun string) (*services.AcceptedSeededUpdate, bool) {
	accepted, err := h.platformFrameworkService.AcceptSeededUpdate(entity, id, parentID)
	switch {
	case errors.Is(err, services.ErrSeededContentNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": noun + " not found"})
		return nil, false
	case errors.Is(err, services.ErrNoSeededUpdate):
		c.JSON(http.StatusConflict, gin.H{"error": "No update available: an upgrade has not offered this " + seededNounLower(noun) + " any new content"})
		return nil, false
	case err != nil:
		log.Printf("accept seeded %s update %s: %v", entity, id, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept the update"})
		return nil, false
	}
	return accepted, true
}

func seededNounLower(noun string) string {
	switch noun {
	case "Framework":
		return "framework"
	case "Control":
		return "control"
	default:
		return "measurement rule"
	}
}

// auditSeededAccept records an accepted update. Best-effort, like the other
// explicit audit entries in this service: the accept has committed, and
// failing the request now would report a change that happened as one that did
// not. The request-level LogRequest entry lands regardless.
func auditSeededAccept(c *gin.Context, resourceType string, id uuid.UUID, name string, accepted *services.AcceptedSeededUpdate) {
	mw, ok := audithelpers.ExtractAuditMiddleware(c)
	if !ok {
		log.Printf("accept seeded update: audit middleware unavailable, %s %s unrecorded", resourceType, id)
		return
	}
	_ = audithelpers.LogWithContext(
		c.Request.Context(), mw,
		resourceType+".seeded_update_accepted", audithelpers.EventCategoryCompliance,
		"update", resourceType, id.String(), name,
		accepted.Before, accepted.After,
		audithelpers.AuditMetadata{
			ResourceName:  name,
			ChangeSummary: fmt.Sprintf("Accepted the shipped update for %s %s", resourceType, id),
			AdditionalData: map[string]interface{}{
				"framework_id": accepted.FrameworkID.String(),
			},
		},
	)
}
