package handlers

// Settings → Asset Lifecycle, the drift half (workstream 4.7).
//
// One setting: how far back the `drift` producer's baseline reaches. It is a
// separate endpoint from the asset-lifecycle policy beside it on the same page
// because the two live in different places — the lifecycle policy has its own
// table, the drift window is a key in `tenant_admin_settings.config` — and
// smuggling one into the other's payload would put a jsonb setting behind a
// row-shaped API that cannot express "leave the rest of the document alone".

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/driftsettings"
)

// DriftSettingsHandler serves the tenant's drift settings.
type DriftSettingsHandler struct {
	settings driftSettingsStore
}

type driftSettingsStore interface {
	Get(ctx context.Context, tenantID uuid.UUID) (driftsettings.Settings, error)
	Set(ctx context.Context, tenantID, actorUserID uuid.UUID, days int) (driftsettings.Settings, error)
}

// NewDriftSettingsHandler wires the handler.
func NewDriftSettingsHandler(settings driftSettingsStore) *DriftSettingsHandler {
	return &DriftSettingsHandler{settings: settings}
}

// GetDriftSettings handles GET /settings/drift.
func (h *DriftSettingsHandler) GetDriftSettings(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	out, err := h.settings.Get(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the drift settings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"drift": gin.H{
		"baseline_days": out.BaselineDays,
		"min_days":      driftsettings.MinBaselineDays,
		"max_days":      driftsettings.MaxBaselineDays,
	}})
}

// UpdateDriftSettings handles PUT /settings/drift.
//
// `baseline_days` is a POINTER in the body so "not sent" and "sent as 0" are
// distinguishable. A plain int renders both as 0, and 0 is out of range — so a
// client sending an unrelated future field would get a 400 it could not
// explain, or (worse, in the shape this repository keeps finding) a silent
// write of a value nobody asked for.
func (h *DriftSettingsHandler) UpdateDriftSettings(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	var body struct {
		BaselineDays *int `json:"baseline_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.BaselineDays == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"message": "baseline_days is required: how many days of history the drift baseline covers",
		})
		return
	}
	out, err := h.settings.Set(c.Request.Context(), tenantID, userID, *body.BaselineDays)
	if errors.Is(err, driftsettings.ErrInvalidBaselineDays) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid baseline_days",
			"message": err.Error(),
		})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the drift settings"})
		return
	}

	// The audit trail. `tenant_admin_settings` carries its own change trigger,
	// so the row-level before/after is recorded whatever happens here; this is
	// the activity-log entry that names the ACT — a tenant admin changing what
	// the platform reports as a change.
	resourceType := "drift_settings"
	logAuditActivity(c, "settings.drift.updated", auditmiddleware.EventCategoryConfig, "update",
		&resourceType, &tenantID, nil,
		map[string]any{"baseline_days": out.BaselineDays},
		[]string{"baseline_days"},
		nil)

	c.JSON(http.StatusOK, gin.H{"drift": gin.H{
		"baseline_days": out.BaselineDays,
		"min_days":      driftsettings.MinBaselineDays,
		"max_days":      driftsettings.MaxBaselineDays,
	}})
}
