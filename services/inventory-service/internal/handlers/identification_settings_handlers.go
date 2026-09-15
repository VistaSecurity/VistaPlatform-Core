package handlers

// Settings → Identification rules, the writable half (workstream 4.6).
//
// One setting today: the learned matcher's auto-accept threshold. It is the
// only NEW write path this workstream adds, and the only place in the product
// where a tenant grants the platform permission to merge two of their assets
// without asking — so it is deliberately its own small handler rather than a
// field smuggled into a larger settings payload, and the reachability check for
// it is a control on a page a tenant can navigate to, not an endpoint.

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// IdentificationSettingsHandler serves the tenant's identification settings.
type IdentificationSettingsHandler struct {
	settings identificationSettingsStore
	// matcherModelID names the matcher this build ships, so the page can say
	// what the threshold is a threshold ON — and, when it is empty, say that
	// nothing is scored and the threshold cannot fire.
	matcherModelID string
}

type identificationSettingsStore interface {
	Get(ctx context.Context, tenantID uuid.UUID) (services.IdentificationSettings, error)
	Set(ctx context.Context, tenantID, actorUserID uuid.UUID, threshold float64) (services.IdentificationSettings, error)
}

// NewIdentificationSettingsHandler wires the handler.
func NewIdentificationSettingsHandler(settings identificationSettingsStore, matcherModelID string) *IdentificationSettingsHandler {
	return &IdentificationSettingsHandler{settings: settings, matcherModelID: matcherModelID}
}

// GetIdentificationSettings handles GET /settings/identification.
func (h *IdentificationSettingsHandler) GetIdentificationSettings(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	out, err := h.settings.Get(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the identification settings"})
		return
	}
	out.MatcherModelID = h.matcherModelID
	c.JSON(http.StatusOK, gin.H{"identification": out})
}

// UpdateIdentificationSettings handles PUT /settings/identification.
//
// `auto_accept_threshold` is a POINTER in the body so "not sent" and "sent as
// 0" are distinguishable. They mean opposite things — leave it alone, and turn
// auto-accept OFF — and a plain float64 renders both as 0, so a client sending
// an unrelated future field would silently disable a tenant's auto-accept.
func (h *IdentificationSettingsHandler) UpdateIdentificationSettings(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	var body struct {
		AutoAcceptThreshold *float64 `json:"auto_accept_threshold"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.AutoAcceptThreshold == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"message": "auto_accept_threshold is required: a number between 0 and 1, where 0 means never auto-accept",
		})
		return
	}
	out, err := h.settings.Set(c.Request.Context(), tenantID, userID, *body.AutoAcceptThreshold)
	if errors.Is(err, services.ErrInvalidAutoAcceptThreshold) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid auto_accept_threshold",
			"message": err.Error(),
		})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the identification settings"})
		return
	}
	out.MatcherModelID = h.matcherModelID

	// The audit trail. `tenant_admin_settings` carries its own change trigger,
	// so the row-level before/after is recorded whatever happens here; this is
	// the activity-log entry that names the ACT — a tenant admin changing how
	// much the platform may decide on its own.
	resourceType := "identification_settings"
	logAuditActivity(c, "settings.identification.updated", auditmiddleware.EventCategoryConfig, "update",
		&resourceType, &tenantID, nil,
		map[string]any{"auto_accept_threshold": out.AutoAcceptThreshold},
		[]string{"auto_accept_threshold"},
		map[string]any{"matcher_model_id": h.matcherModelID})

	c.JSON(http.StatusOK, gin.H{"identification": out})
}
