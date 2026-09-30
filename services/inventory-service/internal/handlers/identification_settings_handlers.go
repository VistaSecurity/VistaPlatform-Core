package handlers

// Settings → Identification rules, the writable half (workstream 4.6).
//
// Two settings: the learned matcher's auto-accept threshold, and whether a fixed
// rule may merge two existing assets it is sure are one device
// (`auto_merge_existing`, Phase 4). Between them they are the only places
// in the product where a tenant decides whether the platform may merge two of
// their assets without asking — so this is deliberately its own small handler
// rather than a field smuggled into a larger settings payload, and the
// reachability check for it is a control on a page a tenant can navigate to,
// not an endpoint.

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
	Update(ctx context.Context, tenantID, actorUserID uuid.UUID, in services.IdentificationSettingsUpdate) (services.IdentificationSettings, error)
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
// A PARTIAL update: send either field, or both. Both are POINTERS in the body so
// "not sent" and "sent as 0 / false" are distinguishable. They mean opposite
// things — leave it alone, and turn it OFF — and a plain float64 or bool renders
// both as the zero value, so a client that only meant to flip the rule-merge
// toggle would silently disable a tenant's auto-accept, and the reverse. A body
// carrying neither field is a 400, not a no-op that reports success.
func (h *IdentificationSettingsHandler) UpdateIdentificationSettings(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	var body struct {
		AutoAcceptThreshold *float64 `json:"auto_accept_threshold"`
		AutoMergeExisting   *bool    `json:"auto_merge_existing"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || (body.AutoAcceptThreshold == nil && body.AutoMergeExisting == nil) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"message": "send auto_accept_threshold (a number between 0 and 1, where 0 means never auto-accept), " +
				"auto_merge_existing (true or false), or both",
		})
		return
	}
	out, err := h.settings.Update(c.Request.Context(), tenantID, userID, services.IdentificationSettingsUpdate{
		AutoAcceptThreshold: body.AutoAcceptThreshold,
		AutoMergeExisting:   body.AutoMergeExisting,
	})
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

	// The audit trail. `tenant_admin_settings` carries its own change trigger
	// (`log_tenant_admin_settings_change`), so the row-level before/after is
	// recorded whatever happens here; this is the activity-log entry that names
	// the ACT — a tenant admin changing how much the platform may decide on its
	// own. Only the fields the caller SENT are listed as changed.
	newValues := map[string]any{}
	changed := []string{}
	if body.AutoAcceptThreshold != nil {
		newValues["auto_accept_threshold"] = out.AutoAcceptThreshold
		changed = append(changed, "auto_accept_threshold")
	}
	if body.AutoMergeExisting != nil {
		newValues["auto_merge_existing"] = out.AutoMergeExisting
		changed = append(changed, "auto_merge_existing")
	}
	resourceType := "identification_settings"
	logAuditActivity(c, "settings.identification.updated", auditmiddleware.EventCategoryConfig, "update",
		&resourceType, &tenantID, nil, newValues, changed,
		map[string]any{"matcher_model_id": h.matcherModelID})

	c.JSON(http.StatusOK, gin.H{"identification": out})
}
