package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identitysettings"
)

type IdentityDiscoverySettingsStore interface {
	Get(context.Context, uuid.UUID) (identitysettings.Settings, error)
	Set(context.Context, uuid.UUID, uuid.UUID, identitysettings.Update) (identitysettings.Settings, error)
}
type IdentityDiscoverySettingsHandler struct {
	store IdentityDiscoverySettingsStore
}

func NewIdentityDiscoverySettingsHandler(store IdentityDiscoverySettingsStore) *IdentityDiscoverySettingsHandler {
	return &IdentityDiscoverySettingsHandler{store: store}
}
func (h *IdentityDiscoverySettingsHandler) Get(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	out, err := h.store.Get(c.Request.Context(), tenant)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "identity_discovery_settings_unavailable"})
		return
	}
	c.JSON(http.StatusOK, out)
}
func (h *IdentityDiscoverySettingsHandler) Update(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	actor, ok := autoScanUser(c)
	if !ok || actor == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "actor_required"})
		return
	}
	var body struct {
		Mode       string `json:"mode"`
		Version    int    `json:"version"`
		Reason     string `json:"reason"`
		Enrichment struct {
			Enabled           *bool       `json:"enabled"`
			ExcludedCIDRs     []string    `json:"excluded_cidrs"`
			SensitiveAssetIDs []uuid.UUID `json:"sensitive_asset_ids"`
		} `json:"enrichment"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || body.Enrichment.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_payload"})
		return
	}
	out, err := h.store.Set(c.Request.Context(), tenant, actor, identitysettings.Update{Mode: body.Mode, Version: body.Version, Reason: body.Reason, Enrichment: identitysettings.Enrichment{Enabled: *body.Enrichment.Enabled, ExcludedCIDRs: body.Enrichment.ExcludedCIDRs, SensitiveAssetIDs: body.Enrichment.SensitiveAssetIDs}})
	if err != nil {
		status := http.StatusInternalServerError
		code := "identity_discovery_settings_unavailable"
		switch {
		case errors.Is(err, identitysettings.ErrStaleVersion), errors.Is(err, identitysettings.ErrCapability), errors.Is(err, identitysettings.ErrActivated):
			status = http.StatusConflict
			code = err.Error()
		case errors.Is(err, identitysettings.ErrInvalid):
			status = http.StatusBadRequest
			code = identitysettings.ErrInvalid.Error()
		}
		response := gin.H{"error": code}
		if status != http.StatusInternalServerError {
			response["message"] = err.Error()
		}
		c.JSON(status, response)
		return
	}
	c.JSON(http.StatusOK, out)
}
