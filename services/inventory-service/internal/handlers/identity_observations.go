package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type IdentityObservationHandler struct{ service *services.AssetService }

func NewIdentityObservationHandler(service *services.AssetService) *IdentityObservationHandler {
	return &IdentityObservationHandler{service: service}
}

func (h *IdentityObservationHandler) Detail(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid observation ID"})
		return
	}
	out, err := h.service.GetIdentityObservation(c.Request.Context(), tenant, id)
	if writeObservationError(c, err) {
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *IdentityObservationHandler) Confirm(c *gin.Context) { h.decide(c, "confirmed") }
func (h *IdentityObservationHandler) Link(c *gin.Context)    { h.decide(c, "linked") }
func (h *IdentityObservationHandler) Dismiss(c *gin.Context) { h.decide(c, "dismissed") }

func (h *IdentityObservationHandler) decide(c *gin.Context, action string) {
	tenant, actor, ok := tenantAndUser(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid observation ID"})
		return
	}
	var input services.ObservationDecisionInput
	if err := c.ShouldBindJSON(&input); err != nil || strings.TrimSpace(input.Reason) == "" || (action == "linked" && (input.AssetID == nil || *input.AssetID == uuid.Nil)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "A reason is required; linking also requires an asset ID"})
		return
	}
	out, err := h.service.DecideIdentityObservation(c.Request.Context(), tenant, id, actor, action, input)
	if writeObservationError(c, err) {
		return
	}
	c.JSON(http.StatusOK, out)
}

func writeObservationError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, services.ErrObservationNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Observation or asset not found"})
	case errors.Is(err, services.ErrObservationChanged):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrObservationAllowance):
		c.JSON(http.StatusPaymentRequired, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to process identity observation"})
	}
	return true
}

func (h *IdentityObservationHandler) Summary(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	out, err := h.service.IdentitySummary(c.Request.Context(), tenant)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to read identity coverage"})
		return
	}
	c.JSON(http.StatusOK, out)
}

func (h *IdentityObservationHandler) List(c *gin.Context) {
	tenant, ok := autoScanTenant(c)
	if !ok {
		return
	}
	q := struct {
		State    string `form:"state" binding:"oneof=unresolved linked conflict dismissed expired all"`
		Page     int    `form:"page" binding:"min=1"`
		PageSize int    `form:"page_size" binding:"min=1,max=100"`
		AssetID  string `form:"asset_id"`
	}{State: "unresolved", Page: 1, PageSize: 50}
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid observation filters"})
		return
	}
	var assetID *uuid.UUID
	if q.AssetID != "" {
		id, err := uuid.Parse(q.AssetID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
			return
		}
		assetID = &id
	}
	out, err := h.service.ListIdentityObservations(c.Request.Context(), tenant, q.State, q.Page, q.PageSize, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to read identity observations"})
		return
	}
	c.JSON(http.StatusOK, out)
}
