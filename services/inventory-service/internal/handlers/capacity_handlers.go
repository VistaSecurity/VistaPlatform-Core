package handlers

// GET /api/v2/inventory-service/dcim/capacity (dcim.read): the facilities
// capacity roll-up behind the Facilities dashboard. One JSON document, wrapped
// in the usual {"data": ...} envelope. See services/capacity_service.go.

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// CapacityStore is the roll-up; services.CapacityService implements it.
type CapacityStore interface {
	Report(ctx context.Context, tenant uuid.UUID) (services.CapacityReport, error)
}

// CapacityHandler serves the capacity route.
type CapacityHandler struct{ store CapacityStore }

// NewCapacityHandler returns the handler over store.
func NewCapacityHandler(store CapacityStore) *CapacityHandler { return &CapacityHandler{store: store} }

// Get is GET /dcim/capacity.
func (h *CapacityHandler) Get(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	rep, err := h.store.Report(c.Request.Context(), tenant)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rep})
}
