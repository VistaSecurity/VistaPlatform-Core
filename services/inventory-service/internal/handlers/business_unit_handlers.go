package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// businessUnitService is the slice of *services.BusinessUnitService the
// handlers depend on, so the contract test drives the real handlers over an
// in-memory stub.
type businessUnitService interface {
	List(ctx context.Context, tenantID uuid.UUID) ([]models.BusinessUnit, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (*models.BusinessUnit, error)
	Create(ctx context.Context, tenantID, actor uuid.UUID, in models.BusinessUnitInput) (*models.BusinessUnit, error)
	Update(ctx context.Context, tenantID, actor, id uuid.UUID, in models.BusinessUnitInput) (*models.BusinessUnit, error)
	Delete(ctx context.Context, tenantID, actor, id uuid.UUID, reassignTo *uuid.UUID) error
}

// BusinessUnitHandler serves /api/v2/inventory-service/dcim/business-units.
type BusinessUnitHandler struct{ svc businessUnitService }

// NewBusinessUnitHandler returns the handler over the real service.
func NewBusinessUnitHandler(svc *services.BusinessUnitService) *BusinessUnitHandler {
	return &BusinessUnitHandler{svc: svc}
}

// NewBusinessUnitHandlerFor returns the handler over any implementation of the
// service interface (tests).
func NewBusinessUnitHandlerFor(svc businessUnitService) *BusinessUnitHandler {
	return &BusinessUnitHandler{svc: svc}
}

func buRespondError(c *gin.Context, err error) {
	var inUse *services.BusinessUnitInUseError
	switch {
	case errors.Is(err, services.ErrBusinessUnitNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Business unit not found"})
	case errors.As(err, &inUse):
		c.JSON(http.StatusConflict, gin.H{"error": inUse.Error(), "assets": inUse.Assets, "prefixes": inUse.Prefixes})
	case errors.Is(err, services.ErrBusinessUnitSlugExists):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, services.ErrBusinessUnitInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": strings.TrimPrefix(err.Error(), "invalid business unit: ")})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Business unit request failed"})
	}
}

func buID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business unit id"})
		return uuid.Nil, false
	}
	return id, true
}

// List handles GET /dcim/business-units.
func (h *BusinessUnitHandler) List(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	list, err := h.svc.List(c.Request.Context(), tenantID)
	if err != nil {
		buRespondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"business_units": list, "total": len(list)})
}

// Get handles GET /dcim/business-units/:id.
func (h *BusinessUnitHandler) Get(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	id, ok := buID(c)
	if !ok {
		return
	}
	u, err := h.svc.Get(c.Request.Context(), tenantID, id)
	if err != nil {
		buRespondError(c, err)
		return
	}
	c.JSON(http.StatusOK, u)
}

// Create handles POST /dcim/business-units.
func (h *BusinessUnitHandler) Create(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	var in models.BusinessUnitInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	u, err := h.svc.Create(c.Request.Context(), tenantID, getOptionalUserID(c), in)
	if err != nil {
		buRespondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, u)
}

// Update handles PUT /dcim/business-units/:id (a patch: absent fields are kept).
func (h *BusinessUnitHandler) Update(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	id, ok := buID(c)
	if !ok {
		return
	}
	var in models.BusinessUnitInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	u, err := h.svc.Update(c.Request.Context(), tenantID, getOptionalUserID(c), id, in)
	if err != nil {
		buRespondError(c, err)
		return
	}
	c.JSON(http.StatusOK, u)
}

// Delete handles DELETE /dcim/business-units/:id?reassign_to=<id>. 409 when
// assets or network segments still reference the unit and no target is given.
func (h *BusinessUnitHandler) Delete(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}
	id, ok := buID(c)
	if !ok {
		return
	}
	var reassign *uuid.UUID
	if raw := strings.TrimSpace(c.Query("reassign_to")); raw != "" {
		r, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "reassign_to is not a uuid"})
			return
		}
		reassign = &r
	}
	if err := h.svc.Delete(c.Request.Context(), tenantID, getOptionalUserID(c), id, reassign); err != nil {
		buRespondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
