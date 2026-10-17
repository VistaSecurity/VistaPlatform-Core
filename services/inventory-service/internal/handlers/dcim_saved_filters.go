package handlers

// Saved Filters routes (DCIM BUILD_PLAN row 5.4): /dcim/saved-filters. The
// route group gates on assets.read; the rule that decides who may publish or
// touch a shared filter lives in the service, fed by CanShare below.

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// SavedFilterStore is what the handlers need; services.SavedFilterService
// implements it over Postgres.
type SavedFilterStore interface {
	List(ctx context.Context, tenant, user uuid.UUID, kind string) ([]services.SavedFilter, error)
	Create(ctx context.Context, tenant uuid.UUID, who services.SavedFilterCaller, in services.SavedFilterInput) (services.SavedFilter, error)
	Update(ctx context.Context, tenant uuid.UUID, who services.SavedFilterCaller, id uuid.UUID, in services.SavedFilterInput) (services.SavedFilter, error)
	Delete(ctx context.Context, tenant uuid.UUID, who services.SavedFilterCaller, id uuid.UUID) error
}

// CanShareFunc answers whether a user may publish filters to the organisation.
type CanShareFunc func(ctx context.Context, tenant, user uuid.UUID) (bool, error)

// DcimSavedFilterHandler serves the saved-filter routes.
type DcimSavedFilterHandler struct {
	store    SavedFilterStore
	canShare CanShareFunc
}

// NewDcimSavedFilterHandler returns the handler.
func NewDcimSavedFilterHandler(store SavedFilterStore, canShare CanShareFunc) *DcimSavedFilterHandler {
	return &DcimSavedFilterHandler{store: store, canShare: canShare}
}

func (h *DcimSavedFilterHandler) caller(c *gin.Context) (uuid.UUID, services.SavedFilterCaller, bool) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return uuid.Nil, services.SavedFilterCaller{}, false
	}
	user, ok := sharedmw.GetUserIDFromContext(c)
	if !ok || user == uuid.Nil {
		dcimError(c, http.StatusUnauthorized, "unauthenticated", "A saved filter belongs to a signed-in user.")
		return uuid.Nil, services.SavedFilterCaller{}, false
	}
	can, err := h.canShare(c.Request.Context(), tenant, user)
	if err != nil {
		_ = c.Error(err)
		dcimError(c, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
		return uuid.Nil, services.SavedFilterCaller{}, false
	}
	return tenant, services.SavedFilterCaller{UserID: user, CanShare: can}, true
}

func savedFilterError(c *gin.Context, err error) {
	if qe, ok := services.AsQueryError(err); ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": gin.H{
			"code": "invalid_query", "message": "The query is not valid for this kind.",
			"query": qe.Query, "details": renderQueryErrors(qe.Errors),
		}})
		return
	}
	switch {
	case errors.Is(err, services.ErrSavedFilterNotFound):
		dcimError(c, http.StatusNotFound, "saved_filter_not_found", "No such saved filter.")
	case errors.Is(err, services.ErrSavedFilterForbidden):
		dcimError(c, http.StatusForbidden, "share_forbidden", err.Error())
	case errors.Is(err, services.ErrSavedFilterDuplicate):
		dcimError(c, http.StatusConflict, "saved_filter_exists", err.Error())
	case errors.Is(err, services.ErrSavedFilterInvalid):
		dcimError(c, http.StatusUnprocessableEntity, "invalid_saved_filter", err.Error())
	default:
		dcimStoreError(c, err)
	}
}

type savedFilterBody struct {
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	Description *string           `json:"description"`
	ObjectKinds []dcim.ObjectKind `json:"object_kinds"`
	Query       string            `json:"query"`
	Shared      bool              `json:"shared"`
	Weight      *int              `json:"weight"`
}

func (b savedFilterBody) input() services.SavedFilterInput {
	return services.SavedFilterInput{Name: b.Name, Slug: b.Slug, Description: b.Description, ObjectKinds: b.ObjectKinds, Query: b.Query, Shared: b.Shared, Weight: b.Weight}
}

// List is GET /dcim/saved-filters[?kind=].
func (h *DcimSavedFilterHandler) List(c *gin.Context) {
	tenant, who, ok := h.caller(c)
	if !ok {
		return
	}
	out, err := h.store.List(c.Request.Context(), tenant, who.UserID, c.Query("kind"))
	if err != nil {
		savedFilterError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "can_share": who.CanShare})
}

// Create is POST /dcim/saved-filters.
func (h *DcimSavedFilterHandler) Create(c *gin.Context) {
	tenant, who, ok := h.caller(c)
	if !ok {
		return
	}
	var b savedFilterBody
	if err := dcimStrictJSON(c, &b); err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	out, err := h.store.Create(c.Request.Context(), tenant, who, b.input())
	if err != nil {
		savedFilterError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": out})
}

// Update is PUT /dcim/saved-filters/{id}.
func (h *DcimSavedFilterHandler) Update(c *gin.Context) {
	tenant, who, ok := h.caller(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_id", "Saved filter id must be a UUID.")
		return
	}
	var b savedFilterBody
	if err := dcimStrictJSON(c, &b); err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	out, err := h.store.Update(c.Request.Context(), tenant, who, id, b.input())
	if err != nil {
		savedFilterError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// Delete is DELETE /dcim/saved-filters/{id}.
func (h *DcimSavedFilterHandler) Delete(c *gin.Context) {
	tenant, who, ok := h.caller(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_id", "Saved filter id must be a UUID.")
		return
	}
	if err := h.store.Delete(c.Request.Context(), tenant, who, id); err != nil {
		savedFilterError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
