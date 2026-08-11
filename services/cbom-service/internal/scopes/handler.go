package scopes

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/middleware"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// scopeStore is the persistence surface the Handler needs. *Repository is the
// production implementation; depending on the interface (rather than the
// concrete type) lets the HTTP layer be exercised by the contract test with an
// in-memory stub, no database required. Keep this in sync with the methods the
// handlers below actually call.
type scopeStore interface {
	SeedDefaultsIfMissing(ctx context.Context, tenantID, seededBy uuid.UUID) (bool, error)
	List(ctx context.Context, tenantID uuid.UUID) ([]Scope, error)
	Get(ctx context.Context, tenantID, scopeID uuid.UUID) (*Scope, error)
	Create(ctx context.Context, s *Scope) error
	Update(ctx context.Context, tenantID, scopeID, updatedBy uuid.UUID, req UpdateRequest) (*Scope, error)
	Delete(ctx context.Context, tenantID, scopeID uuid.UUID) error
}

// Handler exposes Scope CRUD over HTTP. Routes are mounted under
// /api/v1/cbom-service/scopes from cmd/main.go.
type Handler struct {
	repo scopeStore
}

// NewHandler constructs a Handler over the given store. Production passes a
// *Repository; tests pass an in-memory stub.
func NewHandler(repo scopeStore) *Handler {
	return &Handler{repo: repo}
}

// RegisterRoutes attaches the scope endpoints to the given route group.
// Caller is responsible for applying auth + tenant middleware to the group.
// writeGate guards the mutating routes (a Scope is the attestation boundary
// for CBOM artifacts — see); reads and preview stay tenant-wide.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup, writeGate ...gin.HandlerFunc) {
	rg.GET("/scopes", h.list)
	rg.POST("/scopes", append(append([]gin.HandlerFunc{}, writeGate...), h.create)...)
	rg.GET("/scopes/:id", h.get)
	rg.PUT("/scopes/:id", append(append([]gin.HandlerFunc{}, writeGate...), h.update)...)
	rg.DELETE("/scopes/:id", append(append([]gin.HandlerFunc{}, writeGate...), h.delete)...)
	rg.POST("/scopes/:id/preview", h.preview)
}

// list — GET /scopes. Also lazy-seeds the three system defaults on first call
// for a tenant, so any new tenant gets a usable starting set without an
// explicit setup step.
func (h *Handler) list(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	userID, _ := middleware.GetUserIDFromContext(c)
	if _, err := h.repo.SeedDefaultsIfMissing(c.Request.Context(), tenantID, userID); err != nil {
		fmt.Fprintf(os.Stderr, "scopes.list seed defaults failed: tenant=%s user=%s err=%+v\n", tenantID, userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	scopes, err := h.repo.List(c.Request.Context(), tenantID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scopes.list query failed: tenant=%s err=%+v\n", tenantID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"scopes": scopes})
}

// create — POST /scopes.
func (h *Handler) create(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	userID, _ := middleware.GetUserIDFromContext(c)

	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sharedapi.BadRequest(c, "invalid request body")
		return
	}
	if err := ValidateName(req.Name); err != nil {
		sharedapi.BadRequest(c, err.Error())
		return
	}

	scope := Scope{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Predicate:   req.Predicate,
		IsDefault:   false,
		IsSystem:    false,
		CreatedBy:   userID,
		UpdatedBy:   userID,
	}
	if err := h.repo.Create(c.Request.Context(), &scope); err != nil {
		log.Printf("create scope: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusCreated, scope)
}

// get — GET /scopes/:id.
func (h *Handler) get(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	scopeID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope id"})
		return
	}
	scope, err := h.repo.Get(c.Request.Context(), tenantID, scopeID)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scope not found"})
		return
	}
	if err != nil {
		log.Printf("get scope: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, scope)
}

// update — PUT /scopes/:id.
func (h *Handler) update(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	userID, _ := middleware.GetUserIDFromContext(c)
	scopeID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope id"})
		return
	}
	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sharedapi.BadRequest(c, "invalid request body")
		return
	}

	scope, err := h.repo.Update(c.Request.Context(), tenantID, scopeID, userID, req)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scope not found"})
		return
	}
	if err != nil {
		log.Printf("update scope: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, scope)
}

// delete — DELETE /scopes/:id. System scopes return 409.
func (h *Handler) delete(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	scopeID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope id"})
		return
	}
	err = h.repo.Delete(c.Request.Context(), tenantID, scopeID)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scope not found"})
		return
	}
	if errors.Is(err, ErrSystemScopeDelete) {
		c.JSON(http.StatusConflict, gin.H{"error": "system scopes cannot be deleted; edit instead"})
		return
	}
	if err != nil {
		log.Printf("delete scope: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// preview — POST /scopes/:id/preview. Stub for Phase 1: returns the predicate
// echoed back. Phase 2 will resolve this against inventory-service to return
// an asset count, so the UI can show "this scope currently matches N assets."
func (h *Handler) preview(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	scopeID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope id"})
		return
	}
	scope, err := h.repo.Get(c.Request.Context(), tenantID, scopeID)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scope not found"})
		return
	}
	if err != nil {
		log.Printf("preview: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	// Phase 1 stub: echo predicate. Phase 2 wires this to inventory-service.
	c.JSON(http.StatusOK, gin.H{
		"scope_id":  scope.ID,
		"name":      scope.Name,
		"predicate": scope.Predicate,
		"preview": gin.H{
			"status":        "not_implemented",
			"matched_count": nil,
			"note":          "scope evaluation against inventory ships in Phase 2",
		},
	})
}
