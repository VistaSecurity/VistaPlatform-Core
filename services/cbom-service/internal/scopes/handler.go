package scopes

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

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

// assetCounter answers "how many assets match this query?" — inventory-service,
// over the service-to-service hop. It is an interface for the same reason
// scopeStore is: the contract test runs the HTTP layer with no network.
type assetCounter interface {
	CountAssets(ctx context.Context, authToken, tenantID, assetQuery string) (int64, error)
}

// Handler exposes Scope CRUD over HTTP. Routes are mounted under
// /api/v1/cbom-service/scopes from cmd/main.go.
type Handler struct {
	repo   scopeStore
	assets assetCounter
}

// NewHandler constructs a Handler over the given store. Production passes a
// *Repository; tests pass an in-memory stub.
//
// The asset counter is optional and is wired with WithAssetCounter: without it
// a preview reports `status: unavailable` rather than a number, which is the
// honest answer when there is nothing to ask.
func NewHandler(repo scopeStore) *Handler {
	return &Handler{repo: repo}
}

// WithAssetCounter wires the inventory-service client the preview counts
// through. Returns the handler so it can be chained at construction.
func (h *Handler) WithAssetCounter(a assetCounter) *Handler {
	h.assets = a
	return h
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
	// Validate before storing. A scope whose query fails at generate time is an
	// artifact that either does not exist or claims a boundary nobody checked.
	// 400 with the full diagnostics: the caller is a person typing a predicate
	// into an editor, and a span is what turns a refusal into a correction.
	canonical, err := ValidateQuery(req.Query)
	if err != nil {
		if writeQueryError(c, http.StatusBadRequest, req.Query, err) {
			return
		}
		sharedapi.BadRequest(c, err.Error())
		return
	}

	scope := Scope{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Query:       canonical,
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
	if err := ValidateName(req.Name); err != nil {
		sharedapi.BadRequest(c, err.Error())
		return
	}
	// Validate on UPDATE too, and store the canonical form. Validating only on
	// create would leave the one path a tenant actually uses to break a scope —
	// editing it — unguarded, and the version bump compares the stored text, so
	// a non-canonical edit would look like a change when it is not.
	canonical, err := ValidateQuery(req.Query)
	if err != nil {
		if writeQueryError(c, http.StatusBadRequest, req.Query, err) {
			return
		}
		sharedapi.BadRequest(c, err.Error())
		return
	}
	req.Query = canonical

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

// preview — POST /scopes/:id/preview. Returns the scope's query and how many
// assets it currently matches.
//
// The count comes from inventory-service, which compiles the SAME query string
// the CBOM generation will send it. That is the whole design: the number a
// customer adjusts a scope against and the rows the artifact ends up containing
// are one predicate answered by one service, so a preview cannot promise a
// boundary the generation then disagrees with. Counting here — in cbom-service,
// against its own idea of what a scope means — is exactly the second opinion
// this workstream deleted.
//
// A count that cannot be obtained is reported as `status: unavailable` with a
// null count, never as zero. "Your scope matches nothing" is the worst possible
// wrong answer for an attestation boundary, and it is the one a fail-soft zero
// would give.
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

	// Validate before counting, and answer 422 if the stored query no longer
	// validates — the same answer generation gives, for the same reason. A
	// preview that silently skipped a broken predicate would tell a customer
	// their scope is fine right up until the artifact refuses to build.
	canonical, err := ValidateQuery(scope.Query)
	if err != nil {
		writeQueryError(c, http.StatusUnprocessableEntity, scope.Query, err)
		return
	}

	body := gin.H{"scope_id": scope.ID, "name": scope.Name, "query": canonical}
	if h.assets == nil {
		// No inventory client wired (the contract test constructs the handler
		// without one). Say so rather than inventing a number.
		body["preview"] = gin.H{
			"status":        "unavailable",
			"matched_count": nil,
			"note":          "inventory-service is not reachable from this deployment",
		}
		c.JSON(http.StatusOK, body)
		return
	}

	count, err := h.assets.CountAssets(c.Request.Context(), bearerToken(c), tenantID.String(), canonical)
	if err != nil {
		log.Printf("preview: counting assets for scope %s: %v", scope.ID, err)
		body["preview"] = gin.H{
			"status":        "unavailable",
			"matched_count": nil,
			"note":          "inventory-service did not answer; try again",
		}
		c.JSON(http.StatusOK, body)
		return
	}
	body["preview"] = gin.H{"status": "ok", "matched_count": count}
	c.JSON(http.StatusOK, body)
}

// writeQueryError renders a query-language failure with QUERY_LANGUAGE §10's
// structured diagnostics — one entry per problem, each with its code, message,
// byte span and suggestion — rather than one flattened sentence.
//
// The status is the caller's, because the same failure means different things
// at different moments: 400 when a person is typing a scope and can fix it, 422
// when a STORED scope no longer validates and the request itself was fine.
//
// It returns true when it wrote a response, so a caller can `if
// writeQueryError(...) { return }`. An error carrying no diagnostics is not
// one of ours and is left to the caller.
func writeQueryError(c *gin.Context, status int, src string, err error) bool {
	qe, ok := AsInvalidQuery(err)
	if !ok {
		return false
	}
	if src == "" {
		src = qe.Query
	}
	out := make([]gin.H, 0, len(qe.Errors))
	for _, e := range qe.Errors {
		item := gin.H{
			"code":    string(e.Code),
			"message": e.Message,
			"span":    gin.H{"start": e.Span.Start, "end": e.Span.End},
		}
		if e.Suggestion != "" {
			item["suggestion"] = e.Suggestion
		}
		out = append(out, item)
	}
	c.JSON(status, gin.H{"error": "Invalid query", "query": src, "errors": out})
	return true
}

// bearerToken returns the caller's token, for the S2S hop to inventory-service.
//
// The hop is HMAC-signed either way (serviceauth), so this is the caller's
// identity travelling with the request rather than the authorisation for it —
// the same thing the CBOM generation path passes.
func bearerToken(c *gin.Context) string {
	const prefix = "Bearer "
	h := c.GetHeader("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}
