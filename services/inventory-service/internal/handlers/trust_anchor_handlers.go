package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
	"github.com/vistasecurity/vistaplatform/shared/certificates/publicroots"
)

// trustAnchorStore is the persistence surface the trust-anchor handlers need.
// *certtrust.Store is the production implementation; the contract test drives
// the real handlers over an in-memory stub.
type trustAnchorStore interface {
	ListAnchors(ctx context.Context, tenantID uuid.UUID) ([]certtrust.Anchor, error)
	CreateAnchor(ctx context.Context, tenantID uuid.UUID, req certtrust.CreateRequest) (*certtrust.Anchor, error)
	UpdateAnchor(ctx context.Context, tenantID, id uuid.UUID, req certtrust.UpdateRequest) (*certtrust.Anchor, error)
	DeleteAnchor(ctx context.Context, tenantID, id uuid.UUID) error
	CreateAnchorFromChain(ctx context.Context, tenantID uuid.UUID, req certtrust.FromChainRequest) (*certtrust.Anchor, error)
}

// PublicRootsInfo is the GET /trust-anchors/public-roots body.
type PublicRootsInfo struct {
	Version   string `json:"version"`
	RootCount int    `json:"root_count"`
	Source    string `json:"source,omitempty"`
}

// TrustAnchorHandler serves Settings -> Certificates -> Trusted CAs and the
// certificate drawer's Trust / Distrust action.
type TrustAnchorHandler struct {
	store       trustAnchorStore
	publicRoots func() PublicRootsInfo
}

// NewTrustAnchorHandler returns a handler over store, reporting the embedded
// public root bundle.
func NewTrustAnchorHandler(store trustAnchorStore) *TrustAnchorHandler {
	return &TrustAnchorHandler{store: store, publicRoots: embeddedPublicRoots}
}

func embeddedPublicRoots() PublicRootsInfo {
	return PublicRootsInfo{Version: publicroots.Version(), RootCount: publicroots.Count(), Source: publicroots.Source()}
}

// maxTrustAnchorBody bounds a create / update body: a PEM chain plus a note.
const maxTrustAnchorBody = certtrust.MaxPEMBytes + (64 << 10)

// decodeStrict reads a JSON body, refusing unknown fields (the contract's
// request schemas are additionalProperties: false) and oversize bodies.
func decodeStrict(c *gin.Context, dst interface{}) bool {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxTrustAnchorBody+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not read request body"})
		return false
	}
	if len(body) > maxTrustAnchorBody {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request body exceeds the 1 MiB limit"})
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return false
	}
	return true
}

func (h *TrustAnchorHandler) writeError(c *gin.Context, op string, err error) {
	var invalid *certtrust.ErrInvalid
	var conflict *certtrust.ErrConflict
	switch {
	case errors.As(err, &invalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": invalid.Msg})
	case errors.As(err, &conflict):
		c.JSON(http.StatusConflict, gin.H{"error": conflict.Error()})
	case errors.Is(err, certtrust.ErrAnchorNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Trust decision not found"})
	default:
		log.Printf("[TrustAnchorHandler] %s: %v", op, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to " + op})
	}
}

func anchorIDParam(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust decision id"})
		return uuid.Nil, false
	}
	return id, true
}

// ListTrustAnchors handles GET /inventory-service/trust-anchors.
func (h *TrustAnchorHandler) ListTrustAnchors(c *gin.Context) {
	tenantID, ok := certTenantID(c)
	if !ok {
		return
	}
	anchors, err := h.store.ListAnchors(c.Request.Context(), tenantID)
	if err != nil {
		h.writeError(c, "list trust decisions", err)
		return
	}
	if anchors == nil {
		anchors = []certtrust.Anchor{}
	}
	c.JSON(http.StatusOK, gin.H{"anchors": anchors, "total": len(anchors)})
}

// GetPublicRoots handles GET /inventory-service/trust-anchors/public-roots.
func (h *TrustAnchorHandler) GetPublicRoots(c *gin.Context) {
	if _, ok := certTenantID(c); !ok {
		return
	}
	c.JSON(http.StatusOK, h.publicRoots())
}

type trustAnchorCreateBody struct {
	CertificateID  *string `json:"certificate_id"`
	CertificatePEM *string `json:"certificate_pem"`
	Decision       string  `json:"decision"`
	Note           *string `json:"note"`
}

// CreateTrustAnchor handles POST /inventory-service/trust-anchors.
func (h *TrustAnchorHandler) CreateTrustAnchor(c *gin.Context) {
	tenantID, ok := certTenantID(c)
	if !ok {
		return
	}
	var body trustAnchorCreateBody
	if !decodeStrict(c, &body) {
		return
	}
	req := certtrust.CreateRequest{Decision: body.Decision, DecidedBy: getOptionalUserID(c)}
	if body.CertificateID != nil {
		id, err := uuid.Parse(*body.CertificateID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "certificate_id is not a valid id"})
			return
		}
		req.CertificateID = &id
	}
	if body.CertificatePEM != nil {
		req.CertificatePEM = *body.CertificatePEM
	}
	if body.Note != nil {
		req.Note = *body.Note
	}
	anchor, err := h.store.CreateAnchor(c.Request.Context(), tenantID, req)
	if err != nil {
		h.writeError(c, "record trust decision", err)
		return
	}
	c.JSON(http.StatusCreated, anchor)
}

type trustAnchorUpdateBody struct {
	Decision *string `json:"decision"`
	Note     *string `json:"note"`
}

// UpdateTrustAnchor handles PUT /inventory-service/trust-anchors/:id.
func (h *TrustAnchorHandler) UpdateTrustAnchor(c *gin.Context) {
	tenantID, ok := certTenantID(c)
	if !ok {
		return
	}
	id, ok := anchorIDParam(c)
	if !ok {
		return
	}
	var body trustAnchorUpdateBody
	if !decodeStrict(c, &body) {
		return
	}
	anchor, err := h.store.UpdateAnchor(c.Request.Context(), tenantID, id, certtrust.UpdateRequest{
		Decision: body.Decision, Note: body.Note, DecidedBy: getOptionalUserID(c),
	})
	if err != nil {
		h.writeError(c, "update trust decision", err)
		return
	}
	c.JSON(http.StatusOK, anchor)
}

// DeleteTrustAnchor handles DELETE /inventory-service/trust-anchors/:id.
func (h *TrustAnchorHandler) DeleteTrustAnchor(c *gin.Context) {
	tenantID, ok := certTenantID(c)
	if !ok {
		return
	}
	id, ok := anchorIDParam(c)
	if !ok {
		return
	}
	if err := h.store.DeleteAnchor(c.Request.Context(), tenantID, id); err != nil {
		h.writeError(c, "remove trust decision", err)
		return
	}
	c.Status(http.StatusNoContent)
}

type trustAnchorFromChainBody struct {
	ChainPEM string  `json:"chain_pem"`
	Decision string  `json:"decision"`
	Note     *string `json:"note"`
}

// CreateTrustAnchorFromChain handles POST /inventory-service/trust-anchors/from-chain:
// trust (or distrust) the top CA of the chain a server presented — what an
// integration's "Trust this CA" sends (E1).
func (h *TrustAnchorHandler) CreateTrustAnchorFromChain(c *gin.Context) {
	tenantID, ok := certTenantID(c)
	if !ok {
		return
	}
	var body trustAnchorFromChainBody
	if !decodeStrict(c, &body) {
		return
	}
	req := certtrust.FromChainRequest{ChainPEM: body.ChainPEM, Decision: body.Decision, DecidedBy: getOptionalUserID(c)}
	if body.Note != nil {
		req.Note = *body.Note
	}
	anchor, err := h.store.CreateAnchorFromChain(c.Request.Context(), tenantID, req)
	if err != nil {
		h.writeError(c, "record trust decision", err)
		return
	}
	c.JSON(http.StatusCreated, anchor)
}

// internalTrustStore is what the internal trust route reads
// (*certtrust.Store in production).
type internalTrustStore interface {
	InternalAnchors(ctx context.Context, tenantID uuid.UUID) (certtrust.InternalAnchors, error)
}

// InternalTrustHandler serves GET /inventory-service/internal/trust/anchors:
// the tenant's trust decisions for a service building a TLS trust pool
// (a connector service, slice 4). Mounted only behind
// RequireSignedServiceCall, which sets the signed tenant.
type InternalTrustHandler struct {
	store internalTrustStore
}

// NewInternalTrustHandler returns the handler over store.
func NewInternalTrustHandler(store internalTrustStore) *InternalTrustHandler {
	return &InternalTrustHandler{store: store}
}

// Anchors handles GET /inventory-service/internal/trust/anchors.
func (h *InternalTrustHandler) Anchors(c *gin.Context) {
	tenantID, ok := certTenantID(c)
	if !ok {
		return
	}
	out, err := h.store.InternalAnchors(c.Request.Context(), tenantID)
	if err != nil {
		log.Printf("[InternalTrustHandler] tenant %s: %v", tenantID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list trust decisions"})
		return
	}
	c.JSON(http.StatusOK, out)
}

// RegisterInternalTrustRoutes mounts the internal trust read on a group that
// already carries the signed-call gate (mountSourceImportRoutes).
func RegisterInternalTrustRoutes(internal *gin.RouterGroup, h *InternalTrustHandler) {
	internal.GET("/inventory-service/internal/trust/anchors", h.Anchors)
}
