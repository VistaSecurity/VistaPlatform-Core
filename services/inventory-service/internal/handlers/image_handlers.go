package handlers

// HTTP surface of image attachments (DCIM BUILD_PLAN row 2.8), under
// /api/v2/inventory-service/dcim:
//
//	GET    /objects/{kind}/{id}/images   dcim.read    the object's images, newest first
//	POST   /objects/{kind}/{id}/images   dcim.manage  multipart: file (≤ 5 MB png/jpeg/webp/svg), description?, slot?
//	GET    /images/{id}                  dcim.read    metadata
//	GET    /images/{id}/download         dcim.read    the bytes (proxied, never a storage URL)
//	DELETE /images/{id}                  dcim.manage
//
// slot=front|rear applies to a device type and sets its front_image_ref /
// rear_image_ref.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// ImageStore is what the handlers need; services.ImageService implements it.
type ImageStore interface {
	ListForObject(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, p services.IPAMListParams) ([]json.RawMessage, int, error)
	List(ctx context.Context, tenant uuid.UUID, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, id uuid.UUID) (json.RawMessage, error)
	Upload(ctx context.Context, tenant uuid.UUID, in services.ImageUpload) (json.RawMessage, error)
	Delete(ctx context.Context, tenant, id uuid.UUID) error
	Download(ctx context.Context, tenant, id uuid.UUID) (io.ReadCloser, string, string, error)
}

// ImageHandler serves the image routes.
type ImageHandler struct{ store ImageStore }

// NewImageHandler returns the handler over store.
func NewImageHandler(store ImageStore) *ImageHandler { return &ImageHandler{store: store} }

func imageError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrImageTooLarge):
		ipamError(c, http.StatusRequestEntityTooLarge, "image_too_large", err.Error())
	case errors.Is(err, services.ErrImageUnsupported):
		ipamError(c, http.StatusUnsupportedMediaType, "unsupported_image", err.Error())
	case errors.Is(err, services.ErrImageInvalid):
		ipamError(c, http.StatusBadRequest, "invalid_image", err.Error())
	default:
		ipamStoreError(c, err)
	}
}

// ListForObject is GET /objects/{kind}/{id}/images.
func (h *ImageHandler) ListForObject(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	kind, id, ok := objectRef(c)
	if !ok {
		return
	}
	p, ok := listParams(c)
	if !ok {
		return
	}
	delete(p.Filters, "object_kind")
	delete(p.Filters, "object_id")
	rows, total, err := h.store.ListForObject(c.Request.Context(), tenant, kind, id, p)
	if err != nil {
		imageError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
}

// List is GET /images (filters: object_kind, object_id, storage_ref).
func (h *ImageHandler) List(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	p, ok := listParams(c)
	if !ok {
		return
	}
	rows, total, err := h.store.List(c.Request.Context(), tenant, p)
	if err != nil {
		imageError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": ipamPagination(total, p.Limit, p.Offset)})
}

// Get is GET /images/{id}.
func (h *ImageHandler) Get(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	row, err := h.store.Get(c.Request.Context(), tenant, id)
	if err != nil {
		imageError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": row})
}

// Upload is POST /objects/{kind}/{id}/images.
func (h *ImageHandler) Upload(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	kind, id, ok := objectRef(c)
	if !ok {
		return
	}
	// Refuse before buffering: the multipart framing adds a little to the 5 MB.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, services.MaxImageBytes+(256<<10))
	fh, err := c.FormFile("file")
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			imageError(c, services.ErrImageTooLarge)
			return
		}
		ipamError(c, http.StatusBadRequest, "invalid_request", "A multipart form with a \"file\" field is required.")
		return
	}
	if fh.Size > services.MaxImageBytes {
		imageError(c, services.ErrImageTooLarge)
		return
	}
	f, err := fh.Open()
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "The file could not be read.")
		return
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, services.MaxImageBytes+1))
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "The file could not be read.")
		return
	}
	row, err := h.store.Upload(c.Request.Context(), tenant, services.ImageUpload{
		Kind: kind, ObjectID: id, Filename: fh.Filename,
		Description: c.PostForm("description"), Slot: strings.TrimSpace(c.PostForm("slot")), Data: data,
	})
	if err != nil {
		imageError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": row})
}

// Download is GET /images/{id}/download.
func (h *ImageHandler) Download(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	rc, ct, _, err := h.store.Download(c.Request.Context(), tenant, id)
	if err != nil {
		imageError(c, err)
		return
	}
	defer func() { _ = rc.Close() }()
	// An uploaded SVG is attacker-controlled markup: never let it run script
	// in the app's origin, and never let a browser re-sniff any of them.
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	c.Header("Cache-Control", "private, max-age=300")
	c.Header("Content-Disposition", "inline")
	c.DataFromReader(http.StatusOK, -1, ct, rc, nil)
}

// Delete is DELETE /images/{id}.
func (h *ImageHandler) Delete(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	if err := h.store.Delete(c.Request.Context(), tenant, id); err != nil {
		imageError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
