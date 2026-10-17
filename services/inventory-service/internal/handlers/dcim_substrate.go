package handlers

// HTTP surface of the DCIM object substrate (DCIM BUILD_PLAN row 0.3):
//
//	GET    /dcim/changes                          dcim.read
//	GET    /dcim/changes/{id}                     dcim.read
//	GET    /dcim/objects/{kind}/{id}/journal      dcim.read
//	POST   /dcim/objects/{kind}/{id}/journal      dcim.manage
//	GET    /dcim/objects/{kind}/{id}/tags         dcim.read
//	PUT    /dcim/objects/{kind}/{id}/tags         dcim.manage
//	GET    /dcim/tags                             dcim.read
//	POST   /dcim/tags                             dcim.manage
//	PATCH  /dcim/tags/{id}                        dcim.manage
//	DELETE /dcim/tags/{id}                        dcim.manage
//
// The permission gates are mounted with the routes (cmd/dcim_substrate_routes.go);
// these handlers assume them. Responses use the ADR-0002 envelope: `data`,
// `pagination` on lists, and `{error: {code, message}}`.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/journal"
	"github.com/vistasecurity/vistaplatform/shared/dcim/tags"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// DcimSubstrateStore is what the handlers need; services.DcimSubstrateService
// implements it over Postgres, the contract tests stub it.
type DcimSubstrateStore interface {
	ListChanges(ctx context.Context, f changes.Filter) ([]changes.ObjectChange, int, error)
	GetChange(ctx context.Context, tenant, id uuid.UUID) (changes.ObjectChange, error)
	ListJournal(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, limit, offset int) ([]journal.Entry, int, error)
	AddJournal(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, entryKind journal.Kind, comments string) (journal.Entry, error)
	ObjectTags(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) ([]tags.Tag, error)
	SetObjectTags(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, tagIDs []uuid.UUID) ([]tags.Tag, error)
	ListTags(ctx context.Context, tenant uuid.UUID) ([]tags.Tag, error)
	CreateTag(ctx context.Context, tenant uuid.UUID, in tags.Input) (tags.Tag, error)
	UpdateTag(ctx context.Context, tenant, id uuid.UUID, p services.TagPatch) (tags.Tag, error)
	DeleteTag(ctx context.Context, tenant, id uuid.UUID) error
}

// DcimSubstrateHandler serves the substrate routes.
type DcimSubstrateHandler struct {
	store DcimSubstrateStore
}

// NewDcimSubstrateHandler returns the handler over store.
func NewDcimSubstrateHandler(store DcimSubstrateStore) *DcimSubstrateHandler {
	return &DcimSubstrateHandler{store: store}
}

const (
	dcimDefaultLimit = 50
	dcimMaxLimit     = 200
)

func dcimError(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": msg}})
}

func dcimTenant(c *gin.Context) (uuid.UUID, bool) {
	tenant, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		dcimError(c, http.StatusUnauthorized, "unauthenticated", "tenant context required")
	}
	return tenant, ok
}

// dcimStoreError maps the writers' errors onto statuses. Anything unknown is a
// 500 with a generic message; the detail goes to the log, not the client.
func dcimStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrDcimObjectNotFound):
		dcimError(c, http.StatusNotFound, "object_not_found", "No such object for this organisation.")
	case errors.Is(err, tags.ErrNotFound):
		dcimError(c, http.StatusNotFound, "tag_not_found", "No such tag.")
	case errors.Is(err, tags.ErrDuplicate):
		dcimError(c, http.StatusConflict, "tag_exists", err.Error())
	case errors.Is(err, tags.ErrInvalid), errors.Is(err, tags.ErrNotApplicable), errors.Is(err, journal.ErrInvalid):
		dcimError(c, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, changes.ErrNoActor):
		dcimError(c, http.StatusUnauthorized, "unauthenticated", "A change must be attributed to a signed-in user.")
	default:
		_ = c.Error(err)
		dcimError(c, http.StatusInternalServerError, "internal_error", "The request could not be completed.")
	}
}

func dcimPagination(total, limit, offset int) gin.H {
	var next any
	if offset+limit < total {
		next = offset + limit
	}
	return gin.H{"total": total, "limit": limit, "offset": offset, "next_offset": next}
}

// dcimObjectRef parses {kind}/{id}; it answers 400 itself on a bad one.
func dcimObjectRef(c *gin.Context) (dcim.ObjectKind, uuid.UUID, bool) {
	kind, ok := dcim.ParseObjectKind(c.Param("kind"))
	if !ok {
		dcimError(c, http.StatusBadRequest, "invalid_object_kind", "Unknown object kind.")
		return "", uuid.Nil, false
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_object_id", "Object id must be a UUID.")
		return "", uuid.Nil, false
	}
	return kind, id, true
}

// ListChanges is GET /dcim/changes.
func (h *DcimSubstrateHandler) ListChanges(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	limit, offset, err := sharedapi.ParseLimitOffsetStrict(c, dcimDefaultLimit, dcimMaxLimit)
	if err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	f := changes.Filter{TenantID: tenant, Limit: limit, Offset: offset}
	if v := c.Query("object_kind"); v != "" {
		k, ok := dcim.ParseObjectKind(v)
		if !ok {
			dcimError(c, http.StatusBadRequest, "invalid_object_kind", "Unknown object kind.")
			return
		}
		f.ObjectKind = k
	}
	for name, dst := range map[string]*uuid.UUID{"object_id": &f.ObjectID, "user": &f.UserID} {
		if v := c.Query(name); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				dcimError(c, http.StatusBadRequest, "invalid_"+name, name+" must be a UUID.")
				return
			}
			*dst = id
		}
	}
	if v := c.Query("since"); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			dcimError(c, http.StatusBadRequest, "invalid_since", "since must be an RFC 3339 timestamp.")
			return
		}
		f.Since = ts
	}
	if v := c.Query("until"); v != "" {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			dcimError(c, http.StatusBadRequest, "invalid_until", "until must be an RFC 3339 timestamp.")
			return
		}
		f.Until = ts
	}
	if v := c.Query("action"); v != "" {
		if f.Action = changes.Action(v); !f.Action.Valid() {
			dcimError(c, http.StatusBadRequest, "invalid_action", "action must be create, update or delete.")
			return
		}
	}
	if v := c.Query("source"); v != "" {
		// A family ("intake:", "sync:") or one full source.
		if f.Source = changes.Source(v); !f.Source.Valid() && v != "intake:" && v != "sync:" {
			dcimError(c, http.StatusBadRequest, "invalid_source", "source must be ui, api, system, intake:, sync:, or one full source.")
			return
		}
	}
	f.Query = c.Query("q")
	f.UserQuery = c.Query("user_name")
	if c.Query("include_related") == "true" {
		if f.ObjectKind == "" || f.ObjectID == uuid.Nil {
			dcimError(c, http.StatusBadRequest, "invalid_include_related", "include_related needs object_kind and object_id.")
			return
		}
		f.IncludeRelated = true
	}
	rows, total, err := h.store.ListChanges(c.Request.Context(), f)
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": dcimPagination(total, limit, offset)})
}

// changeDetail is a change with its computed field-level diff.
type changeDetail struct {
	changes.ObjectChange
	Diff []changes.FieldDiff `json:"diff"`
}

// GetChange is GET /dcim/changes/{id}: the change, both images (secrets were
// redacted when it was recorded) and the field-level diff.
func (h *DcimSubstrateHandler) GetChange(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_id", "Change id must be a UUID.")
		return
	}
	oc, err := h.store.GetChange(c.Request.Context(), tenant, id)
	if errors.Is(err, changes.ErrNotFound) {
		dcimError(c, http.StatusNotFound, "not_found", "No such change.")
		return
	}
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": changeDetail{ObjectChange: oc, Diff: changes.FieldDiffs(oc)}})
}

// ListJournal is GET /dcim/objects/{kind}/{id}/journal.
func (h *DcimSubstrateHandler) ListJournal(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	kind, id, ok := dcimObjectRef(c)
	if !ok {
		return
	}
	limit, offset, err := sharedapi.ParseLimitOffsetStrict(c, dcimDefaultLimit, dcimMaxLimit)
	if err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	rows, total, err := h.store.ListJournal(c.Request.Context(), tenant, kind, id, limit, offset)
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "pagination": dcimPagination(total, limit, offset)})
}

type journalInput struct {
	Kind     journal.Kind `json:"kind"`
	Comments string       `json:"comments"`
}

// AddJournal is POST /dcim/objects/{kind}/{id}/journal.
func (h *DcimSubstrateHandler) AddJournal(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	kind, id, ok := dcimObjectRef(c)
	if !ok {
		return
	}
	var in journalInput
	if err := dcimStrictJSON(c, &in); err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	e, err := h.store.AddJournal(c.Request.Context(), tenant, kind, id, in.Kind, in.Comments)
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": e})
}

// GetObjectTags is GET /dcim/objects/{kind}/{id}/tags.
func (h *DcimSubstrateHandler) GetObjectTags(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	kind, id, ok := dcimObjectRef(c)
	if !ok {
		return
	}
	out, err := h.store.ObjectTags(c.Request.Context(), tenant, kind, id)
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

type objectTagsInput struct {
	TagIDs []uuid.UUID `json:"tag_ids"`
}

// SetObjectTags is PUT /dcim/objects/{kind}/{id}/tags.
func (h *DcimSubstrateHandler) SetObjectTags(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	kind, id, ok := dcimObjectRef(c)
	if !ok {
		return
	}
	var in objectTagsInput
	if err := dcimStrictJSON(c, &in); err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if in.TagIDs == nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", "tag_ids is required (an empty list clears the tags).")
		return
	}
	out, err := h.store.SetObjectTags(c.Request.Context(), tenant, kind, id, in.TagIDs)
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// ListTags is GET /dcim/tags.
func (h *DcimSubstrateHandler) ListTags(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	out, err := h.store.ListTags(c.Request.Context(), tenant)
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

type tagInput struct {
	Name        *string            `json:"name"`
	Slug        *string            `json:"slug"`
	Color       *string            `json:"color"`
	Description *string            `json:"description"`
	ObjectKinds *[]dcim.ObjectKind `json:"object_kinds"`
}

// CreateTag is POST /dcim/tags.
func (h *DcimSubstrateHandler) CreateTag(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	var in tagInput
	if err := dcimStrictJSON(c, &in); err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if in.Name == nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", "name is required.")
		return
	}
	ti := tags.Input{Name: *in.Name, Color: in.Color, Description: in.Description}
	if in.Slug != nil {
		ti.Slug = *in.Slug
	}
	if in.ObjectKinds != nil {
		ti.ObjectKinds = *in.ObjectKinds
	}
	t, err := h.store.CreateTag(c.Request.Context(), tenant, ti)
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": t})
}

func dcimTagID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_tag_id", "Tag id must be a UUID.")
		return uuid.Nil, false
	}
	return id, true
}

// UpdateTag is PATCH /dcim/tags/{id}.
func (h *DcimSubstrateHandler) UpdateTag(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	id, ok := dcimTagID(c)
	if !ok {
		return
	}
	var in tagInput
	if err := dcimStrictJSON(c, &in); err != nil {
		dcimError(c, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	t, err := h.store.UpdateTag(c.Request.Context(), tenant, id, services.TagPatch{
		Name: in.Name, Slug: in.Slug, Color: in.Color, Description: in.Description, ObjectKinds: in.ObjectKinds,
	})
	if err != nil {
		dcimStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": t})
}

// DeleteTag is DELETE /dcim/tags/{id}.
func (h *DcimSubstrateHandler) DeleteTag(c *gin.Context) {
	tenant, ok := dcimTenant(c)
	if !ok {
		return
	}
	id, ok := dcimTagID(c)
	if !ok {
		return
	}
	if err := h.store.DeleteTag(c.Request.Context(), tenant, id); err != nil {
		dcimStoreError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// dcimStrictJSON decodes the body refusing unknown fields, so a misspelt field is
// a 400 rather than a silent no-op.
func dcimStrictJSON(c *gin.Context, dst any) error {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("malformed JSON body: " + strings.TrimPrefix(err.Error(), "json: "))
	}
	return nil
}
