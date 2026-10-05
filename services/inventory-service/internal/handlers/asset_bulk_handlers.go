package handlers

// Bulk actions over a selection of assets: Inventory → All assets and
// Stale, rows ticked or every asset matching the query.
//
//   POST /infrastructure-assets/bulk-actions/archive   assets.update
//   POST /infrastructure-assets/bulk-actions/restore   assets.update
//   POST /infrastructure-assets/bulk-actions/delete    assets.delete
//   POST /infrastructure-assets/bulk-actions/update    assets.update
//
// The bulk Active Scan is POST /infrastructure-assets/scan with the same
// selection (asset_lifecycle_handlers.go), because a scan is the same action
// whether one asset or a thousand is selected.
//
// The permission is checked on the route (cmd/asset_bulk_routes.go); these
// handlers assume it.

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// bulkAssetStore and bulkLifecycleStore are the slices of AssetService and
// AssetLifecycleService the bulk handlers use, as interfaces so the contract
// test can drive the real handlers without a database.
type bulkAssetStore interface {
	ResolveAssetSelection(tenantID uuid.UUID, sel services.AssetSelection, limit int) ([]uuid.UUID, error)
	DeleteAssets(tenantID uuid.UUID, assetIDs []uuid.UUID) (int, error)
	BulkUpdateAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, changes services.BulkAssetChanges, actor uuid.UUID) (int, error)
}

type bulkLifecycleStore interface {
	ArchiveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, actor uuid.UUID) (int, error)
	UnarchiveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, actor uuid.UUID) (int, error)
}

// AssetBulkHandler serves the bulk-actions routes.
type AssetBulkHandler struct {
	assets    bulkAssetStore
	lifecycle bulkLifecycleStore
}

// NewAssetBulkHandler wires the bulk handlers to the concrete services.
func NewAssetBulkHandler(assets *services.AssetService, lifecycle *services.AssetLifecycleService) *AssetBulkHandler {
	return &AssetBulkHandler{assets: assets, lifecycle: lifecycle}
}

// selectionBody is the selection half of every bulk request body: rows a
// person ticked, or a query and the count they confirmed for it.
type selectionBody struct {
	AssetIDs      []string `json:"asset_ids"`
	Query         *string  `json:"query"`
	ExpectedCount *int     `json:"expected_count"`
}

func (b selectionBody) selection() services.AssetSelection {
	return services.AssetSelection{AssetIDs: b.AssetIDs, Query: b.Query, ExpectedCount: b.ExpectedCount}
}

// writeSelectionError answers a selection that could not be resolved, and
// reports whether it did. Each refusal says what the person can do about it.
func writeSelectionError(c *gin.Context, err error) bool {
	var tooLarge *services.SelectionTooLargeError
	var changed *services.SelectionChangedError
	switch {
	case writeQueryError(c, err):
	case errors.Is(err, services.ErrSelectionInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_selection", "details": err.Error()})
	case errors.As(err, &tooLarge):
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "selection_too_large", "details": err.Error(), "limit": tooLarge.Limit})
	case errors.As(err, &changed):
		// The query matches more assets than the person agreed to. Nothing
		// was changed; they are told the new count and asked again.
		c.JSON(http.StatusConflict, gin.H{"error": "selection_changed", "details": err.Error(), "expected_count": changed.Expected, "count": changed.Count})
	default:
		return false
	}
	return true
}

func tenantFrom(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get("tenantID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return id, true
}

// bulkAction is one lifecycle-shaped bulk write: resolve, act, report.
type bulkAction func(tenant uuid.UUID, ids []uuid.UUID, actor uuid.UUID) (int, error)

func (h *AssetBulkHandler) run(c *gin.Context, name string, body selectionBody, act bulkAction, auditExtra map[string]interface{}) {
	tenant, ok := tenantFrom(c)
	if !ok {
		return
	}
	ids, err := h.assets.ResolveAssetSelection(tenant, body.selection(), services.MaxBulkAssets)
	if errors.Is(err, services.ErrSelectionEmpty) {
		// A query that matches nothing any more is not an error: nothing was
		// asked of nothing. The counts say so.
		c.JSON(http.StatusOK, gin.H{"action": name, "matched": 0, "changed": 0, "unchanged": 0})
		return
	}
	if err != nil {
		if writeSelectionError(c, err) {
			return
		}
		log.Printf("[ERROR] bulk %s - tenant %s: resolve selection: %v", name, tenant, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve the selection"})
		return
	}
	changed, err := act(tenant, ids, lifecycleActor(c))
	if err != nil {
		if errors.Is(err, services.ErrBulkChangesInvalid) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_changes", "details": err.Error()})
			return
		}
		// Chunks commit independently, so a failure part-way leaves the
		// earlier chunks changed. Say how many, rather than "failed".
		log.Printf("[ERROR] bulk %s - tenant %s: %d of %d changed before: %v", name, tenant, changed, len(ids), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to " + name + " every selected asset", "matched": len(ids), "changed": changed})
		return
	}
	auditBulk(c, name, body, ids, changed, auditExtra)
	c.JSON(http.StatusOK, gin.H{"action": name, "matched": len(ids), "changed": changed, "unchanged": len(ids) - changed})
}

// auditBulk records one audit entry per bulk request: who, what, which
// selection, and how many. A query selection names its query, so the record
// says how the set was chosen and not only which ids it came to.
func auditBulk(c *gin.Context, name string, body selectionBody, ids []uuid.UUID, changed int, extra map[string]interface{}) {
	const listed = 500
	meta := map[string]interface{}{"matched": len(ids), "changed": changed}
	if body.Query != nil {
		meta["selection"] = "query"
		meta["query"] = *body.Query
	} else {
		meta["selection"] = "asset_ids"
	}
	shown := ids
	if len(shown) > listed {
		shown = shown[:listed]
		meta["asset_ids_truncated"] = true
	}
	strs := make([]string, len(shown))
	for i, id := range shown {
		strs[i] = id.String()
	}
	meta["asset_ids"] = strs
	for k, v := range extra {
		meta[k] = v
	}
	resourceType := "asset"
	logAuditActivity(c, "asset.bulk_"+name, auditmiddleware.EventCategoryAsset, name, &resourceType, nil, nil, nil, nil, meta)
}

// BulkArchive handles POST /infrastructure-assets/bulk-actions/archive.
func (h *AssetBulkHandler) BulkArchive(c *gin.Context) {
	var body selectionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	h.run(c, "archive", body, h.lifecycle.ArchiveAssets, nil)
}

// BulkRestore handles POST /infrastructure-assets/bulk-actions/restore: the
// selected archived assets return to active inventory.
func (h *AssetBulkHandler) BulkRestore(c *gin.Context) {
	var body selectionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	h.run(c, "restore", body, h.lifecycle.UnarchiveAssets, nil)
}

// BulkDelete handles POST /infrastructure-assets/bulk-actions/delete: a soft
// delete, as DELETE /infrastructure-assets/{id} is.
func (h *AssetBulkHandler) BulkDelete(c *gin.Context) {
	var body selectionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	h.run(c, "delete", body, func(t uuid.UUID, ids []uuid.UUID, _ uuid.UUID) (int, error) {
		return h.assets.DeleteAssets(t, ids)
	}, nil)
}

// bulkChangesBody is the field edit. A field that is absent is left alone; a
// field sent as "" is cleared.
type bulkChangesBody struct {
	OwnerEmail   *string           `json:"owner_email"`
	Environment  *string           `json:"environment"`
	BusinessUnit *string           `json:"business_unit"`
	SupportGroup *string           `json:"support_group"`
	AddTags      map[string]string `json:"add_tags"`
	RemoveTags   []string          `json:"remove_tags"`
}

// BulkUpdate handles POST /infrastructure-assets/bulk-actions/update.
func (h *AssetBulkHandler) BulkUpdate(c *gin.Context) {
	var body struct {
		selectionBody
		Changes *bulkChangesBody `json:"changes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Changes == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": "changes is required"})
		return
	}
	ch := services.BulkAssetChanges{
		OwnerEmail: body.Changes.OwnerEmail, Environment: body.Changes.Environment,
		BusinessUnit: body.Changes.BusinessUnit, SupportGroup: body.Changes.SupportGroup,
		AddTags: body.Changes.AddTags, RemoveTags: body.Changes.RemoveTags,
	}
	// Refused before the selection is resolved: an edit that changes nothing
	// should not first read five thousand ids.
	if err := ch.Normalize(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_changes", "details": err.Error()})
		return
	}
	h.run(c, "update", body.selectionBody, func(t uuid.UUID, ids []uuid.UUID, actor uuid.UUID) (int, error) {
		return h.assets.BulkUpdateAssets(t, ids, ch, actor)
	}, map[string]interface{}{"changes": body.Changes})
}
