package handlers

// Core half of entitlements: the billable-item CATALOG and the per-TIER
// composition.
//
// Both are Core because they are what makes shared/entitlements resolve to
// something real: the catalog defines what the levers are, the tier composition
// says what a plan grants, and tier_management.go can ASSIGN a tenant to a tier.
// A single-organization deployment therefore has fully working, fully enforced
// entitlements with no Enterprise code in the binary.
//
// The per-TENANT override handlers moved to ee/msp/tenant_entitlements.go —
// "this customer, unlike others on their plan, gets X" is a management-plane
// concept, and those routes live under /admin/tenants/**, which Core does not
// ship. Nothing about ENFORCEMENT moved: shared/entitlements and
// shared/services/limit_enforcement.go are untouched.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// entitlementsService is the package-level singleton initialized at
// server start (matches the tier-service / override-service pattern).
var entitlementsService *services.EntitlementsService

// InitializeEntitlementsService wires the catalog/composition service
// to the request handlers. Called once from server bootstrap.
// bypassDB is the cross-tenant (BYPASSRLS) handle for the platform-wide
// ref-count/lookup paths.
func InitializeEntitlementsService(db, bypassDB *sql.DB) {
	entitlementsService = services.NewEntitlementsService(db, bypassDB)
}

// billableItemStore is the dependency of the billable-item catalog handlers
// (admin-ui Entitlements catalog). *services.EntitlementsService satisfies it;
// the interface lets the handlers be contract-tested with an in-memory stub and
// no DB. (The tier-entitlement handlers below still use the package global and
// are out of scope for this slice.)
type billableItemStore interface {
	ListBillableItems() ([]services.BillableItem, error)
	CreateBillableItem(in services.BillableItemInput) (*services.BillableItem, error)
	UpdateBillableItem(id uuid.UUID, in services.BillableItemInput) (*services.BillableItem, error)
	DeleteBillableItem(id uuid.UUID) error
}

// ListBillableItems handles GET /api/v1/admin-service/admin/billable-items
//
// Returns every catalog row, ordered by sort_order then key. Includes
// inactive items so the catalog-management page can surface them; the
// tier composer client-side filters to is_active=true.
func ListBillableItems(store billableItemStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		items, err := store.ListBillableItems()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list billable items"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}

// CreateBillableItem handles POST /api/v1/admin-service/admin/billable-items
//
// Adds a new gateable concept to the catalog. The key field is the
// stable code identifier that Go and TS will reference; once set, it
// is not editable via the update endpoint. Duplicate keys return 409.
func CreateBillableItem(store billableItemStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in services.BillableItemInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if in.Key == "" || in.DisplayName == "" || in.Category == "" || in.Kind == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "key, display_name, category, and kind are required"})
			return
		}
		item, err := store.CreateBillableItem(in)
		if err != nil {
			var dup *services.DuplicateKeyError
			if errors.As(err, &dup) {
				c.JSON(http.StatusConflict, gin.H{"error": "billable_item key already exists", "key": dup.Key})
				return
			}
			if respondInvalidValue(c, err) {
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create billable item"})
			return
		}
		c.JSON(http.StatusCreated, item)
	}
}

// UpdateBillableItem handles PUT /api/v1/admin-service/admin/billable-items/:id
//
// Rewrites every non-key field. Key is intentionally not editable —
// the route ignores any "key" field in the body.
func UpdateBillableItem(store billableItemStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
			return
		}
		var in services.BillableItemInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if in.DisplayName == "" || in.Category == "" || in.Kind == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "display_name, category, and kind are required"})
			return
		}
		item, err := store.UpdateBillableItem(id, in)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Billable item not found"})
			return
		}
		if respondInvalidValue(c, err) {
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update billable item"})
			return
		}
		c.JSON(http.StatusOK, item)
	}
}

// DeleteBillableItem handles DELETE /api/v1/admin-service/admin/billable-items/:id
//
// Hard delete; refuses (409) when any tier or tenant references the
// item. Admins should prefer toggling is_active to false via the
// update endpoint when the item is in use — that preserves the FK
// graph while hiding the item from the composer.
func DeleteBillableItem(store billableItemStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
			return
		}
		err = store.DeleteBillableItem(id)
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Billable item not found"})
			return
		}
		var inUse *services.ItemInUseError
		if errors.As(err, &inUse) {
			c.JSON(http.StatusConflict, gin.H{
				"error":       inUse.Error(),
				"tier_refs":   inUse.TierRefs,
				"tenant_refs": inUse.TenantRefs,
			})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete billable item"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// tierEntitlementsProvider is the narrow surface of *services.EntitlementsService
// the tier-entitlements handlers use. The public handlers delegate to the
// *WithService variants passing the package-global, so the handlers are
// contract-testable over an in-memory stub (ADR-0001) with no global-type change.
type tierEntitlementsProvider interface {
	GetTierComposition(tierID uuid.UUID) (services.TierComposition, error)
	UpsertTierEntitlement(tierID uuid.UUID, in services.TierEntitlementInput, changedBy uuid.UUID) (*services.CompositionWriteResult, error)
	UpdateTierComposition(tierID uuid.UUID, u services.CompositionUpdate, changedBy uuid.UUID) (*services.CompositionWriteResult, error)
}

// tierEntitlementsResponse is the envelope every tier-entitlements route
// answers with: the rows plus the version a multi-item write must send back.
func tierEntitlementsResponse(tierID uuid.UUID, comp services.TierComposition) gin.H {
	return gin.H{"tier_id": tierID, "entitlements": comp.Entitlements, "version": comp.Version}
}

// GetTierEntitlements handles GET /api/v1/admin-service/admin/tiers/:id/entitlements
//
// Returns the composition rows joined with the catalog metadata
// (kind / category / unit) the composer needs to render each cell, and the
// composition's `version`. Items not yet composed for this tier are absent
// from the response — the client fills missing items in from the catalog with
// each item's default_value.
func GetTierEntitlements(c *gin.Context) {
	getTierEntitlementsWithService(c, entitlementsService)
}

func getTierEntitlementsWithService(c *gin.Context, svc tierEntitlementsProvider) {
	tierID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
		return
	}
	comp, err := svc.GetTierComposition(tierID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tier entitlements"})
		return
	}
	c.JSON(http.StatusOK, tierEntitlementsResponse(tierID, comp))
}

// upsertTierEntitlementRequest is the single-item body. The item is the :key
// path parameter.
type upsertTierEntitlementRequest struct {
	IncludedValue     json.RawMessage `json:"included_value"`
	OveragePriceCents *int            `json:"overage_price_cents,omitempty"`
	OverageUnitSize   *int            `json:"overage_unit_size,omitempty"`
	ClearOveragePrice bool            `json:"clear_overage_price_cents,omitempty"`
	ClearOverageSize  bool            `json:"clear_overage_unit_size,omitempty"`
}

// UpsertTierEntitlement handles PUT /api/v1/admin-service/admin/tiers/:id/entitlements/:key
//
// Sets ONE item on the tier — the Plans & Pricing matrix's cell edit. It can
// neither remove nor alter any other item, so it needs no version: whatever
// the client has (or has not yet) loaded, the rest of the composition is safe.
func UpsertTierEntitlement(c *gin.Context) {
	upsertTierEntitlementWithService(c, entitlementsService)
}

func upsertTierEntitlementWithService(c *gin.Context, svc tierEntitlementsProvider) {
	tierID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
		return
	}
	var req upsertTierEntitlementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	key := c.Param("key")
	res, err := svc.UpsertTierEntitlement(tierID, services.TierEntitlementInput{
		ItemKey:           key,
		IncludedValue:     req.IncludedValue,
		OveragePriceCents: req.OveragePriceCents,
		OverageUnitSize:   req.OverageUnitSize,
		ClearOveragePrice: req.ClearOveragePrice,
		ClearOverageSize:  req.ClearOverageSize,
	}, platformActor(c))
	if err != nil {
		if respondCompositionError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tier entitlement"})
		return
	}
	auditCompositionChange(c, "subscription_tier.entitlement_set", tierID, res.Changes)
	c.JSON(http.StatusOK, tierEntitlementsResponse(tierID, res.Composition))
}

// updateTierEntitlementsRequest is the multi-item body. Items it does not name
// are left as they are; only `remove` deletes.
type updateTierEntitlementsRequest struct {
	Entitlements []services.TierEntitlementInput `json:"entitlements"`
	Remove       []string                        `json:"remove"`
	Version      string                          `json:"version"`
}

// UpdateTierEntitlements handles PUT /api/v1/admin-service/admin/tiers/:id/entitlements
//
// Multi-item write: upserts `entitlements`, deletes `remove`, nothing else —
// this used to be a delete-everything-then-insert "replace", and a request
// built from an empty client cache erased the tier's composition. `version`
// (from GET) is required: missing → 428, stale → 409 with current_version.
// Atomic; every key and value is validated before anything is written.
func UpdateTierEntitlements(c *gin.Context) {
	updateTierEntitlementsWithService(c, entitlementsService)
}

func updateTierEntitlementsWithService(c *gin.Context, svc tierEntitlementsProvider) {
	tierID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
		return
	}
	var req updateTierEntitlementsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	res, err := svc.UpdateTierComposition(tierID, services.CompositionUpdate{
		Set: req.Entitlements, Remove: req.Remove, Version: req.Version,
	}, platformActor(c))
	if err != nil {
		if respondCompositionError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tier entitlements"})
		return
	}
	auditCompositionChange(c, "subscription_tier.entitlements_updated", tierID, res.Changes)
	c.JSON(http.StatusOK, tierEntitlementsResponse(tierID, res.Composition))
}

// respondCompositionError writes the response for the typed errors a
// composition write can return and reports whether it did. Validation errors
// echo the offending key or shape (they describe the request, never the
// database); anything else is left to the caller's generic 500.
func respondCompositionError(c *gin.Context, err error) bool {
	if errors.Is(err, services.ErrTierNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tier not found"})
		return true
	}
	if errors.Is(err, services.ErrCompositionVersionRequired) {
		c.JSON(http.StatusPreconditionRequired, gin.H{
			"error":  "entitlements version required",
			"detail": "Read the tier's entitlements first and send their version with the change.",
		})
		return true
	}
	var stale *services.StaleCompositionError
	if errors.As(err, &stale) {
		c.JSON(http.StatusConflict, gin.H{
			"error":           "tier entitlements changed since they were read",
			"detail":          "Someone else changed this plan's entitlements after you opened it. Reload to see the current values, then save again.",
			"current_version": stale.Current,
		})
		return true
	}
	var unknown *services.UnknownItemKeyError
	if errors.As(err, &unknown) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown or inactive billable_item key", "item_key": unknown.Key, "detail": unknown.Error()})
		return true
	}
	var dup *services.DuplicateItemKeyError
	if errors.As(err, &dup) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "billable_item key appears more than once", "item_key": dup.Key, "detail": dup.Error()})
		return true
	}
	var overageConflict *services.OverageConflictError
	if errors.As(err, &overageConflict) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "conflicting overage fields", "item_key": overageConflict.Key, "detail": overageConflict.Error()})
		return true
	}
	return respondInvalidValue(c, err)
}

// auditCompositionChange records a composition write that changed something.
// The metadata is the before/after diff — entitlement shapes, never secrets.
func auditCompositionChange(c *gin.Context, eventType string, tierID uuid.UUID, changes []services.EntitlementChange) {
	if len(changes) == 0 {
		return
	}
	recordPlatformAudit(c, PlatformAuditEntry{
		EventType:     eventType,
		Action:        "update",
		EventCategory: "config",
		ResourceType:  "subscription_tier",
		ResourceID:    tierID.String(),
		ChangedFields: compositionChangedFields(changes),
		Metadata:      map[string]interface{}{"entitlement_changes": changes},
	})
}

// compositionChangedFields names each changed item as "entitlements.<key>".
func compositionChangedFields(changes []services.EntitlementChange) []string {
	keys := services.ChangedKeys(changes)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, "entitlements."+k)
	}
	return out
}

// platformActor is the authenticated platform user, or uuid.Nil when the
// request carries none (an internal call). The auth middleware stores it under
// sharedmw.CtxKeyUserID ("userID").
func platformActor(c *gin.Context) uuid.UUID {
	id, _ := sharedmw.GetUserIDFromContext(c)
	return id
}

// respondInvalidValue writes the 400 for an entitlements.InvalidValueError and
// reports whether it did. The reason is echoed verbatim: it describes the
// request's shape ("missing \"quantity\" (expected {\"quantity\": N} ...)"),
// never the database, and the whole point of the check is that an operator
// can fix the cell from the message.
func respondInvalidValue(c *gin.Context, err error) bool {
	var ive *entitlements.InvalidValueError
	if !errors.As(err, &ive) {
		return false
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid entitlement value", "kind": string(ive.Kind), "detail": err.Error()})
	return true
}
