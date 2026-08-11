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
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/services"
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

// GetTierEntitlements handles GET /api/v1/admin-service/admin/tiers/:id/entitlements
//
// Returns the composition rows joined with the catalog metadata
// (kind / category / unit) the composer needs to render each cell.
// Items not yet composed for this tier are absent from the response —
// the client fills missing items in from the catalog with each item's
// default_value.
// tierEntitlementsProvider is the narrow surface of *services.EntitlementsService
// the tier-entitlements handlers use. The public handlers delegate to the
// *WithService variants passing the package-global, so the handlers are
// contract-testable over an in-memory stub (ADR-0001) with no global-type change.
type tierEntitlementsProvider interface {
	GetTierEntitlements(tierID uuid.UUID) ([]services.TierEntitlement, error)
	ReplaceTierEntitlements(tierID uuid.UUID, inputs []services.TierEntitlementInput) error
}

func GetTierEntitlements(c *gin.Context) {
	getTierEntitlementsWithService(c, entitlementsService)
}

func getTierEntitlementsWithService(c *gin.Context, svc tierEntitlementsProvider) {
	tierID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tier ID"})
		return
	}
	ents, err := svc.GetTierEntitlements(tierID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tier entitlements"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tier_id": tierID, "entitlements": ents})
}

// updateTierEntitlementsRequest is the bulk-replace body. Items not
// present here are deleted from the tier; new keys are inserted.
type updateTierEntitlementsRequest struct {
	Entitlements []services.TierEntitlementInput `json:"entitlements" binding:"required"`
}

// UpdateTierEntitlements handles PUT /api/v1/admin-service/admin/tiers/:id/entitlements
//
// Bulk replace: the request body is the complete desired composition.
// Atomic per the transaction in EntitlementsService.ReplaceTierEntitlements.
// Returns 400 on unknown item_key (an entire request fails rather than
// half-applying — better an obvious error than silent drift).
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

	if err := svc.ReplaceTierEntitlements(tierID, req.Entitlements); err != nil {
		// Surface the underlying message for unknown-key errors so the
		// admin UI can pinpoint the bad cell. Generic 500 for the rest
		// to avoid leaking SQL detail.
		var validationErr *services.UnknownItemKeyError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown or inactive billable_item key", "item_key": validationErr.Key})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tier entitlements"})
		return
	}

	// Echo back the new state so the client can pin its cached query
	// without a second round trip.
	updated, err := svc.GetTierEntitlements(tierID)
	if err != nil {
		// The write succeeded; report success even if the readback fails.
		c.JSON(http.StatusOK, gin.H{"tier_id": tierID})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tier_id": tierID, "entitlements": updated})
}
