package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/api"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// planStore is the slice of *services.RemediationPlanService the plan handlers
// depend on. Declaring it as an interface (the concrete service still satisfies
// it) lets the contract test drive the real handlers with an in-memory stub —
// no database — per the spec-first contract recipe (ADR-0001). Union of every
// planService method the handlers call.
type planStore interface {
	List(tenantID uuid.UUID, filters models.PlanFilters) ([]models.RemediationPlan, int, error)
	GetByID(tenantID, planID uuid.UUID) (*models.RemediationPlan, error)
	Create(tenantID, createdBy uuid.UUID, input models.CreatePlanInput) (*models.RemediationPlan, error)
	Update(tenantID, planID uuid.UUID, input models.UpdatePlanInput) (*models.RemediationPlan, error)
	Delete(tenantID, planID uuid.UUID) error
	ListItems(tenantID, planID uuid.UUID) ([]models.RemediationPlanItem, error)
	AddItem(tenantID, planID, addedBy uuid.UUID, input models.AddPlanItemInput) (*models.RemediationPlanItem, error)
	AddItemsBulk(tenantID, planID, addedBy uuid.UUID, input models.AddPlanItemsBulkInput) (int, error)
	RemoveItem(tenantID, planID, itemID uuid.UUID) error
	LinkTicket(tenantID, planID, itemID uuid.UUID, input models.LinkTicketInput) error
	ListForTicketIDs(tenantID uuid.UUID, ticketIDs []uuid.UUID) (map[uuid.UUID][]models.PlanRef, error)
	GetProgress(tenantID, planID uuid.UUID) (*models.PlanProgress, error)
}

// RemediationPlanHandlers contains remediation plan management handlers
type RemediationPlanHandlers struct {
	planService planStore
}

// NewRemediationPlanHandlers creates a new instance of remediation plan handlers
func NewRemediationPlanHandlers(planService *services.RemediationPlanService) *RemediationPlanHandlers {
	return &RemediationPlanHandlers{planService: planService}
}

// ListPlans returns filtered, paginated remediation plans for the tenant
func (h *RemediationPlanHandlers) ListPlans(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	filters := models.PlanFilters{
		Status:   c.Query("status"),
		PlanType: c.Query("plan_type"),
		Priority: c.Query("priority"),
		OwnerID:  c.Query("owner_id"),
		Search:   c.Query("search"),
	}

	if p, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil {
		filters.Page = p
	}
	if ps, err := strconv.Atoi(c.DefaultQuery("page_size", "20")); err == nil {
		filters.PageSize = ps
	}

	plans, total, err := h.planService.List(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list plans"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"plans":     plans,
		"total":     total,
		"page":      filters.Page,
		"page_size": filters.PageSize,
	})
}

// CreatePlan creates a new remediation plan
func (h *RemediationPlanHandlers) CreatePlan(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	userUUID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	var input models.CreatePlanInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if input.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title is required"})
		return
	}

	plan, err := h.planService.Create(tenantUUID, userUUID, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create plan"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Plan created successfully",
		"plan":    plan,
	})
}

// GetPlan returns a single remediation plan by ID
func (h *RemediationPlanHandlers) GetPlan(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	plan, err := h.planService.GetByID(tenantUUID, planID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get plan"})
		return
	}
	if plan == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Plan not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plan": plan})
}

// UpdatePlan updates a remediation plan
func (h *RemediationPlanHandlers) UpdatePlan(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	var input models.UpdatePlanInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	plan, err := h.planService.Update(tenantUUID, planID, input)
	if err != nil {
		if err.Error() == "plan not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Plan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update plan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Plan updated successfully",
		"plan":    plan,
	})
}

// DeletePlan deletes a remediation plan (only draft or cancelled)
func (h *RemediationPlanHandlers) DeletePlan(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	if err := h.planService.Delete(tenantUUID, planID); err != nil {
		if err.Error() == "plan not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Plan not found"})
			return
		}
		if err.Error() == "only draft or cancelled plans can be deleted" {
			api.BadRequest(c, "only draft or cancelled plans can be deleted")
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete plan"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Plan deleted successfully"})
}

// ListPlanItems returns items for a plan with joined finding/ticket data
func (h *RemediationPlanHandlers) ListPlanItems(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	items, err := h.planService.ListItems(tenantUUID, planID)
	if err != nil {
		if err.Error() == "plan not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Plan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list plan items"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}

// AddPlanItem adds a finding to a plan
func (h *RemediationPlanHandlers) AddPlanItem(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	userUUID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	var input models.AddPlanItemInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if input.FindingID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "finding_id is required"})
		return
	}

	item, err := h.planService.AddItem(tenantUUID, planID, userUUID, input)
	if err != nil {
		if err.Error() == "plan not found" || err.Error() == "finding not found" {
			api.ErrorResponse(c, http.StatusNotFound, err.Error(), nil)
			return
		}
		if err.Error() == "finding already in plan" {
			api.ErrorResponse(c, http.StatusConflict, "finding already in plan", nil)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add item to plan"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Item added to plan",
		"item":    item,
	})
}

// AddPlanItemsBulk adds multiple findings to a plan
func (h *RemediationPlanHandlers) AddPlanItemsBulk(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	userUUID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	var input models.AddPlanItemsBulkInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if len(input.FindingIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "finding_ids is required"})
		return
	}

	added, err := h.planService.AddItemsBulk(tenantUUID, planID, userUUID, input)
	if err != nil {
		if err.Error() == "plan not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Plan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add items to plan"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Items added to plan",
		"added":   added,
	})
}

// RemovePlanItem removes a finding from a plan
func (h *RemediationPlanHandlers) RemovePlanItem(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	itemID, err := uuid.Parse(c.Param("itemId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	if err := h.planService.RemoveItem(tenantUUID, planID, itemID); err != nil {
		if err.Error() == "plan not found" || err.Error() == "item not found" {
			api.ErrorResponse(c, http.StatusNotFound, err.Error(), nil)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove item"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Item removed from plan"})
}

// LinkTicketToItem links a ticket to a plan item
func (h *RemediationPlanHandlers) LinkTicketToItem(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	itemID, err := uuid.Parse(c.Param("itemId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	var input models.LinkTicketInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if input.TicketID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ticket_id is required"})
		return
	}

	if err := h.planService.LinkTicket(tenantUUID, planID, itemID, input); err != nil {
		if err.Error() == "plan not found" || err.Error() == "item not found" || err.Error() == "ticket not found" {
			api.ErrorResponse(c, http.StatusNotFound, err.Error(), nil)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link ticket"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ticket linked to plan item"})
}

// ListPlansForTickets returns the remediation plans that reference the given
// ticket IDs. Input is a comma-separated `ticket_ids` query param. Response is
// a map keyed by ticket ID, each value being a minimal PlanRef list.
// Used by the Tickets page to render "in plan X" badges.
func (h *RemediationPlanHandlers) ListPlansForTickets(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	raw := c.Query("ticket_ids")
	if raw == "" {
		c.JSON(http.StatusOK, gin.H{"plans_by_ticket": map[string][]models.PlanRef{}})
		return
	}

	parts := strings.Split(raw, ",")
	ids := make([]uuid.UUID, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := uuid.Parse(p)
		if err != nil {
			// Skip invalid IDs silently — badge query is best-effort.
			continue
		}
		ids = append(ids, id)
	}

	// Cap to a reasonable size to avoid abuse.
	const maxTicketIDs = 200
	if len(ids) > maxTicketIDs {
		ids = ids[:maxTicketIDs]
	}

	plansByTicket, err := h.planService.ListForTicketIDs(tenantUUID, ids)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load plan refs for tickets"})
		return
	}

	// Serialize as string-keyed JSON object for friendlier client consumption.
	out := make(map[string][]models.PlanRef, len(plansByTicket))
	for k, v := range plansByTicket {
		out[k.String()] = v
	}

	c.JSON(http.StatusOK, gin.H{"plans_by_ticket": out})
}

// GetPlanProgress returns detailed progress for a plan
func (h *RemediationPlanHandlers) GetPlanProgress(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	planID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
		return
	}

	progress, err := h.planService.GetProgress(tenantUUID, planID)
	if err != nil {
		if err.Error() == "plan not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Plan not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get plan progress"})
		return
	}

	c.JSON(http.StatusOK, progress)
}
