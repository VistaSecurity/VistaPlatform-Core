package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// TicketHandlers contains unified ticket management handlers.
//
// `ticketService` is typed as the small `ticketStore` interface (defined in
// framework_stores.go) rather than the concrete `*services.TicketService`,
// so the ticket HTTP surface can be exercised from
// `ticket_contract_test.go` with an in-memory stub — no DB, no NATS. The
// concrete `*services.TicketService` satisfies the interface implicitly, so
// production wiring through `cmd/main.go` is untouched.
type TicketHandlers struct {
	ticketService ticketStore
}

// NewTicketHandlers creates a new instance of ticket handlers.
// Production callers pass the concrete *services.TicketService; the contract
// test passes a stub satisfying ticketStore.
func NewTicketHandlers(ticketService *services.TicketService) *TicketHandlers {
	return &TicketHandlers{ticketService: ticketService}
}

// ListTickets returns filtered, paginated tickets for the tenant
func (h *TicketHandlers) ListTickets(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	filters := models.TicketFilters{
		Category:      c.Query("category"),
		Status:        c.Query("status"),
		Priority:      c.Query("priority"),
		Severity:      c.Query("severity"),
		AssignedTo:    c.Query("assigned_to"),
		AssetID:       c.Query("asset_id"),
		CertificateID: c.Query("certificate_id"),
		FindingID:     c.Query("finding_id"),
		Source:        c.Query("source"),
		Search:        c.Query("search"),
		Overdue:       c.Query("overdue") == "true",
	}

	if p, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil {
		filters.Page = p
	}
	if ps, err := strconv.Atoi(c.DefaultQuery("page_size", "20")); err == nil {
		filters.PageSize = ps
	}

	tickets, total, err := h.ticketService.List(tenantUUID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tickets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tickets":   tickets,
		"total":     total,
		"page":      filters.Page,
		"page_size": filters.PageSize,
	})
}

// CreateTicket creates a new ticket
func (h *TicketHandlers) CreateTicket(c *gin.Context) {
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

	var input models.CreateTicketInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if input.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title is required"})
		return
	}

	// Defaults first, then validate, so the value checked is the value
	// written. Without this the closed-vocabulary fields reached the DB CHECK
	// and a caller who sent a category we do not have got a 500 "Failed to
	// create ticket" that named no field at all.
	input.ApplyDefaults()
	if err := input.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ticket, err := h.ticketService.Create(tenantUUID, userUUID, input)
	if err != nil {
		// Log the underlying error so the next 500 is diagnosable from the
		// service logs without an extra rebuild round-trip.
		log.Printf("CreateTicket: tenant=%s user=%s failed: %v", tenantUUID, userUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create ticket"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Ticket created successfully",
		"ticket":  ticket,
	})
}

// GetTicket retrieves a single ticket by ID
func (h *TicketHandlers) GetTicket(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	ticketID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	ticket, err := h.ticketService.GetByID(tenantUUID, ticketID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get ticket"})
		return
	}
	if ticket == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ticket": ticket})
}

// UpdateTicket updates an existing ticket
func (h *TicketHandlers) UpdateTicket(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	ticketID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	var input models.UpdateTicketInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// No defaulting here: on an update a nil pointer means "not changing this
	// field", which is not the same as "set it to the default".
	if err := input.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ticket, err := h.ticketService.Update(tenantUUID, ticketID, input)
	if err != nil {
		if err.Error() == "ticket not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update ticket"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Ticket updated successfully",
		"ticket":  ticket,
	})
}

// DeleteTicket deletes a ticket
func (h *TicketHandlers) DeleteTicket(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	ticketID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	deleted, err := h.ticketService.Delete(tenantUUID, ticketID)
	if err != nil {
		if err.Error() == "ticket not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
			return
		}
		log.Printf("DeleteTicket: tenant=%s ticket=%s failed: %v", tenantUUID, ticketID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete ticket"})
		return
	}

	auditTicketDeleted(c, deleted)

	c.JSON(http.StatusOK, gin.H{"message": "Ticket deleted successfully"})
}

// GetTicketProgress returns time-series remediation progress data
func (h *TicketHandlers) GetTicketProgress(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	days := 30
	if d, err := strconv.Atoi(c.DefaultQuery("days", "30")); err == nil && d > 0 {
		days = d
	}
	category := c.Query("category")

	progress, err := h.ticketService.GetProgress(tenantUUID, days, category)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get ticket progress"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"progress": progress})
}

// GetTicketStats returns aggregate ticket statistics
func (h *TicketHandlers) GetTicketStats(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	stats, err := h.ticketService.GetStats(tenantUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get ticket stats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// ListComments returns all comments for a ticket
func (h *TicketHandlers) ListComments(c *gin.Context) {
	tenantUUID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}

	ticketID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	comments, err := h.ticketService.ListComments(tenantUUID, ticketID)
	if err != nil {
		if err.Error() == "ticket not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list comments"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"comments": comments})
}

// AddComment adds a comment to a ticket
func (h *TicketHandlers) AddComment(c *gin.Context) {
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

	ticketID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ticket ID"})
		return
	}

	var input struct {
		Content string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Content is required"})
		return
	}

	comment, err := h.ticketService.AddComment(tenantUUID, ticketID, userUUID, input.Content)
	if err != nil {
		if err.Error() == "ticket not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add comment"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Comment added successfully",
		"comment": comment,
	})
}

// auditTicketDeleted records a destroyed ticket in the audit trail.
//
// The global LogRequest middleware already records that a DELETE happened.
// That is not sufficient here and the difference matters: the delete is HARD,
// so once it returns, the row, its description, its assignee, its due date and
// its whole comment thread are gone. A trail that reads
// "DELETE /tickets/6f3a… 200" proves only that something was destroyed. This
// entry carries the ticket itself in `oldValues`, which makes it the record
// rather than a pointer to one.
//
// Deliberately best-effort. The ticket is already gone and the transaction is
// committed; failing the request now would tell the caller the delete failed
// when it did not, which is a worse lie than a missing audit line. The audit
// client logs its own failures, and the LogRequest entry still lands.
func auditTicketDeleted(c *gin.Context, t *models.Ticket) {
	if t == nil {
		return
	}
	mw, ok := audithelpers.ExtractAuditMiddleware(c)
	if !ok {
		// Only reachable if the audit_middleware context wiring in cmd/main.go
		// is removed. TestAuditMiddleware_IsReachableFromHandlers exists so
		// that shows up as a failing test rather than as silence.
		log.Printf("DeleteTicket: audit middleware unavailable, ticket %s deletion unrecorded", t.ID)
		return
	}

	related := []audithelpers.RelatedResource{}
	add := func(kind string, id *uuid.UUID) {
		if id != nil {
			related = append(related, audithelpers.RelatedResource{Type: kind, ID: id.String()})
		}
	}
	// What the ticket was attached to. After the delete these links exist
	// nowhere else, and "which asset was that ticket about?" is the first
	// question anyone asks.
	add("asset", t.AssetID)
	add("certificate", t.CertificateID)
	add("finding", t.FindingID)
	add("crypto_implementation", t.CryptoImplementationID)
	add("alert", t.AlertID)

	extra := map[string]interface{}{
		"category": t.Category,
		"status":   t.Status,
		"priority": t.Priority,
		"source":   t.Source,
	}
	if t.AssignedTo != nil {
		extra["assigned_to"] = t.AssignedTo.String()
	}
	if t.DueDate != nil {
		extra["due_date"] = t.DueDate.Format(time.RFC3339)
	}
	if t.ResolvedAt != nil {
		extra["resolved_at"] = t.ResolvedAt.Format(time.RFC3339)
	}
	if len(t.Tags) > 0 {
		extra["tags"] = []string(t.Tags)
	}
	if t.ExternalTicketSystem != nil {
		extra["external_ticket_system"] = *t.ExternalTicketSystem
	}
	if t.ExternalTicketID != nil {
		extra["external_ticket_id"] = *t.ExternalTicketID
	}
	// How long it existed. A ticket deleted minutes after it was filed is a
	// mistake being tidied up; one deleted after three months open is a
	// different event, and the reader should not have to work that out.
	extra["age_hours"] = int(time.Since(t.CreatedAt).Hours())

	_ = audithelpers.LogWithContext(
		c.Request.Context(), mw,
		audithelpers.EventTypeTicketDeleted, audithelpers.EventCategoryCompliance,
		"delete", "ticket", t.ID.String(), t.Title,
		t, nil,
		audithelpers.AuditMetadata{
			ResourceName:     t.Title,
			RelatedResources: related,
			ChangeSummary: fmt.Sprintf("Deleted %s ticket %q (%s, %s)",
				t.Category, t.Title, t.Status, t.Priority),
			AdditionalData: extra,
		},
	)
}
