package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
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

	if err := h.ticketService.Delete(tenantUUID, ticketID); err != nil {
		if err.Error() == "ticket not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Ticket not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete ticket"})
		return
	}

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
