package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// alertEngine is the narrow surface the HTTP handlers depend on (not the
// concrete *services.AlertEngineService) so they can be exercised against an
// in-memory stub — no database / NATS — in the spec-first contract test
// (alert_contract_test.go, ADR-0001). The concrete *services.AlertEngineService
// satisfies it; production wiring in cmd/main.go is unchanged.
type alertEngine interface {
	List(ctx context.Context, tenantID uuid.UUID, f models.AlertFilters) ([]models.Alert, error)
	Stats(ctx context.Context, tenantID uuid.UUID) (*models.AlertStats, error)
	Get(ctx context.Context, tenantID, alertID uuid.UUID) (*models.Alert, []models.AlertEvent, error)
	Acknowledge(ctx context.Context, tenantID, alertID, userID uuid.UUID) (*models.Alert, error)
	Snooze(ctx context.Context, tenantID, alertID, userID uuid.UUID, until time.Time, reason string) (*models.Alert, error)
	Unsnooze(ctx context.Context, tenantID, alertID, userID uuid.UUID) (*models.Alert, error)
	ResolveManual(ctx context.Context, tenantID, alertID, userID uuid.UUID, note string) (*models.Alert, error)
	CreateTicketFromAlert(ctx context.Context, tenantID, alertID, userID uuid.UUID) (*models.Ticket, error)
}

// AlertHandlers is the HTTP surface over the stateful alert engine.
// Reads are open to all tenant members; lifecycle mutations sit behind the
// alerts.manage permission (wired in cmd/main.go).
type AlertHandlers struct {
	engine alertEngine
}

func NewAlertHandlers(engine *services.AlertEngineService) *AlertHandlers {
	return &AlertHandlers{engine: engine}
}

// ListAlerts returns filtered alerts for the tenant.
// GET /alerts?status=&severity=&type=&limit=
func (h *AlertHandlers) ListAlerts(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	filters := models.AlertFilters{
		Status:    c.Query("status"),
		Severity:  c.Query("severity"),
		AlertType: c.Query("type"),
	}
	if l, err := strconv.Atoi(c.DefaultQuery("limit", "200")); err == nil {
		filters.Limit = l
	}
	alerts, err := h.engine.List(c.Request.Context(), tenantID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list alerts"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

// ListPlatformAlerts returns platform-track stateful alerts (service_down,
// tenant_health_degraded, …) raised under the sentinel platform tenant. This is
// the read side of the platform-track model; it is platform-admin gated in
// cmd/main.go (the /compliance-engine/admin group), so no tenant context is
// used — it always scopes to services.PlatformAlertTenantID.
// GET /compliance-engine/admin/alerts?status=&severity=&type=&limit=
func (h *AlertHandlers) ListPlatformAlerts(c *gin.Context) {
	filters := models.AlertFilters{
		Status:    c.Query("status"),
		Severity:  c.Query("severity"),
		AlertType: c.Query("type"),
	}
	if l, err := strconv.Atoi(c.DefaultQuery("limit", "200")); err == nil {
		filters.Limit = l
	}
	alerts, err := h.engine.List(c.Request.Context(), services.PlatformAlertTenantID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list platform alerts"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

// GetAlertStats returns summary counts for the Alerts page cards.
// GET /alerts/stats
func (h *AlertHandlers) GetAlertStats(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	stats, err := h.engine.Stats(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get alert stats"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// GetAlert returns one alert with its full evidence chain.
// GET /alerts/:id
func (h *AlertHandlers) GetAlert(c *gin.Context) {
	tenantID, alertID, ok := h.tenantAndAlertID(c)
	if !ok {
		return
	}
	alert, events, err := h.engine.Get(c.Request.Context(), tenantID, alertID)
	if err != nil {
		h.writeEngineError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"alert": alert, "events": events})
}

// AcknowledgeAlert marks the alert acknowledged by the calling user.
// POST /alerts/:id/acknowledge
func (h *AlertHandlers) AcknowledgeAlert(c *gin.Context) {
	h.userAction(c, func(tenantID, alertID, userID uuid.UUID) (*models.Alert, error) {
		return h.engine.Acknowledge(c.Request.Context(), tenantID, alertID, userID)
	})
}

// SnoozeAlert pauses the alert until the given time.
// POST /alerts/:id/snooze  body: { "until": RFC3339, "reason": "..." }
func (h *AlertHandlers) SnoozeAlert(c *gin.Context) {
	var body struct {
		Until  time.Time `json:"until" binding:"required"`
		Reason string    `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "until (RFC3339) is required"})
		return
	}
	h.userAction(c, func(tenantID, alertID, userID uuid.UUID) (*models.Alert, error) {
		return h.engine.Snooze(c.Request.Context(), tenantID, alertID, userID, body.Until, body.Reason)
	})
}

// UnsnoozeAlert returns a snoozed alert to active.
// POST /alerts/:id/unsnooze
func (h *AlertHandlers) UnsnoozeAlert(c *gin.Context) {
	h.userAction(c, func(tenantID, alertID, userID uuid.UUID) (*models.Alert, error) {
		return h.engine.Unsnooze(c.Request.Context(), tenantID, alertID, userID)
	})
}

// ResolveAlert manually resolves the alert with an optional note.
// POST /alerts/:id/resolve  body: { "note": "..." }
func (h *AlertHandlers) ResolveAlert(c *gin.Context) {
	var body struct {
		Note string `json:"note"`
	}
	_ = c.ShouldBindJSON(&body) // body optional
	h.userAction(c, func(tenantID, alertID, userID uuid.UUID) (*models.Alert, error) {
		return h.engine.ResolveManual(c.Request.Context(), tenantID, alertID, userID, body.Note)
	})
}

// CreateTicketFromAlert creates a linked unified ticket carrying the alert's
// evidence timeline.
// POST /alerts/:id/ticket
func (h *AlertHandlers) CreateTicketFromAlert(c *gin.Context) {
	tenantID, alertID, ok := h.tenantAndAlertID(c)
	if !ok {
		return
	}
	userID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	ticket, err := h.engine.CreateTicketFromAlert(c.Request.Context(), tenantID, alertID, userID)
	if err != nil {
		h.writeEngineError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"ticket": ticket})
}

// --- helpers -----------------------------------------------------------------

func (h *AlertHandlers) tenantAndAlertID(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, uuid.Nil, false
	}
	alertID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert ID"})
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, alertID, true
}

func (h *AlertHandlers) userAction(c *gin.Context, fn func(tenantID, alertID, userID uuid.UUID) (*models.Alert, error)) {
	tenantID, alertID, ok := h.tenantAndAlertID(c)
	if !ok {
		return
	}
	userID, ok := sharedmw.GetUserIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}
	alert, err := fn(tenantID, alertID, userID)
	if err != nil {
		h.writeEngineError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"alert": alert})
}

func (h *AlertHandlers) writeEngineError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrAlertNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
	case errors.Is(err, services.ErrInvalidTransition):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Alert operation failed"})
	}
}
