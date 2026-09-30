package handlers

// Internal service-to-service endpoints over the export feed
// (services/export_feed.go). Mounted ONLY on the HMAC-gated internal group in
// cmd/main.go, under /audit-service/internal/, which the gateway denies on
// every public host (standards/service-registry.yaml internal_prefixes): no
// user token — tenant or platform — can reach them, and no browser ever calls
// them.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// exportFeedService is the slice of *services.ActivityLogService the feed
// handlers use, so a test can drive them without a database.
type exportFeedService interface {
	ExportPage(ctx context.Context, after services.ExportCursor, limit int, settle time.Duration) (services.ExportPage, error)
	ExportHead(ctx context.Context, backfill time.Duration) (services.ExportCursor, error)
}

// ExportFeedHandler serves the export feed to internal callers.
type ExportFeedHandler struct {
	service exportFeedService
	// settle is the feed's settle window (services.ExportSettleWindow in
	// production; a test may shorten it).
	settle time.Duration
}

// NewExportFeedHandler serves the feed from the activity-log store.
func NewExportFeedHandler(service *services.ActivityLogService) *ExportFeedHandler {
	return &ExportFeedHandler{service: service, settle: services.ExportSettleWindow}
}

// NewExportFeedHandlerFor serves the feed from any implementation of the two
// feed reads — the router wiring tests in cmd/ use a stub so they need no
// database.
func NewExportFeedHandlerFor(service exportFeedService, settle time.Duration) *ExportFeedHandler {
	return &ExportFeedHandler{service: service, settle: settle}
}

// GetEvents handles GET /api/v1/audit-service/internal/export/events.
//
// Query: after_created_at (RFC 3339, required), after_id (UUID, required),
// limit (1..1000, default 500). Returns the events stored strictly after that
// cursor, oldest first, each with the cursor that points just past it.
func (h *ExportFeedHandler) GetEvents(c *gin.Context) {
	at, err := time.Parse(time.RFC3339Nano, c.Query("after_created_at"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "after_created_at must be an RFC 3339 timestamp"})
		return
	}
	id, err := uuid.Parse(c.Query("after_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "after_id must be a UUID"})
		return
	}
	limit := services.ExportPageDefault
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be an integer"})
			return
		}
		limit = n
	}
	page, err := h.service.ExportPage(c.Request.Context(), services.ExportCursor{CreatedAt: at, ID: id}, limit, h.settle)
	if err != nil {
		writeExportError(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

// GetHead handles GET /api/v1/audit-service/internal/export/head.
//
// Query: backfill_seconds (0..604800, default 0). Returns the cursor a new
// consumer starts from: "now" by the database clock, or that many seconds ago.
func (h *ExportFeedHandler) GetHead(c *gin.Context) {
	var backfill time.Duration
	if raw := c.Query("backfill_seconds"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "backfill_seconds must be an integer"})
			return
		}
		backfill = time.Duration(n) * time.Second
		if n < 0 || backfill > services.ExportBackfillMax {
			c.JSON(http.StatusBadRequest, gin.H{"error": "backfill_seconds is out of range"})
			return
		}
	}
	cur, err := h.service.ExportHead(c.Request.Context(), backfill)
	if err != nil {
		writeExportError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"cursor": cur})
}

func writeExportError(c *gin.Context, err error) {
	if errors.Is(err, services.ErrInvalidExportRequest) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("ERROR: audit export feed: %v", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the audit export feed"})
}
