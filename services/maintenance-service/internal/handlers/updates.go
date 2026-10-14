package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/updates"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// UpdatesService is the update-check seam the handlers call.
// *updates.Service satisfies it.
type UpdatesService interface {
	Read(ctx context.Context) (updates.View, error)
	Check(ctx context.Context) (updates.View, error)
}

// SetUpdates wires the update-check service. It is a setter rather than a New
// parameter so the constructor other work packages call keeps its shape.
func (h *Handlers) SetUpdates(s UpdatesService) { h.updates = s }

// manualCheckTimeout bounds a synchronous POST /updates/check.
const manualCheckTimeout = 20 * time.Second

// ErrorResponse is the body of the 4xx/5xx answers of the update routes.
type ErrorResponse struct {
	Error string `json:"error"`
}

// UpdateStatus answers GET /admin/updates: what the last check found.
func (h *Handlers) UpdateStatus(c *gin.Context) {
	if h.updates == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "updates_unavailable"})
		return
	}
	v, err := h.updates.Read(c.Request.Context())
	if err != nil {
		h.log.WithError(err).Error("updates: could not read the status row")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "status_unavailable"})
		return
	}
	c.JSON(http.StatusOK, v)
}

// CheckForUpdates answers POST /admin/updates/check: run a check now and return
// the new row. 409 check_in_progress when another check holds the lock;
// 409 check_disabled when the operator turned the check off.
func (h *Handlers) CheckForUpdates(c *gin.Context) {
	if h.updates == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "updates_unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), manualCheckTimeout)
	defer cancel()

	v, err := h.updates.Check(ctx)
	switch {
	case errors.Is(err, updates.ErrInProgress):
		c.JSON(http.StatusConflict, ErrorResponse{Error: "check_in_progress"})
		return
	case errors.Is(err, updates.ErrDisabled):
		c.JSON(http.StatusConflict, ErrorResponse{Error: "check_disabled"})
		return
	case err != nil:
		h.log.WithError(err).Error("updates: manual check failed")
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "check_failed"})
		return
	}
	h.auditManualCheck(c, v)
	c.JSON(http.StatusOK, v)
}

// auditManualCheck records the operator-initiated check in the activity trail
// (on top of the request-level entry the audit middleware writes), naming what
// the check found.
func (h *Handlers) auditManualCheck(c *gin.Context, v updates.View) {
	mw, ok := auditmiddleware.ExtractAuditMiddleware(c)
	if !ok {
		return
	}
	name := "up to date"
	success, errMsg := true, ""
	switch {
	case v.Error != nil:
		success, errMsg, name = false, *v.Error, "check failed"
	case v.UpdateAvailable && v.LatestVersion != nil:
		name = *v.LatestVersion + " available"
	}
	if err := auditmiddleware.LogSimple(c.Request.Context(), mw,
		"maintenance.update.checked", auditmiddleware.EventCategorySystem, "check",
		"platform_update_status", "", name, success, errMsg); err != nil {
		h.log.WithError(err).Warn("updates: could not record the manual check in the audit trail")
	}
}
