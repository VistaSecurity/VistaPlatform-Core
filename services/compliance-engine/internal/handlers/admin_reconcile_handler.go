package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// AdminReconcileHandler exposes the platform-admin manual re-evaluation action
// (ADR-0015). It enqueues a bounded per-tenant reconcile via the same NATS path as
// framework activation/publish — there is no scheduled re-evaluation, so this is the
// explicit escape hatch for suspected drift, an engine fix, or a bulk import.
type AdminReconcileHandler struct {
	enqueuer *services.ReconcileEnqueuer
}

// NewAdminReconcileHandler builds the handler over the shared reconcile enqueuer.
func NewAdminReconcileHandler(enqueuer *services.ReconcileEnqueuer) *AdminReconcileHandler {
	return &AdminReconcileHandler{enqueuer: enqueuer}
}

// ReevaluateTenant handles POST /compliance-engine/admin/tenants/:tenantId/reevaluate.
// The reconcile is idempotent (it converges on re-run), so this is safe to repeat; no
// rate limit is enforced in v1.
func (h *AdminReconcileHandler) ReevaluateTenant(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenantId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}
	if h.enqueuer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reconcile worker unavailable (NATS not configured)"})
		return
	}
	h.enqueuer.EnqueueTenant(tenantID, "manual platform-admin re-evaluation")
	c.JSON(http.StatusAccepted, gin.H{"message": "Re-evaluation enqueued for tenant " + tenantID.String()})
}
