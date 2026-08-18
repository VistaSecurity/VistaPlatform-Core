package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// ReevaluationHandler is the TENANT-facing manual re-evaluation, gated on
// compliance.manage and rate-limited to one accepted run per tenant per hour.
//
// The tenant is taken from the caller's context and from nowhere else. There is no
// :tenantId on the route and no tenant field in the body — a caller-supplied tenant
// id on a tenant route is a cross-tenant hole, and this repo has shipped that bug
// before. The platform-admin route keeps its path parameter because it is gated by
// RequirePlatformAdmin and crossing tenants IS its job.
type ReevaluationHandler struct {
	svc      reevaluationCooldown
	enqueuer reconcileEnqueuer
}

// reevaluationCooldown is the persisted per-tenant cooldown
// (*services.ReevaluationService in production). An interface so the contract test
// can exercise the real handlers without a database.
type reevaluationCooldown interface {
	State(ctx context.Context, tenantID uuid.UUID) (services.ReevaluationState, error)
	Claim(ctx context.Context, tenantID, userID uuid.UUID) (services.ReevaluationState, bool, error)
}

// reconcileEnqueuer is the one reconcile path (*services.ReconcileEnqueuer).
type reconcileEnqueuer interface {
	Ready() bool
	EnqueueTenant(tenantID uuid.UUID, reason string)
}

// NewReevaluationHandler builds the handler over the cooldown service and the shared
// reconcile enqueuer (the same one the admin route and framework activation use —
// there is exactly one reconcile path).
//
// A nil enqueuer (NATS not configured) is stored as a nil INTERFACE, not as a
// typed-nil wrapped in one: `h.enqueuer == nil` has to actually be true, or the 503
// guard silently stops guarding and we enqueue into nothing while answering 202.
func NewReevaluationHandler(svc *services.ReevaluationService, enqueuer *services.ReconcileEnqueuer) *ReevaluationHandler {
	h := &ReevaluationHandler{svc: svc}
	if enqueuer != nil {
		h.enqueuer = enqueuer
	}
	return h
}

// reevaluationStateBody is the wire shape of the cooldown, returned by GET and on
// BOTH outcomes of POST so a client never has to guess or make a second call.
func reevaluationStateBody(st services.ReevaluationState, now time.Time) gin.H {
	body := gin.H{
		"allowed":          st.Allowed,
		"cooldown_seconds": int(st.Cooldown / time.Second),
	}
	if st.LastRequestedAt != nil {
		body["last_requested_at"] = st.LastRequestedAt.UTC().Format(time.RFC3339)
	} else {
		body["last_requested_at"] = nil
	}
	if st.NextAllowedAt != nil {
		body["next_allowed_at"] = st.NextAllowedAt.UTC().Format(time.RFC3339)
		body["retry_after_seconds"] = st.RetryAfter(now)
	} else {
		body["next_allowed_at"] = nil
		body["retry_after_seconds"] = 0
	}
	return body
}

// GetState handles GET /compliance-engine/reevaluation. Read-only; lets the UI
// disable the control BEFORE the user clicks, rather than letting them click and
// then answering 429.
func (h *ReevaluationHandler) GetState(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant context required"})
		return
	}
	st, err := h.svc.State(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read re-evaluation state"})
		return
	}
	c.JSON(http.StatusOK, reevaluationStateBody(st, time.Now()))
}

// Reevaluate handles POST /compliance-engine/reevaluate.
//
// A cooldown-blocked request answers 429, not 200. It did not do the thing the
// caller asked for, and a 200 would be indistinguishable from success in every
// client log and retry policy — the same "reports success while doing nothing"
// shape CLAUDE.md warns about. The body carries the full state (and Retry-After)
// so the client can re-sync in one round trip.
func (h *ReevaluationHandler) Reevaluate(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant context required"})
		return
	}
	// Check the transport BEFORE consuming the cooldown: burning an hour on a
	// request that could never have run is exactly the kind of silent nothing this
	// endpoint exists to avoid.
	if h.enqueuer == nil || !h.enqueuer.Ready() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Re-evaluation is unavailable right now (the reconcile worker is not running)"})
		return
	}
	userID, _ := sharedmw.GetUserIDFromContext(c)

	now := time.Now()
	st, claimed, err := h.svc.Claim(c.Request.Context(), tenantID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start re-evaluation"})
		return
	}
	if !claimed {
		body := reevaluationStateBody(st, now)
		body["error"] = "Re-evaluation was run recently. Try again later."
		c.Header("Retry-After", strconv.Itoa(st.RetryAfter(now)))
		c.JSON(http.StatusTooManyRequests, body)
		return
	}

	h.enqueuer.EnqueueTenant(tenantID, "manual tenant re-evaluation")

	body := reevaluationStateBody(st, now)
	body["message"] = "Re-evaluation queued. Findings and scores refresh in the background."
	c.JSON(http.StatusAccepted, body)
}
