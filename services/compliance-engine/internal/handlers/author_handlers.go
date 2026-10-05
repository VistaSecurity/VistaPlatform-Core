package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/ai"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// AuthorHandlers serves the one piece of the ADR-0008 Author seam that exists
// in every edition: whether it can answer.
//
// The drafting endpoints themselves are Enterprise (ee/author) and are simply
// not mounted in a Core build. This one IS mounted in Core, answering
// `{"available":false,"reason":"edition"}`, so the two authoring UIs have a
// single, stable question to ask before deciding whether to offer the button.
// The alternative — let the UI infer from a 404 — cannot tell "this build has
// no generative author" from "the route is broken", and would put a 404 in
// every Core user's console on every visit to the page.
//
// Which BINARY is running is fixed at wiring time, and in Core that is the whole
// answer. In a build with the model clients the answer is per request: a
// tenant may have connected its own provider, so "is drafting available"
// depends on who is asking. live, when set, answers for the scope on the
// request; the wiring-time value is what a build without it serves.
type AuthorHandlers struct {
	availability models.AuthorAvailability
	live         func(ctx context.Context) models.AuthorAvailability
}

// NewAuthorHandlers creates the availability handler. The zero
// AuthorAvailability is the honest Core answer, so a caller that wires nothing
// reports unavailable rather than reporting available by omission.
func NewAuthorHandlers(availability models.AuthorAvailability) *AuthorHandlers {
	if availability.Reason == "" && !availability.Available {
		availability.Reason = models.AuthorReasonEdition
	}
	return &AuthorHandlers{availability: availability}
}

// WithLive makes the answer per request. A nil live leaves the wiring-time
// answer in place.
func (h *AuthorHandlers) WithLive(live func(ctx context.Context) models.AuthorAvailability) *AuthorHandlers {
	h.live = live
	return h
}

// GetAvailability reports whether drafting controls from a standard is offered.
//
// Deliberately not behind the custom_policies entitlement, even on the tenant
// route: what it discloses is a property of the DEPLOYMENT (does an operator
// have a model provider configured), not of the tenant or its data, and gating
// it would put a 402 in the console of every non-Enterprise tenant that opens
// the Policies page. The drafting endpoint it guards is gated.
func (h *AuthorHandlers) GetAvailability(c *gin.Context) {
	if h.live == nil {
		c.JSON(http.StatusOK, h.availability)
		return
	}
	// The tenant plane carries a tenant and is answered for that tenant's
	// provider; the platform plane carries none and is answered for the
	// platform's. A platform admin is never told drafting is available on the
	// strength of some tenant's provider.
	ctx := c.Request.Context()
	if tenantID, ok := sharedmw.GetTenantIDFromContext(c); ok {
		ctx = ai.WithTenantScope(ctx, tenantID)
	}
	c.JSON(http.StatusOK, h.live(ctx))
}
