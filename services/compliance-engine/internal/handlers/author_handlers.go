package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
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
// The answer is fixed at wiring time rather than computed per request: it
// depends on the process's AI_PROVIDER configuration and on which binary is
// running, neither of which changes between requests.
type AuthorHandlers struct {
	availability models.AuthorAvailability
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

// GetAvailability reports whether drafting controls from a standard is offered.
//
// Deliberately not behind the custom_policies entitlement, even on the tenant
// route: what it discloses is a property of the DEPLOYMENT (does an operator
// have a model provider configured), not of the tenant or its data, and gating
// it would put a 402 in the console of every non-Enterprise tenant that opens
// the Policies page. The drafting endpoint it guards is gated.
func (h *AuthorHandlers) GetAvailability(c *gin.Context) {
	c.JSON(http.StatusOK, h.availability)
}
