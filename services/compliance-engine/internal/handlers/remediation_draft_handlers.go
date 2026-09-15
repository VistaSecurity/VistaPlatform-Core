package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/ai"
	aiedition "github.com/vistasecurity/vistaplatform/shared/ai/edition"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmw "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// The Remediator seam's HTTP surface (ADR-0008 D1), on the tenant plane.
//
//	POST /findings/:id/remediation/draft    ask for a plan
//	POST /findings/:id/remediation/accept   persist one a person accepted
//
// # Why these live in Core, and answer 402 there
//
// Both routes are mounted in EVERY edition, and the Core build answers 402
// Payment Required. That is deliberate and it is not what the author seam does
// — its drafting routes are mounted by an edition hook and simply do not exist
// in Core, with a separate Core availability endpoint telling the UI so.
//
// The difference is that this capability's availability question is already
// answered, deployment-wide, by `GET /api/v1/auth-service/tenant/ai` (the
// Settings → AI assistant endpoint). A third availability endpoint here would be
// a second answer to a question that already has one, and the two would drift.
// So the UI asks that one, and these routes answer honestly to anything that
// calls them anyway:
//
//	402  this edition has no remediator at all        (a purchase)
//	503  Enterprise, but no model provider is reachable (ten minutes of an
//	                                                     administrator's time)
//	403  the tenant has turned the AI assistant off     (a switch they own)
//
// A 404 for the Core case would be indistinguishable from a broken route, and
// would put one in every Core user's console. Those are the same reasons
// AI_SEAMS §10 and §12 give for their own endpoints.
//
// # What is NOT here
//
// Editing. A drafted plan a person accepts becomes an ordinary remediation plan
// item and is shown on the Plans page like every other one — its notes render in
// full, and nothing about it is a second kind of object. (Plan-item notes have
// no in-place editor today, for a drafted item or a typed one; when one is
// built it is the one editor, not a second one for AI-drafted items.) A separate
// editor here would be a second place to keep correct, and would make an
// accepted draft a different kind of object from the thing beside it — which is
// exactly what the provenance columns exist to avoid needing.
type RemediationDraftHandlers struct {
	seam     seams.Remediator
	resolver findingResolver
	plans    draftPlanStore
	db       *sql.DB

	// modelID is the model THIS DEPLOYMENT is configured with, read once at
	// construction. It is what Accept stamps on the row, instead of the model
	// id the client sent — see acceptRequest.ModelID.
	modelID string
}

// findingResolver is the read half: one finding, projected onto the seam's
// allowlist. *services.RemediationDraftService satisfies it.
//
// An interface rather than the concrete type so the contract tests can drive the
// REAL handlers and the REAL router without a database — the pattern
// RemediationPlanHandlers' planStore already established here. It is narrow on
// purpose: a handler that could reach the rest of that service would grow a
// second way to read a finding.
type findingResolver interface {
	ResolveFinding(ctx context.Context, tenantID, findingID uuid.UUID) (seams.FindingRef, error)
}

// draftPlanStore is the write half: the two plan operations accepting a draft
// needs, and nothing else. *services.RemediationPlanService satisfies it.
//
// AddDraftedItem is deliberately the only write. The ordinary AddItem cannot
// record provenance, and a handler holding the whole plan service could reach
// for it and write an accepted draft with no source_kind — which would look
// exactly like a hand-typed item forever.
type draftPlanStore interface {
	Create(tenantID, createdBy uuid.UUID, input models.CreatePlanInput) (*models.RemediationPlan, error)
	AddDraftedItem(tenantID, planID, addedBy, findingID uuid.UUID, notes, sourceKind, sourceRef string) (*models.RemediationPlanItem, error)
}

// NewRemediationDraftHandlers wires the two endpoints.
//
// A nil or null seam is a supported state, not a wiring error: it is what Core
// has, and what an Enterprise build with AI_PROVIDER unset has. The endpoints
// answer 402 and 503 respectively, and the UI — having asked /tenant/ai — never
// offered the button. Both halves are tested, because "the button is hidden" is a
// UI decision and the endpoint has to be right on its own.
func NewRemediationDraftHandlers(
	seam seams.Remediator,
	resolver findingResolver,
	plans draftPlanStore,
	rawDB *sql.DB,
) *RemediationDraftHandlers {
	if rawDB == nil {
		// Said out loud rather than never. Without a pool the tenant kill
		// switch is not consulted here and the boundary's second lock is
		// reading a stamp this is the code that applies — so the `h.db != nil`
		// guard below would be a check that cannot fail.
		log.Print("[remediation-draft] no database handle: the tenant AI kill switch will NOT be consulted")
	}
	return &RemediationDraftHandlers{
		seam:     seam,
		resolver: resolver,
		plans:    plans,
		db:       rawDB,
		// Read here rather than per request: it is process configuration, it
		// cannot change under a running pod, and reading it at the call site
		// would put an os.Getenv in the write path for no gain.
		modelID: ai.ProviderConfigFromEnv().Model,
	}
}

// draftResponse is what POST …/draft returns.
type draftResponse struct {
	// Plan is always present, in every outcome this endpoint answers 200 for.
	// There is no shape of success in which a caller gets no plan: a model
	// draft, or the finding's own guidance with a reason.
	Plan seams.PlanDraft `json:"plan"`

	// Provenance repeats the draft's own source_kind / source_ref /
	// confidence / model_id at the top level, where a client that renders a
	// "drafted by" line does not have to know that PlanDraft embeds it.
	Provenance seams.Proposal `json:"provenance"`
}

// acceptRequest is the body of POST …/accept.
//
// It carries the STEPS the user is accepting rather than a reference to a draft,
// because the draft was never persisted: the draft endpoint writes nothing, so
// there is no id to reference. What arrives is therefore whatever the client
// sends, which today's drawer renders read-only and echoes back verbatim — but
// that is a property of one client, not of this endpoint.
//
// The consequence is worth stating plainly: the server cannot verify that these
// steps came from a model, and does not pretend to. What the provenance columns
// record is that a plan was accepted through THIS path with this model id — an
// audited action by a named user, not a signed attestation about the text. The
// alternative, persisting every draft so an accept could reference one, would
// store a row for every button press including the ones nobody accepted, to buy
// a guarantee about text the same user was free to rewrite anyway.
type acceptRequest struct {
	// PlanID adds the finding to an existing plan. Omit it and Title creates a
	// new one, which is the path the Findings inspector uses.
	PlanID string `json:"plan_id"`
	Title  string `json:"title"`

	// ModelID is IGNORED, and kept only so an older client's body still decodes.
	//
	// It used to become the row's `source_ref` verbatim, which made the one
	// piece of provenance the server could actually have stood behind a caller
	// assertion: any client could store any model id, of any length, against a
	// plan item stamped `inferred` (security review X.5, X5-07). The server now
	// writes the model THIS DEPLOYMENT is configured with, and
	// `remediator:model` — the seam's own "a model, id not pinned" sentinel —
	// when it is configured with none.
	//
	// That is a small loss of fidelity in the AI_MODEL-unset case and the right
	// trade: a provenance field nobody can forge, saying less, beats a precise
	// one that means nothing.
	ModelID string `json:"model_id"`

	// Summary and Steps are the plan as the user is accepting it. Rendered into
	// the item's notes, which is where the Plans page shows them — the same
	// place, and the same rendering, as a note somebody typed.
	Summary string       `json:"summary"`
	Steps   []acceptStep `json:"steps"`

	// Source echoes the draft's own source. Only a model draft is acceptable
	// here; a guidance draft has nothing drafted in it, and accepting one would
	// record our own guidance text as something a model wrote.
	Source string `json:"source"`
}

type acceptStep struct {
	Action    string `json:"action"`
	Rationale string `json:"rationale"`
	Manual    bool   `json:"manual"`
}

// Draft asks the seam for a plan for one finding.
func (h *RemediationDraftHandlers) Draft(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	findingID, ok := parseUUIDParam(c, "id", "finding")
	if !ok {
		return
	}

	// Edition first. "Your plan does not include this" is the more useful
	// message to lead with when it applies, and answering it before touching
	// the database means a Core deployment spends nothing on a route it cannot
	// serve.
	if !aiedition.RemediatorLinked() {
		c.JSON(http.StatusPaymentRequired, gin.H{
			"error": "Drafting a remediation plan is part of Vista Platform Enterprise. " +
				"Every finding still carries the standard remediation guidance for its kind.",
		})
		return
	}

	// The acting user is not optional here either, and for D4.7's reason rather
	// than D5's: ai.WithAudit REFUSES a request naming no invoker
	// (ai.ErrUnattributed), and "which user or rule invoked it" is the question
	// the audit trail exists to answer. An internal service call carries the
	// no-user sentinel, so this is reachable — and letting it through would
	// spend the boundary's refusal on it and degrade to the guidance with
	// `provider_error`, telling a reader the model provider could not be
	// reached when nothing was wrong with the provider at all.
	userID, hasUser := sharedmw.GetUserIDFromContext(c)
	if !hasUser {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	ctx := seams.WithInvoker(c.Request.Context(), userID.String())
	ctx = auditmw.WithAIActor(ctx, tenantID, "tenant")

	// The tenant's own controls (Settings → AI assistant), read once and used
	// twice: the kill switch answers the request here, and both controls are
	// stamped on the context so ai.WithAudit enforces the switch a second time
	// at the boundary and D4.7's question-recording opt-in reaches the call.
	if h.db != nil {
		controls, err := ai.TenantAIControls(ctx, h.db, tenantID)
		if err != nil {
			// Fail closed, like ai.TenantAllows: a settings read that did not
			// complete is not evidence the tenant said yes. The sentence names
			// the settings read rather than the model, because pointing a user
			// at the AI provider for a database problem wastes their afternoon.
			log.Printf("[remediation-draft] tenant AI controls unreadable for %s: %v", tenantID, err)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Your organization's AI assistant settings could not be read, so nothing was drafted. Try again shortly.",
			})
			return
		}
		ctx = ai.WithTenantControls(ctx, controls)
		if controls.AssistantDisabled {
			// Told, not degraded. A guidance draft here would be a page saying
			// the model answered when the tenant had switched it off, and the
			// Findings inspector is already showing that guidance anyway.
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Your organization has turned the AI assistant off. A tenant administrator can turn it back on in Settings → AI assistant.",
			})
			return
		}
	}

	finding, err := h.resolver.ResolveFinding(ctx, tenantID, findingID)
	if errors.Is(err, services.ErrFindingNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Finding not found"})
		return
	}
	if err != nil {
		log.Printf("[remediation-draft] resolving finding %s: %v", findingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	draft, err := h.seam.Propose(ctx, finding)
	if err != nil {
		h.writeDraftError(c, finding, err)
		return
	}

	c.JSON(http.StatusOK, draftResponse{Plan: draft, Provenance: draft.Provenance()})
}

// writeDraftError maps a seam failure onto a status.
//
// Almost nothing reaches here. The Enterprise implementation degrades every
// provider failure to the finding's own guidance and returns a nil error, so
// this handles the two it does not: the tenant kill switch (the boundary's
// second lock, when the call-site check above could not run because there is no
// pool) and the null seam an Enterprise build with no provider resolves to.
func (h *RemediationDraftHandlers) writeDraftError(c *gin.Context, finding seams.FindingRef, err error) {
	switch {
	case errors.Is(err, ai.ErrTenantDisabled):
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Your organization has turned the AI assistant off. A tenant administrator can turn it back on in Settings → AI assistant.",
		})
	case errors.Is(err, ai.ErrUnavailable):
		// The null seam: this build has the remediator but no model provider is
		// reachable. Deliberately 503 rather than 402 — an operator can fix
		// this one, and the two must not read the same.
		//
		// The guidance goes out in the body anyway. It is what the page shows
		// without a model, the client already has it, and repeating it here
		// means a client that only knows how to render this response still
		// shows the user something true.
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Drafting a remediation plan is not available: this deployment has no AI provider configured. " +
				"The standard remediation guidance for this finding is unchanged.",
			"guidance": finding.Guidance,
		})
	default:
		log.Printf("[remediation-draft] the seam failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

// Accept persists a plan a person accepted (ADR-0008 D5: a seam proposes, a
// human approves).
//
// It writes ONE remediation_plan_items row linking the finding to a plan, with
// the steps rendered into `notes` and the provenance on the row. One row, not
// one per step, because a plan item IS a finding being worked — the table's
// unique_plan_finding constraint says so — and the steps are how this finding is
// being worked, which is what `notes` has always been for. It also means the
// accepted plan is edited on the Plans page exactly like a hand-typed note,
// rather than in a second editor nobody would keep in step.
func (h *RemediationDraftHandlers) Accept(c *gin.Context) {
	tenantID, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	findingID, ok := parseUUIDParam(c, "id", "finding")
	if !ok {
		return
	}
	if !aiedition.RemediatorLinked() {
		c.JSON(http.StatusPaymentRequired, gin.H{
			"error": "Drafting a remediation plan is part of Vista Platform Enterprise.",
		})
		return
	}

	// The acting user is not optional. D5's "a human accepts" is recorded in
	// `added_by`, and an unattributed accept is the shape D4.7 refuses
	// elsewhere — so it is refused here rather than written with a NULL actor.
	userID, hasUser := sharedmw.GetUserIDFromContext(c)
	if !hasUser {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	var req acceptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if len(req.Steps) == 0 {
		// A guidance draft has no steps and is not an accept: there is nothing
		// in it that was drafted, and recording one as `inferred` would claim a
		// model wrote our own guidance text. "Add to plan" is the button for
		// that, and it already exists.
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "There are no drafted steps to accept. Use “Add to plan” to add this finding without a drafted plan.",
		})
		return
	}
	if req.Source != "" && req.Source != seams.PlanSourceModel {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Only a drafted plan can be accepted here.",
		})
		return
	}
	if msg, ok := checkAcceptedPlanBounds(req); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	planID, ok := h.resolvePlan(c, tenantID, userID, req)
	if !ok {
		return
	}

	// The provenance is the SERVER's, not the caller's. source_kind has always
	// been a constant here; source_ref is now the model this deployment is
	// configured with rather than the one the body named.
	item, err := h.plans.AddDraftedItem(tenantID, planID, userID, findingID,
		renderPlanNotes(req), seams.SourceKindInferred, remediatorSourceRef(h.modelID))
	switch {
	case errors.Is(err, services.ErrItemAlreadyInPlan):
		c.JSON(http.StatusConflict, gin.H{"error": "This finding is already in that plan."})
		return
	case err != nil && strings.Contains(err.Error(), "not found"):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	case err != nil:
		log.Printf("[remediation-draft] accepting a plan for finding %s: %v", findingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"item": item, "plan_id": planID})
}

// resolvePlan finds or creates the plan the item goes into.
//
// Creating one is the Findings-inspector path: a person drafting a plan for a
// finding usually has nowhere to put it yet, and making them create a plan first
// would be two dialogs for one decision. The created plan is an ordinary
// remediation plan in `draft` status — nothing about it says AI, because the
// plan is not the drafted thing; the item is.
//
// It answers the request itself on failure and reports false, the way
// parseUUIDParam does. The alternative — returning a status and an error for the
// caller to render — meant building user-facing sentences with errors.New, which
// is both a lint failure (error strings are not capitalised) and a category
// mistake: these are response copy, not errors anything handles.
func (h *RemediationDraftHandlers) resolvePlan(
	c *gin.Context, tenantID, userID uuid.UUID, req acceptRequest,
) (uuid.UUID, bool) {
	if strings.TrimSpace(req.PlanID) != "" {
		id, err := uuid.Parse(req.PlanID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid plan ID"})
			return uuid.Nil, false
		}
		return id, true
	}

	title := strings.TrimSpace(req.Title)
	if title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Give the new plan a title, or name an existing plan"})
		return uuid.Nil, false
	}
	plan, err := h.plans.Create(tenantID, userID, models.CreatePlanInput{Title: title, PlanType: "remediation"})
	if err != nil {
		log.Printf("[remediation-draft] creating a plan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return uuid.Nil, false
	}
	return plan.ID, true
}

// checkAcceptedPlanBounds bounds the plan a client is accepting, and reports the
// sentence to answer with when it does not fit (security review X.5, X5-07).
//
// The steps arrive from the client because the draft was never persisted, which
// is a documented trade — but "the server cannot verify these came from a
// model" is not the same as "the server accepts any amount of anything". Before
// this, Summary and Steps were unbounded, so renderPlanNotes could build a
// `notes` value up to whatever the edge forwards, per accepted plan, and store
// it on a row the Plans page then renders.
//
// The bounds are the seam's own — the numbers that cap what the drafter may
// PROPOSE — so a plan this deployment actually drafted always fits, and a plan
// that does not fit could not have come from here.
//
// Refused, not truncated. A truncated plan is a plan with its last step missing
// and nothing in the notes saying so, which is worse than an error a person can
// act on.
func checkAcceptedPlanBounds(req acceptRequest) (string, bool) {
	if len(req.Steps) > seams.MaxPlanSteps {
		return fmt.Sprintf("That plan has %d steps; at most %d can be accepted. "+
			"Draft again, or add the finding to a plan and write the steps yourself.",
			len(req.Steps), seams.MaxPlanSteps), false
	}
	if len(req.Summary) > seams.MaxPlanSummaryBytes {
		return fmt.Sprintf("The plan summary is longer than %d characters.", seams.MaxPlanSummaryBytes), false
	}
	for i, s := range req.Steps {
		if len(s.Action) > seams.MaxPlanStepBytes {
			return fmt.Sprintf("Step %d is longer than %d characters.", i+1, seams.MaxPlanStepBytes), false
		}
		if len(s.Rationale) > seams.MaxPlanStepBytes {
			return fmt.Sprintf("The rationale on step %d is longer than %d characters.", i+1, seams.MaxPlanStepBytes), false
		}
	}
	return "", true
}

// remediatorSourceRef builds the row's source_ref.
//
// It mirrors shared/ai/ee/remediator.SourceRefFor, which Core may not import.
// The duplication is one string and it is pinned by a contract test, which is
// the same trade shared/ai/edition makes for the implementation name.
func remediatorSourceRef(modelID string) string {
	if strings.TrimSpace(modelID) == "" {
		return "remediator:model"
	}
	return "remediator:" + strings.TrimSpace(modelID)
}

// renderPlanNotes turns an accepted draft into the item's notes.
//
// Plain text, numbered, with the citation markers LEFT IN and the manual steps
// marked. The markers stay because they are the checkable part: a step whose
// evidence reference is stripped on the way into the database is a step nobody
// can audit afterwards, and the same text is what somebody pastes into a ticket.
func renderPlanNotes(req acceptRequest) string {
	var b strings.Builder
	if s := strings.TrimSpace(req.Summary); s != "" {
		b.WriteString(s)
		b.WriteString("\n\n")
	}
	for i, step := range req.Steps {
		fmt.Fprintf(&b, "%d. %s", i+1, strings.TrimSpace(step.Action))
		if step.Manual {
			b.WriteString(" [manual step]")
		}
		b.WriteString("\n")
		if r := strings.TrimSpace(step.Rationale); r != "" {
			fmt.Fprintf(&b, "   %s\n", r)
		}
	}
	return strings.TrimSpace(b.String())
}

func parseUUIDParam(c *gin.Context, param, what string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(param))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid " + what + " ID"})
		return uuid.Nil, false
	}
	return id, true
}
