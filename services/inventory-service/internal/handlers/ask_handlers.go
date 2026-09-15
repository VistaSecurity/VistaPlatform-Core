package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/ai"
	aiedition "github.com/vistasecurity/vistaplatform/shared/ai/edition"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	auditmw "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// The Query seam's HTTP surface (ADR-0008 D1, build-plan 4.4b):
//
//	POST /ask   a question, answered as a query you can edit plus the rows it
//	            selected and a summary that cites them
//
// # What comes back, in order of authority
//
// The QUERY first, then the ROWS, then the prose. That order is the design
// (ADR-0006 D2 with ADR-0008 D4.4): the model's whole output at the first stage
// is one line of the query language, which is parsed and validated before
// anything runs, so the thing between a question and its answer is a checkable
// artefact a user can edit and save as a view. The prose is a reading of the
// rows and is dropped sentence by sentence where it does not cite one.
//
// Consequently a caller that renders nothing but `query` and `rows` has the
// whole answer. `text` is the convenience.
//
// # Why this is mounted in every edition and answers 402 in Core
//
// Same reason the remediator's drafting routes are (AI_SEAMS §14): the
// availability question is already answered deployment-wide by
// `GET /api/v1/auth-service/tenant/ai`, so the UI asks THAT and never offers the
// box — and this endpoint answers honestly to anything that calls it anyway:
//
//	402  this edition has no query seam at all           (a purchase)
//	403  the tenant has turned the AI assistant off      (a switch they own)
//	422  a provider answered and could not write a valid query, with the
//	     validator's diagnostics (something the reader can act on)
//	503  Enterprise, but no model provider is reachable  (an administrator's
//	                                                      ten minutes)
//
// A 404 in Core would be indistinguishable from a broken route and would put
// one in every Core user's console.
//
// # What a Core deployment still has
//
// All of it except the talking. The query language, the query editor, the facet
// rail, saved views and the command palette are the deterministic path and are
// complete without a model — which is why `seams.NullQuery` returning an error
// is the right null default here and a fabricated empty answer would not be.
type AskHandlers struct {
	seam    seams.Query
	assets  askAssetStore
	classes assetClassStore
	db      *sql.DB

	// rowLimit is how many rows the seam asks `query_assets` for. It is the
	// EVIDENCE and the context at once, so it is bounded by what a summary can
	// honestly be about rather than by what the list can return.
	rowLimit int
}

// askRequestBudget bounds ONE question, end to end.
//
// # Why the handler needs one at all
//
// The seam's own 30s timeout bounds one PROVIDER CALL, and a question can spend
// five of them plus three tool calls. Nothing else bounds the request: a gin
// handler runs to completion whether or not anyone is still listening, so a
// wedged provider would hold a goroutine, a database connection and the tenant's
// model budget long after the browser gave up.
//
// # Why this number, and what it is tied to
//
// It is deliberately far SHORTER than `seams.GenerativeWriteTimeout` — the
// API server's `WriteTimeout` (see cmd/main.go) — rather than sized just
// inside it. That ceiling exists to give the platform's slowest generative
// route (compliance-engine's author, a single 90s provider call) room to
// finish; this handler doesn't need anywhere near that much; it exists to cut
// a wedged `/ask` request off quickly, as a 503 with a sentence, well before a
// dropped connection with no body ever becomes possible. One provider call's
// own 30s timeout is the natural floor: past that, continuing to wait for a
// second or third call in the loop is not buying the reader anything they
// would call an answer.
//
// `TestAskRequestBudgetStaysWellUnderTheGenerativeWriteTimeout` asserts the
// inequality directly against `seams.GenerativeWriteTimeout` and fails if this
// ever grows to meet or exceed it.
const askRequestBudget = 30 * time.Second

// NewAskHandlers wires the endpoint.
//
// A null seam is a supported state, not a wiring error: it is what Core has and
// what an Enterprise build with AI_PROVIDER unset has. Both are answered for
// below, and both are tested, because "the UI hides the box" is a UI decision
// and the endpoint has to be right on its own.
func NewAskHandlers(seam seams.Query, assets askAssetStore, classes assetClassStore, rawDB *sql.DB, rowLimit int) *AskHandlers {
	if rawDB == nil {
		// Said out loud rather than never. Without a pool the tenant kill
		// switch is not consulted HERE — the boundary's second lock still reads
		// the stamp this code applies, so an unstamped context would leave the
		// switch unenforced on both locks, and a guard that cannot fire is
		// worse than no guard.
		log.Print("[ask] no database handle: the tenant AI kill switch will NOT be consulted")
	}
	return &AskHandlers{seam: seam, assets: assets, classes: classes, db: rawDB, rowLimit: rowLimit}
}

// askRequest is the body: one question, and nothing else.
//
// No filters, no scope, no row limit. Anything a caller could add here is
// something the query language already says, and a second way of saying it is
// how an agent learns the wrong one (ADR-0007 D2.4, the same reasoning that
// deleted the per-field filter arguments from the MCP tools).
type askRequest struct {
	Question string `json:"question"`
}

// askToolCall is one tool the answer was composed from, echoed so a reader can
// see what was consulted. The RESULT is not echoed — the rows are the evidence
// and they are returned in full under `rows`; repeating a facet payload beside
// them would double the response to say the same thing twice.
type askToolCall struct {
	Tool string         `json:"tool"`
	Args map[string]any `json:"args,omitempty"`
}

// askResponse is a 200.
type askResponse struct {
	// Query is the CANONICAL predicate that ran — the platform's own formatter's
	// output, including the default scope it AND-ed in. This is what the UI
	// shows, what "Open in Inventory" deep-links to, and what a user edits. It
	// is never the string the model wrote.
	Query string `json:"query"`

	// Rows are the assets the query selected, in the list endpoint's own row
	// shape, so a client renders them with the code it already has.
	Rows []any `json:"rows"`

	// Text is the summary, with `[row:<id>]` markers left IN. They are the
	// checkable part: a sentence stripped of its citation on the way to the
	// client is a sentence nobody can audit, and the client resolves each
	// marker against `rows` to link it.
	Text string `json:"text"`

	// Citations are DERIVED from Text rather than accumulated beside it, so the
	// prose cannot cite a row the list omits or list one it never mentions.
	Citations []seams.Citation `json:"citations"`

	// Tools is every tool call the answer was composed from, in order.
	Tools []askToolCall `json:"tools"`

	// Provenance is ADR-0008 D4.1 on the wire: what produced this, and that it
	// is inferred rather than measured. Confidence is 0 by design — we do not
	// ask a model to score itself — and the citations are the evidence instead.
	Provenance seams.Proposal `json:"provenance"`
}

// askRefusalResponse is a 422: a provider answered and what it wrote did not
// validate.
//
// It carries the validator's diagnostics in the SAME wire shape
// QUERY_LANGUAGE §10 fixes for a query typed by hand, because to the reader
// they are the same thing — the reason a predicate was refused, against a
// predicate now sitting in an editable box.
type askRefusalResponse struct {
	Error string `json:"error"`

	// Query is the model's last attempt, or absent when it produced none. It is
	// NOT the canonical query: it never reached the formatter. It goes back to
	// the person who asked, which is the one place it is not a disclosure.
	Query string `json:"query,omitempty"`

	// Errors are `{code, message, span:{start,end}, suggestion?}`.
	Errors []gin.H `json:"errors"`

	// Attempts distinguishes "failed twice" from "refused before asking".
	Attempts int `json:"attempts"`
}

// Ask answers one question.
//
// The order below is the design and is worth reading as a list:
//
//  1. tenant, then EDITION. "Your plan does not include this" is the more
//     useful message to lead with when it applies, and answering it before
//     touching the database means a Core deployment spends nothing on a route
//     it cannot serve.
//  2. the acting user. ai.WithAudit REFUSES a call naming no invoker, so
//     letting one through would spend the boundary's refusal on it and report a
//     provider that is fine as unavailable.
//  3. the tenant's own controls, read ONCE and used twice: the kill switch
//     answers here, and both controls are stamped on the context so the
//     boundary enforces the switch a second time and D4.7's question-recording
//     opt-in reaches the seam.
//  4. the question, bounded by the seam.
//  5. the seam, with a tool layer fixed to this tenant.
func (h *AskHandlers) Ask(c *gin.Context) {
	tenantID, ok := c.Get("tenantID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return
	}
	tenantUUID, ok := tenantID.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	if !aiedition.QueryLinked() {
		c.JSON(http.StatusPaymentRequired, gin.H{
			"error": "Asking questions in words is part of Vista Platform Enterprise. " +
				"The query language, the facet rail and saved views search the same inventory in every edition.",
		})
		return
	}

	userID, hasUser := sharedmw.GetUserIDFromContext(c)
	if !hasUser {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return
	}

	// The transport bound, BEFORE the decoder. seams.MaxQuestionBytes below is
	// the product rule and it is checked on a string the decoder has already
	// built — one step too late to bound what was allocated getting there. See
	// seams.MaxQuestionRequestBytes for why the two numbers differ.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, seams.MaxQuestionRequestBytes)

	var req askRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			// Answered as its own outcome rather than folded into "invalid
			// body": a malformed body is worth fixing and retrying, an over-cap
			// one will be over-cap again every time. The message names the
			// product cap, not this one, because that is the number the caller
			// has to get under.
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": fmt.Sprintf("That request is larger than this endpoint accepts. A question may be "+
					"at most %d characters.", seams.MaxQuestionBytes),
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	question := strings.TrimSpace(req.Question)
	if question == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ask a question."})
		return
	}
	// The cap the spec publishes, refused HERE rather than left to the seam.
	// The seam refuses too, but its ErrQuestionTooLarge is a plain error in an
	// Enterprise package: this file compiles in Core, cannot name it, and would
	// answer it 500 out of the default arm — a caller's mistake reported as a
	// server fault, which sends the wrong person to look. The bound itself is
	// seams.MaxQuestionBytes, which the seam's own constant is defined from, so
	// there is one number rather than two.
	if len(question) > seams.MaxQuestionBytes {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"That question is %d characters; the limit is %d. It is refused rather than shortened — "+
					"half a question answered confidently is worse than no answer, because nothing in the "+
					"reply would say it was half.", len(question), seams.MaxQuestionBytes),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), askRequestBudget)
	defer cancel()
	ctx = seams.WithInvoker(ctx, userID.String())
	ctx = auditmw.WithAIActor(ctx, tenantUUID, "tenant")

	if h.db != nil {
		controls, err := ai.TenantAIControls(ctx, h.db, tenantUUID)
		if err != nil {
			// Fail closed, like ai.TenantAllows: a settings read that did not
			// complete is not evidence the tenant said yes. The sentence names
			// the settings read rather than the model, because pointing a user
			// at the AI provider for a database problem wastes their afternoon.
			log.Printf("[ask] tenant AI controls unreadable for %s: %v", tenantUUID, err)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Your organization's AI assistant settings could not be read, so nothing was asked. Try again shortly.",
			})
			return
		}
		ctx = ai.WithTenantControls(ctx, controls)
		if controls.AssistantDisabled {
			// Told, not degraded. An empty answer here would read as "we looked
			// and found nothing", which is a claim about the inventory made
			// because of a setting.
			writeAssistantDisabled(c)
			return
		}
	}

	tools := newAskToolSet(tenantUUID, h.assets, h.classes, h.rowLimit)
	answer, err := h.seam.Answer(ctx, question, tools)
	if err != nil {
		h.writeAskError(c, err)
		return
	}

	rows, canonical := askRowsFrom(answer)
	c.JSON(http.StatusOK, askResponse{
		Query:      canonical,
		Rows:       rows,
		Text:       answer.Text,
		Citations:  askCitations(answer.Text),
		Tools:      askToolCalls(answer),
		Provenance: answer.Proposal,
	})
}

// writeAskError maps a seam failure onto a status.
func (h *AskHandlers) writeAskError(c *gin.Context, err error) {
	// The refusal FIRST, and by interface rather than by type: the
	// implementation is Enterprise and this file compiles in Core, so
	// `seams.GroundingRefusal` is the only way the diagnostics can be reached
	// from here. It is checked before ai.ErrUnavailable because it deliberately
	// does not wrap it — a provider answered, twice, and the validator said
	// exactly why.
	var refusal seams.GroundingRefusal
	if errors.As(err, &refusal) {
		c.JSON(http.StatusUnprocessableEntity, askRefusalResponse{
			Error: "That question could not be turned into a query this inventory understands. " +
				"The reasons below are the query language's own; edit the query and run it directly.",
			Query:    refusal.GroundingQuery(),
			Errors:   renderQueryErrors(refusal.GroundingDiagnostics()),
			Attempts: refusal.GroundingAttempts(),
		})
		return
	}

	switch {
	case errors.Is(err, ai.ErrTenantDisabled):
		// The boundary's second lock, reached when the call-site check above
		// could not run because there is no pool.
		writeAssistantDisabled(c)
	case errors.Is(err, context.DeadlineExceeded):
		// The per-request budget ran out. Said out loud, and as a 503 rather
		// than a 500: nothing is broken, the answer did not arrive in the time
		// the connection has, and asking something narrower is a move the
		// reader can make. Without this arm it would fall through to the
		// default and be reported as an internal error — a shrug for the one
		// failure with an obvious next step.
		log.Printf("[ask] the question exceeded the %s budget", askRequestBudget)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "That question took longer than this request can wait for. Try a narrower one, " +
				"or search the same inventory directly with the query language.",
		})
	case errors.Is(err, ai.ErrUnavailable):
		// The null seam, or a provider that will not answer. Deliberately 503
		// and not 402 — an operator can fix this one, and the two must not read
		// the same.
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "Asking questions in words is not available: this deployment has no AI provider configured. " +
				"The query language searches the same inventory without one.",
		})
	default:
		log.Printf("[ask] the query seam failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

// writeAssistantDisabled is the ONE place the tenant kill switch's 403 is
// written, for both of the locks that can fire it.
//
// It carries a machine-readable `reason` beside the sentence, and that is the
// load-bearing part. Several different things answer 403 on this route — a role
// without `assets.read`, a scope-narrowed API token, a missing CSRF token, a
// session that must change its password — and exactly ONE of them is an
// availability answer that a caller should stop retrying and report as
// "switched off". A caller that told them apart by looking for a word in the
// prose got it wrong the first time a message was worded differently, and got
// it wrong in the worst direction: `vistaplatform_ask` reported a token-scope
// refusal as "your organization has turned the assistant off", sending an
// operator to a settings page that was already correct.
//
// So the availability answer identifies itself and everything else is a real
// error. `LegacyError` permits sibling keys, and the OpenAPI 403 says this one
// is present only here.
func writeAssistantDisabled(c *gin.Context) {
	c.JSON(http.StatusForbidden, gin.H{
		"error":  "Your organization has turned the AI assistant off. A tenant administrator can turn it back on in Settings → AI assistant.",
		"reason": seams.ReasonAssistantDisabled,
	})
}

// askRowsFrom pulls the rows and the canonical query out of the answer's tool
// results.
//
// It reads the FIRST `query_assets` result and only that one: the seam's
// follow-up allowlist deliberately excludes a second `query_assets` call,
// because a second predicate is a second question and the answer would then be
// about a query the panel is not showing. Reading "the last one" would quietly
// undo that if the allowlist ever changed.
//
// A result this cannot read yields no rows and no canonical query, which the
// client renders as "the summary with no evidence" — visibly wrong — rather
// than as an empty inventory.
func askRowsFrom(answer seams.Answer) ([]any, string) {
	for _, res := range answer.ToolResults {
		if res.Tool != askToolQueryAssets {
			continue
		}
		top, ok := res.Result.(map[string]any)
		if !ok {
			return []any{}, ""
		}
		canonical, _ := top["query"].(string)
		rows, _ := top["assets"].([]any)
		if rows == nil {
			rows = []any{}
		}
		return rows, canonical
	}
	return []any{}, ""
}

// askCitations derives the citation list from the prose.
func askCitations(text string) []seams.Citation {
	out := seams.CollectCitations(seams.CitationKindRow, text)
	if out == nil {
		// An explicit empty array rather than null: a client that renders a
		// citation count should print 0, not crash on a null, and the schema
		// says the field is always present.
		return []seams.Citation{}
	}
	return out
}

// askToolCalls echoes what was consulted, without the payloads.
func askToolCalls(answer seams.Answer) []askToolCall {
	out := make([]askToolCall, 0, len(answer.ToolResults))
	for _, res := range answer.ToolResults {
		out = append(out, askToolCall{Tool: res.Tool, Args: res.Args})
	}
	return out
}
