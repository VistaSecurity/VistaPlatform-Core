package seams

import "time"

// Wire constants a CORE consumer of a generative seam needs.
//
// They live here for the same reason [GroundingRefusal] does: the seam
// implementations are Enterprise and the export deletes them, while the HTTP
// handlers in front of them are mounted in every edition and therefore compile
// in Core. A handler cannot name a constant declared in an `ee/` tree, so a
// value that BOTH the handler and the implementation have to agree on has to be
// declared where both can see it.

// MaxQuestionBytes is the largest question a query seam accepts, measured after
// trimming.
//
// # Why the caller enforces it too
//
// `shared/ai/ee/query` refuses past this bound rather than truncating — half a
// question translated confidently is worse than no answer, because nothing
// downstream can tell it was half. But its `ErrQuestionTooLarge` is a plain
// error in an Enterprise package: a Core-compiled handler can neither name it
// nor tell it apart from a wiring failure, so it would land in the handler's
// `default` arm and be answered 500. A caller's mistake reported as a server
// error sends the wrong person to look.
//
// So the bound is declared HERE, the seam's own constant is defined from it so
// the two cannot drift, and the HTTP surface refuses an over-long question
// itself with a 400 that names the cap. The seam keeps its own check: it is the
// backstop for a caller that does not have one.
const MaxQuestionBytes = 4096

// MaxQuestionRequestBytes is the TRANSPORT bound on a question's request body:
// what an http.MaxBytesReader in front of the JSON decoder allows.
//
// It is a different quantity from [MaxQuestionBytes] and both are needed.
// MaxQuestionBytes is the product rule — how long a question may be — and it is
// checked after the body has been decoded into a string, which is exactly one
// step too late to bound what the process allocated getting there. A caller can
// send a hundred megabytes of JSON whose `question` field is a single enormous
// string; the decoder builds that string before anything measures it.
//
// The multiple is the JSON escaping headroom. A byte of UTF-8 can render as
// `\u00XX` — six bytes — so a question at the product cap can legitimately
// arrive as six times its length, plus the envelope. Eight times plus a
// kilobyte leaves room for that and for whatever a future field adds, while
// still being three orders of magnitude below the edge's own 100 MiB.
//
// The direction matters: a LEGAL request must never trip this, because the
// error it produces (413, no body) says nothing a user can act on. The 400 that
// names the cap comes from MaxQuestionBytes, and this only catches the request
// that was never going to be answered anyway.
const MaxQuestionRequestBytes = MaxQuestionBytes*8 + 1024

// The bounds on a remediation plan, declared here for the reason
// [MaxQuestionBytes] is: the numbers were the Enterprise remediator's private
// constants, and they bound what a MODEL may propose. The ACCEPT endpoint — the
// one that writes a row — is in Core, cannot import that package, and bounded
// nothing at all: it took the steps from the client, rendered them into the plan
// item's notes and stored whatever arrived (security review X.5, X5-07).
//
// So the caps live at the seam both sides can name, and the endpoint is now the
// one enforcing them on the way in. A plan that is too long to have come from
// this platform's own drafter is refused rather than truncated: a truncated plan
// is a plan whose last step is missing, and nothing in the stored notes would
// say so.
const (
	// MaxPlanSteps caps a plan. A remediation plan a person is going to work
	// through is a handful of steps; twenty is a document, and a document gets
	// accepted unread.
	MaxPlanSteps = 12

	// MaxPlanStepBytes caps one step's action or rationale. A step longer than
	// this is a paragraph, and a paragraph in a numbered list is how a plan
	// stops being checkable.
	MaxPlanStepBytes = 600

	// MaxPlanSummaryBytes caps the sentence above the steps.
	MaxPlanSummaryBytes = 600
)

// GenerativeWriteTimeout is the `http.Server.WriteTimeout` that
// inventory-service, compliance-engine and cbom-service each configure on
// their API server — the mTLS branch and the plaintext-fallback branch alike
// — in `cmd/main.go`. It does not apply to the plaintext `/health` server
// those same services also run: that one answers a static JSON body, never
// calls a seam, and keeps its own short, independent timeout.
//
// # Why one constant, declared in Core, covers three services
//
// Every one of those API servers can reach a generative HTTP route: this
// package's own query seam (`/ask`), the remediator's `/remediation/draft`,
// the author's `/draft-controls` (both in compliance-engine), and the
// narrator inside cbom-service's `/cbom/compare`. Each of those seam
// implementations configures its own per-provider-call timeout, and they are
// not the same number: `shared/ai/ee/query` bounds one call at 30s,
// `shared/ai/ee/remediator` at 45s, `services/cbom-service/ee/diff` at 20s,
// and `services/compliance-engine/ee/author` — the slowest — at 90s. All four
// live in `ee/` trees that a Core file may not import, so none of their
// constants can be read from `cmd/main.go` directly, and three independent
// `cmd/main.go` files cannot see each other's number either. A single
// Core-visible ceiling, sized above the slowest of the four with room to
// spare, is the one thing all of them — and all three servers — can agree on
// without an import cycle.
//
// # Why this was a live bug, not a theoretical one
//
// Before this constant existed, all three servers hard-coded
// `WriteTimeout: 15 * time.Second`, well under even the FASTEST of those four
// per-call timeouts (cbom-service's 20s), let alone the author's 90s. A gin
// handler runs to completion regardless of whether the server is still
// listening, so a generative request that took its seam's own timeout to
// fail over to a rule-based answer still lost the response: past
// `WriteTimeout` the write fails and the client sees a dropped connection
// with no body — an answer composed at full model cost that nobody can read
// — instead of the seam's honest degraded answer or a readable error.
//
// # What derives from this, and what does not
//
// `askRequestBudget` (`services/inventory-service/internal/handlers`) is
// declared independently and stays far below this ceiling on purpose — it
// exists to cut off a wedged `/ask` request quickly, as a 503 with a
// sentence, long before this ceiling would ever matter to it. The two are
// tied together only by a test asserting `askRequestBudget` stays under this
// constant, the same relationship the pre-existing single-service version of
// that test enforced.
//
// The 90s figure this constant is built around, and each server's wiring to
// it, are each pinned by their own test: `shared/ai/ee/query`,
// `shared/ai/ee/remediator`, `services/compliance-engine/ee/author` and
// `services/cbom-service/ee/diff` each assert their own per-call timeout
// stays comfortably under this constant, and each service's `cmd` package has
// a test reading its real `main.go` source to confirm the API server (not the
// health server) is wired to `GenerativeWriteTimeout` rather than a
// hard-coded literal.
const GenerativeWriteTimeout = 120 * time.Second

// ReasonAssistantDisabled is the machine-readable `reason` an HTTP surface puts
// on the 403 it returns because THIS TENANT has switched the AI assistant off.
//
// # Why a key and not a sentence
//
// Several different 403s reach a generative endpoint — a role without the
// required permission, a scope-narrowed API token, a missing CSRF token, a
// session that must change its password — and exactly one of them is an
// availability answer. A client telling them apart by looking for a word in the
// prose gets it wrong the first time a message is reworded, and the failure is
// silent and in the wrong direction: `vistaplatform_ask` reported "your
// organization switched the assistant off" for a token-scope refusal, which
// sends an operator to a settings page that is already correct.
//
// So the availability answer identifies ITSELF, positively, with a key that is
// not prose. Anything else is a real error, which is the safe default: a real
// error carries the platform's own sentence and does not claim to know why.
const ReasonAssistantDisabled = "assistant_disabled"
