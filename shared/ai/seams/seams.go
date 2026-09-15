// Package seams holds the eight AI seams of ADR-0008 D1 and their null
// defaults.
//
// A seam is three things: a Go interface, a registration point, and a default
// implementation that does nothing or does the rule-based thing. A deployment
// with no AI configured gets the null column of the ADR's table, the build does
// not change, and there is no `-tags ai`. That is what "AI-native, never
// AI-dependent" means in code — the call site exists everywhere, exercised by
// every deployment, and what varies is only what answers it.
//
// # The null defaults are not stubs
//
// Each one returns a documented, complete, honest answer meaning "I have no
// proposal": nil, or a value whose Unknown/Available flag says so. None of them
// guesses, and none of them returns a fabricated confident value. A caller that
// handles the null default correctly handles a real implementation correctly,
// which is the property that makes shipping the seam before the model safe.
//
// Note what is NOT here. The rule-based work the ADR lists in the "null /
// rule-based default" column — the identification engine's identifier rules,
// the existing drift detectors, the catalogue lookups, the rule-based narrative
// generator — lives in the services that own that data and keeps running
// whether or not a seam is configured. A null seam makes no proposal; it does
// not disable the deterministic path beside it.
//
// # What a seam may not do
//
// ADR-0008 D5 places AI deliberately outside four things: risk scoring,
// compliance evaluation, approval decisions, and signing. A seam may explain a
// risk score; it may not produce one. A seam proposes; a rule or a human
// approves.
package seams

import (
	"context"

	"github.com/vistasecurity/vistaplatform/shared/ai"
)

// ── Classical seams (in-process, no provider) ──────────────────────────────

// Matcher scores a candidate observation against existing assets: "are these
// three observations one asset?"
//
// It proposes; it never merges. ADR-0002 D5 forbids auto-merge on conflict and
// routes merge proposals through the Approvals queue.
type Matcher interface {
	Match(ctx context.Context, candidate Observation, existing []AssetSummary) ([]MatchScore, error)
}

// Classifier proposes what a thing is and what role it plays.
type Classifier interface {
	Classify(ctx context.Context, facts AssetFacts) (ClassProposal, error)
}

// DriftDetector looks across a population window for changes worth an alert.
type DriftDetector interface {
	Detect(ctx context.Context, window PopulationWindow) ([]Anomaly, error)
}

// ── Generative seams (cross the provider boundary) ─────────────────────────

// Enricher looks up facts about a class/vendor/model/version from outside the
// tenant's own data. Every fact it returns carries a source URL or it is not a
// fact (ADR-0008 D4.4).
type Enricher interface {
	Enrich(ctx context.Context, subject EnrichmentSubject) ([]Fact, error)
}

// Narrator summarises rows it is given, citing them.
type Narrator interface {
	Narrate(ctx context.Context, input NarrationInput) (Narrative, error)
}

// Query answers a natural-language question by calling the read-only,
// tenant-scoped tools and returning their results alongside the prose.
type Query interface {
	Answer(ctx context.Context, question string, tools ToolSet) (Answer, error)
}

// Author drafts compliance controls from standard text, always unpublished.
type Author interface {
	Draft(ctx context.Context, standardText string) ([]ControlDraft, error)
}

// Remediator drafts a remediation plan for a finding. It proposes steps; it
// never executes one.
type Remediator interface {
	Propose(ctx context.Context, finding FindingRef) (PlanDraft, error)
}

// ── Null defaults ──────────────────────────────────────────────────────────

// nullProvenance is what a null default's empty answer carries: no model id,
// because no model was involved, and a source_ref naming the producer — so a
// stored proposal can distinguish "the null classifier said unknown" from "a
// model said unknown", which are different facts about the deployment.
func nullProvenance(seam ai.Seam) Proposal {
	return NewProposal("", string(seam)+":"+ImplNone, 0)
}

// NullMatcher makes no proposals. The rule-based identification engine
// (shared/identity) is unaffected and still decides identity on its own; this
// seam is the place a learned scorer would ADD graded candidates, so its
// absence means exactly "no extra candidates".
type NullMatcher struct{}

// Match returns no candidates and no error. Returning nil, nil rather than an
// error matters: "I have no proposal" is a normal, expected outcome and a
// caller must not log it as a failure or surface it to a user.
func (NullMatcher) Match(context.Context, Observation, []AssetSummary) ([]MatchScore, error) {
	return nil, nil
}

// NullClassifier never guesses.
type NullClassifier struct{}

// Classify returns Unknown with an empty class and zero confidence.
//
// This is ADR-0008 D4.3 in one line: not assessed stays not assessed. The
// tempting alternative — returning the statistically most common class with a
// low confidence — is precisely the bug the 2026-08 audit found sixty times,
// and a decimal beside it does not make it a different bug.
func (NullClassifier) Classify(context.Context, AssetFacts) (ClassProposal, error) {
	return ClassProposal{
		Proposal: nullProvenance(ai.SeamClassifier),
		Class:    "",
		Unknown:  true,
	}, nil
}

// NullDriftDetector proposes no anomalies. The deterministic detectors (new
// asset, certificate expiry, stale asset) are elsewhere and keep firing.
type NullDriftDetector struct{}

// Detect returns no anomalies and no error.
func (NullDriftDetector) Detect(context.Context, PopulationWindow) ([]Anomaly, error) {
	return nil, nil
}

// NullEnricher adds no facts. Static catalogue lookups (EOL tables, CPE
// dictionary) are a separate, deterministic path and are unaffected.
type NullEnricher struct{}

// Enrich returns no facts and no error.
func (NullEnricher) Enrich(context.Context, EnrichmentSubject) ([]Fact, error) {
	return nil, nil
}

// NullNarrator produces no narrative.
type NullNarrator struct{}

// Narrate returns Narrative{Available: false}.
//
// Available false, rather than an empty string, is what lets the UI omit the
// panel entirely instead of rendering an empty one that reads as "we looked and
// there was nothing to say".
func (NullNarrator) Narrate(context.Context, NarrationInput) (Narrative, error) {
	return Narrative{Proposal: nullProvenance(ai.SeamNarrator), Available: false}, nil
}

// NullQuery cannot answer questions.
type NullQuery struct{}

// Answer returns ai.ErrUnavailable.
//
// Unlike the four seams above, this one returns an error rather than an empty
// value, because there is no honest empty answer to a question. The UI's job
// is to not offer the box at all when the seam is null — the facets, saved
// views and command palette are the deterministic path — and this error is the
// backstop for when it does anyway.
func (NullQuery) Answer(context.Context, string, ToolSet) (Answer, error) {
	return Answer{Proposal: nullProvenance(ai.SeamQuery)}, ai.ErrUnavailable
}

// NullAuthor drafts nothing; authoring is manual.
type NullAuthor struct{}

// Draft returns ai.ErrUnavailable.
func (NullAuthor) Draft(context.Context, string) ([]ControlDraft, error) {
	return nil, ai.ErrUnavailable
}

// NullRemediator proposes no plan. The finding's existing guidance text is the
// deterministic path and is unaffected.
type NullRemediator struct{}

// Propose returns ai.ErrUnavailable.
func (NullRemediator) Propose(context.Context, FindingRef) (PlanDraft, error) {
	return PlanDraft{Proposal: nullProvenance(ai.SeamRemediator)}, ai.ErrUnavailable
}

// Compile-time proof that every null default satisfies its seam. If an
// interface gains a method and a null default is not updated, this fails at
// build time rather than at the first call.
var (
	_ Matcher       = NullMatcher{}
	_ Classifier    = NullClassifier{}
	_ DriftDetector = NullDriftDetector{}
	_ Enricher      = NullEnricher{}
	_ Narrator      = NullNarrator{}
	_ Query         = NullQuery{}
	_ Author        = NullAuthor{}
	_ Remediator    = NullRemediator{}
)

// ── The invoker ────────────────────────────────────────────────────────────

// invokerKey carries the user id or rule name a generative call is made on
// behalf of.
//
// ADR-0008 D4.7 asks which user or rule invoked every generative call, and
// ai.WithAudit REFUSES a request that names none (ai.ErrUnattributed). None of
// the seam interfaces takes an invoker argument — they are shared by callers
// that have a user and callers that are a background rule — so the thing that
// varies per call travels on the context.
//
// # Why it lives in Core
//
// Because the CALLER is what sets it, and a caller can be Core. AI_SEAMS §12
// records what happens otherwise: the enricher's `WithInvoker` was exported
// from its Enterprise package, so the only code that could set it was that
// package, and the console-triggered runs it was written for had no way to call
// it. It had no caller at all, and every audit record carried the nightly rule
// name instead — a bug whose only symptom was in the audit trail.
//
// The remediator's caller is a Core handler by construction (the endpoint is
// mounted in every edition so Core can answer 402), so an Enterprise-owned key
// here would have been the same bug on the first day.
type invokerKey struct{}

// WithInvoker records who a generative call is being made for.
func WithInvoker(ctx context.Context, invoker string) context.Context {
	return context.WithValue(ctx, invokerKey{}, invoker)
}

// InvokerFrom returns the invoker stamped on ctx, or "".
//
// Empty is not an error here: it is what an unstamped context returns, and the
// place that turns it into a refusal is ai.WithAudit, which is the one door
// every generative call goes through. Refusing here as well would mean each
// seam deciding separately what an unattributed call is, which is how two of
// them would come to disagree.
func InvokerFrom(ctx context.Context) string {
	invoker, _ := ctx.Value(invokerKey{}).(string)
	return invoker
}
