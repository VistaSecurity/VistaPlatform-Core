package seams

import (
	"context"
	"time"
)

// SourceKindInferred is the only source_kind a seam implementation may produce.
//
// ADR-0005 defines the vocabulary — measured, imported, declared, inferred —
// and ADR-0008 D4.1 requires every AI-derived value to carry it along with a
// confidence and a model id. The distinction is the whole posture: a fact an AI
// inferred is not a fact something measured, and the 2026-08 bug audit found
// sixty instances of one shape, "did not check" rendered as "passed". Model
// output is that hazard in a new coat.
const SourceKindInferred = "inferred"

// The rest of the ADR-0005 source_kind vocabulary. A seam cannot produce a
// measured value, but its rule-based default can repeat one it READ — see
// [NewLookupProposal] — and a caller writing that through needs the names.
const (
	SourceKindMeasured = "measured"
	SourceKindImported = "imported"
	SourceKindDeclared = "declared"
)

// Proposal is embedded in every seam output that carries an inferred value.
//
// It does two jobs. It carries the provenance ADR-0008 D4.1 demands — all four
// of it, as FIELDS, so it survives serialisation — and it marks the value as a
// PROPOSAL: ADR-0008 D3 says AI output lands in the same pending state a
// discovered fact lands in and is admitted by the same approval path. A caller
// must not write one of these into a facts table as though something had
// measured it.
//
// Build one with [NewProposal]. A struct literal can leave SourceKind empty,
// and a proposal whose serialised form does not say "inferred" is exactly the
// claim this type exists to prevent.
type Proposal struct {
	// SourceKind is always [SourceKindInferred]. It is a field and not a method
	// because D4.1 is about what a stored or transmitted fact CARRIES: as a
	// method it vanished from every json.Marshal, so a proposal crossing a
	// service boundary or landing in a jsonb column arrived indistinguishable
	// from a measured fact.
	SourceKind string `json:"source_kind"`

	// SourceRef identifies the producer — "classifier:onnx-v1",
	// "narrator:none". D4.1 requires it alongside source_kind, and it is what
	// answers "which thing said this" when two implementations of the same seam
	// have run against the same tenant over time.
	SourceRef string `json:"source_ref"`

	// Confidence is the implementation's own estimate, 0..1. A null default
	// leaves it 0 — which is honest, because it made no claim.
	Confidence float64 `json:"confidence"`

	// ModelID identifies what produced the value, so a later "why does the
	// inventory say this" has an answer that names a version. Empty for a null
	// default: no model was involved, and "" is not a model called unknown.
	ModelID string `json:"model_id"`
}

// NewProposal builds the provenance for one inferred value. SourceKind is set
// for you and cannot be anything else: a seam cannot produce a measured fact,
// so there is nothing to parameterise.
func NewProposal(modelID, sourceRef string, confidence float64) Proposal {
	return Proposal{
		SourceKind: SourceKindInferred,
		SourceRef:  sourceRef,
		ModelID:    modelID,
		Confidence: confidence,
	}
}

// NewLookupProposal builds the provenance for a value a seam's RULE-BASED or
// CATALOGUE-LOOKUP implementation read rather than inferred.
//
// It is the one way to get a [Proposal] whose SourceKind is not "inferred", and
// it exists because ADR-0008 D1 gives several seams a null/rule-based default
// that produces real values: the enricher's "static catalogue lookups", the
// matcher's deterministic identifier rules. A date copied out of
// `eol_catalogue`, with that row's id as its source_ref, is an IMPORTED fact and
// saying "inferred" would understate its provenance as badly as the reverse
// overstates — the honesty rule cuts both ways.
//
// There is no model and no estimate, so ModelID stays empty and Confidence
// stays 0: "" is not a model called unknown, and a lookup made no estimate.
// sourceKind must be one of the ADR-0005 vocabulary — measured, imported,
// declared — and anything else, including "inferred", is refused into
// [SourceKindInferred]'s own constructor territory and normalised to "imported"
// rather than stored as a fifth value nothing reports on. Use [NewProposal] for
// anything a model produced.
func NewLookupProposal(sourceKind, sourceRef string) Proposal {
	switch sourceKind {
	case SourceKindMeasured, SourceKindImported, SourceKindDeclared:
	default:
		sourceKind = SourceKindImported
	}
	return Proposal{SourceKind: sourceKind, SourceRef: sourceRef}
}

// Provenance returns the provenance carried by a seam output. It is promoted
// from the embedded Proposal, which is why every seam output has it.
func (p Proposal) Provenance() Proposal {
	if p.SourceKind == "" {
		// A literal-built Proposal still READS as inferred. This cannot fix the
		// JSON — MarshalJSON on an embedded struct would swallow the outer
		// type's own fields, which is worse — so it is a backstop, not the
		// mechanism. The mechanism is NewProposal.
		p.SourceKind = SourceKindInferred
	}
	return p
}

// proposal is the unexported marker. Its job is NOT to be a barrier — see
// [Proposed].
func (p Proposal) proposal() Proposal { return p }

// Proposed is satisfied by every seam output carrying an inferred value. A
// function that accepts a Proposed is stating that it handles approval, not
// persistence.
//
// # What the unexported method does and does not do
//
// Go promotes the methods of an embedded field, including unexported ones. So
// any type, in any package, satisfies Proposed by embedding [Proposal] — and
// that is the INTENDED mechanism, not a hole in a barrier. It is the same
// pattern as gRPC's mustEmbedUnimplemented: the unexported method makes
// embedding the only way in, and embedding is what drags the provenance fields
// along with it. A type cannot claim to be a proposal without carrying
// source_kind, source_ref, confidence and model_id.
//
// What it does NOT do is enforce ADR-0008 D4.2, "inferred never overwrites
// measured". Nothing in this package implements D4.2: it is a rule about a
// WRITE against an existing value, and it is enforced at the facts layer in
// phase 3, where the existing value's source_kind can be compared. Until then
// D4.2 is a rule people follow, and this marker is not evidence that anything
// checks it.
type Proposed interface {
	Provenance() Proposal
	proposal() Proposal
}

// ProposalOf returns the provenance carried by any seam output.
func ProposalOf(p Proposed) Proposal { return p.Provenance() }

// ── Matcher ────────────────────────────────────────────────────────────────

// Observation is one sighting of something that may or may not already be an
// asset: a discovery row, a cloud resource, an imported spreadsheet line.
//
// Identifiers is the map the rule-based identification engine keys on (serial,
// cloud id, MAC, FQDN, …). A matcher is asked to say which existing assets
// this might be, not to decide.
type Observation struct {
	Kind        string            `json:"kind"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
	Attributes  map[string]any    `json:"attributes,omitempty"`
	ObservedAt  time.Time         `json:"observed_at"`

	// Name is what a person would call this thing — the display name, else the
	// hostname. It is not identity (Identifiers is), and a matcher compares it
	// for SIMILARITY rather than equality.
	Name string `json:"name,omitempty"`

	// Segment is the network segment the observation was made in, empty when
	// unknown. It is the scope a `hostname` or `ip_address` identifier
	// identifies within (ADR-0002 D3), so two sides agreeing on a hostname and
	// disagreeing about the segment are very probably two things: every segment
	// has a `db01`.
	Segment string `json:"segment,omitempty"`

	// SourceKind is the ADR-0005 provenance of the observation — one of
	// [SourceKindMeasured], [SourceKindImported], [SourceKindDeclared].
	SourceKind string `json:"source_kind,omitempty"`
}

// AssetSummary is the thin view of an existing asset a matcher compares
// against. Deliberately not the full asset: a seam gets what it needs to score
// a candidate, not the tenant's inventory.
type AssetSummary struct {
	ID          string            `json:"id"`
	Class       string            `json:"class"`
	Name        string            `json:"name"`
	Identifiers map[string]string `json:"identifiers,omitempty"`

	// Attributes are the few class attributes worth COMPARING across a pair —
	// `vendor` and `model` today. Deliberately not the asset's whole attribute
	// map: a seam gets what it needs to score a candidate, not the tenant's
	// inventory, and the matcher's feature extractor is an allowlist on top of
	// this one.
	Attributes map[string]any `json:"attributes,omitempty"`

	// Segment is the asset's network segment, and the counterpart of
	// [Observation.Segment].
	Segment string `json:"segment,omitempty"`

	// SourceKind is the provenance that supplied this asset's identifiers.
	SourceKind string `json:"source_kind,omitempty"`

	// Status is the asset's approval status (`monitoring`,
	// `pending_approval`, …).
	//
	// A matcher MUST NOT read it: where an asset sits in the approval queue
	// says nothing about whether it is the same physical thing, and a model
	// that learned to favour approved assets would be laundering an approval
	// decision into an identity one. It is here because the engine's
	// auto-accept guard needs it — it refuses to merge into anything not yet
	// admitted to inventory — and carrying it on the summary saves a second
	// read of rows already in hand.
	Status string `json:"status,omitempty"`

	// LastSeenAt is when the asset was last observed. Zero means unknown, which
	// is not the epoch.
	LastSeenAt time.Time `json:"last_seen_at,omitzero"`
}

// MatchFactor is one feature's signed contribution to a [MatchScore].
//
// ADR-0008 D4 makes a score a proposal with provenance, and a proposal a human
// is asked to act on has to be reviewable. A number alone is not: the reviewer
// can only agree with it. These are what the number is MADE of.
//
// A factor names a comparison, never a value. "a one-per-asset identifier
// matches" is the evidence; the serial itself is on the proposal's
// matched-identifier list, where the reviewer is already looking at it.
type MatchFactor struct {
	// Feature is the implementation's stable name for the signal.
	Feature string `json:"feature"`
	// Label is the phrase the UI shows.
	Label string `json:"label"`
	// Value is what was measured, 0..1.
	Value float64 `json:"value"`
	// Weight is the model's signed weight for the feature.
	Weight float64 `json:"weight"`
	// Contribution is Value × Weight — how much this signal moved THIS score,
	// which is not how much the model cares about the signal in general.
	Contribution float64 `json:"contribution"`
}

// MatchScore is one candidate pairing. Reason is the human-readable phrase the
// approval queue shows the reviewer — "same serial, different FQDN" — because a
// score with no reason cannot be reviewed, only rubber-stamped.
type MatchScore struct {
	Proposal
	AssetID string  `json:"asset_id"`
	Score   float64 `json:"score"`
	Reason  string  `json:"reason"`
	// Explanation is the score's working, strongest signal first. Empty from an
	// implementation that cannot explain itself — which is a reason to prefer
	// one that can (ADR-0008 D2 picks the classical family partly for this).
	Explanation []MatchFactor `json:"explanation,omitempty"`
}

// ── Classifier ─────────────────────────────────────────────────────────────

// AssetFacts is what is known about a thing at classification time: its
// identifiers plus whatever the collectors saw (banners, open ports, vendor
// strings, cloud tags).
type AssetFacts struct {
	Identifiers map[string]string `json:"identifiers,omitempty"`
	Facts       map[string]any    `json:"facts,omitempty"`
}

// ClassProposal is a proposed class and role.
//
// Unknown is not a convenience flag, it is rule 3 of ADR-0008 D4: "A model may
// not turn a NULL into a pass. A classifier that returns 'unknown' is recorded
// as unknown, not as the most likely class." Unknown true with an empty Class
// is a complete, valid answer and callers must handle it as one.
type ClassProposal struct {
	Proposal
	Class   string `json:"class"`
	Role    string `json:"role,omitempty"`
	Unknown bool   `json:"unknown"`
}

// ── DriftDetector ──────────────────────────────────────────────────────────

// PopulationWindow is the slice of a tenant's asset population to examine.
type PopulationWindow struct {
	TenantID string    `json:"tenant_id"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
}

// Anomaly is something that changed and might matter. It goes onto the alert
// rail as a proposal, alongside the deterministic detectors (new asset, cert
// expiry, stale) which keep running unchanged.
type Anomaly struct {
	Proposal
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Summary string `json:"summary"`
}

// ── Enricher ───────────────────────────────────────────────────────────────

// EnrichmentSubject is the thing to look up: a class, vendor, model and
// version, with no tenant data in it.
type EnrichmentSubject struct {
	Class   string `json:"class"`
	Vendor  string `json:"vendor,omitempty"`
	Model   string `json:"model,omitempty"`
	Version string `json:"version,omitempty"`
}

// Fact is one enriched attribute — an end-of-life date, a CPE, a known
// advisory.
//
// SourceURL is required, not decorative: ADR-0008 D4.4 says enrichment facts
// carry a source URL and output without a citation is commentary, never
// persisted as a fact. An implementation that cannot cite must return nothing.
type Fact struct {
	Proposal
	Key       string `json:"key"`
	Value     any    `json:"value"`
	SourceURL string `json:"source_url"`
}

// ── Narrator ───────────────────────────────────────────────────────────────

// NarrationInput is the rows to summarise. The narrator summarises what it is
// given; it does not go and fetch more.
type NarrationInput struct {
	Subject string           `json:"subject"`
	Rows    []map[string]any `json:"rows,omitempty"`
}

// Citation points at the row, tool call, or passage a statement came from.
type Citation struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`

	// Text is the passage Ref names, when Ref points into something the CALLER
	// supplied rather than at a row the caller already holds.
	//
	// The narrator's citations name diff rows the client fetched in the same
	// response, so it can resolve `[row:r3]` itself and Text stays empty. The
	// author's cite a byte span of text the user pasted into a box; carrying
	// the resolved span means the reviewer sees the sentence a draft came from
	// beside the draft, and that a stored citation stays checkable after the
	// paste is gone. It is filled by the implementation from ITS OWN copy of
	// the source, never by the model — a model that could write the quoted text
	// could write a quotation that is not in the document.
	Text string `json:"text,omitempty"`
}

// Narrative is generated prose.
//
// Available false is the null default's answer and means "there is no narrative
// here", which the UI renders as the absence of a panel — not as an empty one,
// and not as an error. A narrative with no Citations is commentary (D4.4).
type Narrative struct {
	Proposal
	Available bool       `json:"available"`
	Text      string     `json:"text,omitempty"`
	Citations []Citation `json:"citations,omitempty"`
}

// ── Query ──────────────────────────────────────────────────────────────────

// ToolSet is the read-only, tenant-scoped tool layer a query seam is allowed to
// call. ADR-0008 D6: the query seam never touches the database — it calls the
// MCP tools, which run under the caller's RLS, so a model cannot see a row the
// user cannot. Tenant isolation is this interface's, not the seam's.
type ToolSet interface {
	Names() []string
	Call(ctx context.Context, name string, args map[string]any) (any, error)
}

// ToolResult is one tool call and what it returned, carried back alongside the
// prose so the UI can show the evidence (D4.4: cite or refuse).
type ToolResult struct {
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args,omitempty"`
	Result any            `json:"result"`
}

// Answer is a response to a natural-language question: the tool results plus
// the prose that summarises them, in that order of authority.
type Answer struct {
	Proposal
	Text        string       `json:"text"`
	ToolResults []ToolResult `json:"tool_results,omitempty"`
}

// ── Author ─────────────────────────────────────────────────────────────────

// MeasurementDraft is one drafted measurement rule on a drafted control: which
// measurement the control checks, how, and against what.
//
// The measurement is named by CODE, not by id. A code is stable vocabulary an
// implementation can put in a prompt and check an answer against; a uuid is a
// per-deployment row id a model can only guess at, and a guessed uuid that
// happens to parse would attach the rule to whichever measurement type owns it.
// The consumer resolves the code to an id against the same catalogue it sent.
//
// RuleType and Predicate are the existing typed-predicate vocabulary
// (threshold / presence / pattern / range), unchanged — an author seam that
// invented a fifth would be drafting something no engine evaluates.
type MeasurementDraft struct {
	MeasurementTypeCode string         `json:"measurement_type_code"`
	RuleType            string         `json:"rule_type"`
	Predicate           map[string]any `json:"predicate"`
}

// ControlDraft is a drafted compliance control: an UNPUBLISHED proposal for one
// control and the measurement rules it would evaluate, cited back to the
// passage of the standard it was drafted from.
//
// Published is always false. ADR-0008 D5 keeps compliance evaluation free of
// models: the author seam drafts predicates, the engine evaluates them, and a
// human publishes them.
//
// Citations is not optional in spirit even though it is in the struct tag —
// D4.4 is cite or refuse, and an implementation drops a draft it cannot cite
// rather than returning one with an empty list. A ControlDraft arriving here
// with no citation therefore means the implementation is broken, and a consumer
// is right to refuse it.
type ControlDraft struct {
	Proposal

	// ControlID is the identifier the standard itself uses ("4.2.1"), suggested
	// rather than assigned: the author renames it if their framework numbers
	// controls differently.
	ControlID string `json:"control_id,omitempty"`

	Title       string `json:"title"`
	Description string `json:"description,omitempty"`

	// Severity is the control's baseline severity in the existing vocabulary
	// (Low / Med / High / Critical).
	Severity string `json:"severity,omitempty"`

	// Citations are the passages of the source text this draft came from.
	Citations []Citation `json:"citations,omitempty"`

	// Measurements are the drafted rules. It may legitimately be empty — a
	// standard often states a requirement no catalogued measurement can express
	// — and when it is, Notes says so. An empty Measurements is a control that
	// evaluates nothing, which is "not assessed", not "passes".
	Measurements []MeasurementDraft `json:"measurements,omitempty"`

	// Notes are plain-language remarks for the reviewer: a predicate that was
	// dropped and why, a control with nothing to measure. They are addressed to
	// a human and nothing parses them.
	Notes []string `json:"notes,omitempty"`

	Published bool `json:"published"`
}

// ── Remediator ─────────────────────────────────────────────────────────────

// FindingRef is the finding a plan is wanted for, projected onto an allowlist.
//
// # Why this carries content, when it used to carry only two ids
//
// It said "the seam is given a reference, not the finding's contents, so the
// implementation fetches through the tool layer and stays under RLS". That was
// written before there was an implementation, and it does not survive contact
// with one: the remediator lives in shared/ai/ee/remediator, which has no
// database handle, no tenant context, and no tool layer for findings — the
// query seam's ToolSet is about assets. A seam that "fetched" would have had to
// be handed a pool, which is exactly the platform-runtime coupling ADR-0008
// D4.6 keeps out of this layer.
//
// So the CALLER resolves the finding — it is a request handler, it already
// holds the row under RLS, and RLS is the isolation — and projects it onto the
// fields below. That is the same shape as the narrator, which is handed
// projected diff rows rather than a comparison id, and for the same two
// reasons: the projection IS the boundary allowlist (D4.5), and a reviewer can
// read one struct to know what leaves the building.
//
// Everything here crosses the provider boundary. Nothing that is not here does.
// In particular there is no identifier beyond [FindingRef.SubjectLabel] — no
// asset id, no hostname, no address, no serial — because a remediation step
// does not need to name the host to say what to do to it, and the label is
// already what a person sees on the finding.
type FindingRef struct {
	// FindingID and TenantID are for attribution and audit. They are NOT sent
	// to a provider: the implementation records the finding id on its audit
	// record (D4.7) and keeps both out of the prompt.
	FindingID string `json:"finding_id"`
	TenantID  string `json:"tenant_id"`

	// Producer and Kind identify what judged this and what it judged, from the
	// findings registry (standards/findings-registry.yaml).
	Producer string `json:"producer"`
	Kind     string `json:"kind"`

	// Severity is the finding's own severity, in the findings vocabulary.
	Severity string `json:"severity,omitempty"`

	// SubjectType is what the finding is about — asset, certificate,
	// crypto_configuration, … — and SubjectLabel is the display name the tenant
	// already sees on it. The label is the only identifier that crosses.
	SubjectType  string `json:"subject_type,omitempty"`
	SubjectLabel string `json:"subject_label,omitempty"`

	// Summary is the finding's one-line summary, as rendered for the tenant.
	Summary string `json:"summary,omitempty"`

	// Guidance is the registry's remediation guidance for this KIND
	// (findings.Kind.Guidance). It is the deterministic answer — what a
	// deployment with no model configured returns — and it is also what the
	// model is asked to make specific. An implementation handed an empty
	// Guidance has nothing to degrade to, which is why the endpoint resolves it
	// before calling rather than leaving the seam to.
	Guidance string `json:"guidance,omitempty"`

	// Evidence is the finding's `evidence` jsonb: the measurements that made
	// the judgement. It is the only free-shaped thing here, so it is the one
	// the redactor earns its keep on — it goes into Request.Context, where
	// shared/redact walks it by field name.
	//
	// Its KEYS are the citation vocabulary: a drafted step cites the evidence
	// it relies on as [ev:<key>], and a key that is not in this map does not
	// resolve (see [EvidenceRefsIn]).
	Evidence map[string]any `json:"evidence,omitempty"`

	// Subject is the small, allowlisted description of the thing the finding is
	// about — enough for a step to name the right vendor's command, and no more.
	Subject SubjectContext `json:"subject,omitzero"`
}

// SubjectContext is the allowlisted context about a finding's subject that may
// cross the provider boundary.
//
// It is an explicit struct and not a map, deliberately: "project it onto an
// explicit allowlist of the fields something actually reads" is the collection
// rule (CLAUDE.md, "Collect posture, never key material"), and a struct with
// json tags discards an unknown field structurally rather than by someone
// remembering to. What it buys is a step that says "on a Palo Alto running
// PAN-OS 10.1" rather than "on your device", which is the difference between a
// plan and a paragraph.
//
// Deliberately absent: hostnames, addresses, serials, cloud ids, tags,
// descriptions, owners. A vendor and a model name a product; a serial names a
// thing.
type SubjectContext struct {
	// ClassKey is the asset class — "network.firewall", "server.linux" — from
	// the class registry.
	ClassKey string `json:"class_key,omitempty"`

	// OSName and OSVersion are the `os.name` / `os.version` facts.
	OSName    string `json:"os_name,omitempty"`
	OSVersion string `json:"os_version,omitempty"`

	// HWVendor and HWModel are the `hw.vendor` / `hw.model` facts.
	HWVendor string `json:"hw_vendor,omitempty"`
	HWModel  string `json:"hw_model,omitempty"`

	// Configuration is a one-line summary of the cryptographic configuration a
	// crypto-subject finding is about — protocol version, cipher suite, key
	// exchange, signature — assembled by the caller from the catalogue-linked
	// components. A summary of the configuration row, never the row.
	Configuration string `json:"configuration,omitempty"`
}

// PlanStep is one action in a remediation plan.
//
// A step is a claim plus its evidence, which is why Citations sits on the step
// rather than on the draft: dropping an uncited step leaves the cited ones
// standing, and a reader checking one step does not have to work out which part
// of a draft-level citation list belongs to it.
type PlanStep struct {
	Order     int    `json:"order"`
	Action    string `json:"action"`
	Rationale string `json:"rationale,omitempty"`

	// Citations are what this step rests on: the evidence keys it used, and the
	// registry guidance where it is restating that. DERIVED from the step's own
	// text by [CollectPlanCitations], never accumulated beside it, so the text
	// and the list cannot disagree.
	Citations []Citation `json:"citations,omitempty"`

	// Manual marks a step that names a command, a configuration change, or any
	// other action taken against a system. Every such step is manual, because
	// this seam executes nothing (ADR-0008 D1: "proposes, never executes") — the
	// flag is not a per-step policy decision, it is the UI telling a reader that
	// the platform will not be doing this for them.
	//
	// A step with Manual false asks a person to check, confirm or decide
	// something. Those are not safer; they are just not changes.
	Manual bool `json:"manual"`
}

// Sources a [PlanDraft] can come from.
const (
	// PlanSourceGuidance is the deterministic answer: the findings registry's
	// guidance for the kind, verbatim. It is what a deployment with no model
	// configured returns, what every failure degrades to, and what a UI labels
	// "the standard guidance".
	PlanSourceGuidance = "guidance"

	// PlanSourceModel is a drafted plan.
	PlanSourceModel = "model"
)

// Why a draft came back as [PlanSourceGuidance] rather than as a plan.
//
// A closed set, because "how often does this degrade, and to what" is the first
// question anyone asks of a capability that degrades — and a free-text reason
// cannot be counted. It is also what a UI says out loud: "the model could not
// cite anything" and "this deployment has no model provider" send a reader to
// two different places, and one sentence for both sends most of them to the
// wrong one.
//
// Empty on a model draft. Never invented: an implementation that cannot say
// which of these happened has a bug, not a fifth reason.
const (
	// PlanReasonNoProvider — no model is configured or reachable. The operator's
	// problem, not the reader's.
	PlanReasonNoProvider = "no_provider"

	// PlanReasonProviderError — a provider was asked and did not answer: an
	// outage, a rate limit, a rejected credential, a timeout.
	PlanReasonProviderError = "provider_error"

	// PlanReasonRefused — the model declined to answer. The tokens were spent
	// and there is nothing to show; deliberately not folded into
	// PlanReasonProviderError, because nothing is broken.
	PlanReasonRefused = "refused"

	// PlanReasonUnreadable — the model answered with something that could not be
	// read as a plan. Distinct from "it drafted no steps", which is a claim
	// about the finding that we did not make.
	PlanReasonUnreadable = "unreadable"

	// PlanReasonNoCitedSteps — the model answered and every step it wrote was
	// discarded for citing nothing, or for citing evidence the finding does not
	// have. The honest report is "it could not show its working", not an empty
	// plan.
	PlanReasonNoCitedSteps = "no_cited_steps"
)

// PlanDraft is a proposed remediation plan. "Proposes, never executes"
// (ADR-0008 D1): there is no field here that anything acts on automatically.
//
// The two Sources are not two qualities of one thing. A guidance draft has no
// steps and asserts nothing about this finding in particular; a model draft has
// steps, each cited. A consumer that rendered them identically would be telling
// a user that a paragraph of generic advice was a plan written about their
// device.
type PlanDraft struct {
	Proposal

	// Source is [PlanSourceGuidance] or [PlanSourceModel]. On the wire so a UI
	// can label the panel from the response rather than from remembering which
	// button it pressed — the same reason the CBOM narrative carries one.
	Source string `json:"source"`

	// Summary is the plan in a sentence or two for a model draft, and the
	// registry guidance verbatim for a guidance draft.
	Summary string `json:"summary"`

	// Steps is empty for a guidance draft, and that is a complete answer rather
	// than a failure: "here is what this kind of finding means and what it
	// generally takes" is what the product does without a model, and ADR-0008
	// promises that is not a degraded experience.
	Steps []PlanStep `json:"steps,omitempty"`

	// Reason is one of the PlanReason constants on a guidance draft, and empty
	// on a model draft. It is on the wire because "no model here" and "the model
	// could not show its working" are different facts with different fixes, and
	// a UI given one sentence for both tells most readers the wrong thing.
	Reason string `json:"reason,omitempty"`

	// Dropped counts the steps discarded for failing citation validation.
	//
	// A count rather than a list: unlike the author seam — where a reviewer
	// accepts controls one at a time, so what was dropped is work they can see
	// is missing — a plan is accepted whole, and the discarded steps are by
	// definition the ones with nothing behind them. What a reader needs is that
	// there WERE some, which changes how hard they read the rest.
	Dropped int `json:"dropped,omitempty"`

	// Truncated reports that the model hit its output limit, so the plan stops
	// early. A cut-off plan reads exactly like a short one.
	Truncated bool `json:"truncated,omitempty"`
}
