package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// AuditRecord is one generative call, as ADR-0008 D4.7 requires it to be
// recorded: "seam, provider, model id, prompt hash, tokens, and which user or
// rule invoked it. Prompts themselves are not stored unless the tenant opts
// in."
//
// The hash rather than the prompt is the whole point. It answers the questions
// an operator actually has — was this call made, how often, by whom, was it
// the same prompt as last time — without turning the audit trail into a second
// copy of everything the platform knows about a tenant, sitting in a table
// with different retention rules from the one it was copied out of.
type AuditRecord struct {
	At           time.Time `json:"at"`
	Seam         Seam      `json:"seam"`
	Provider     string    `json:"provider"`
	ModelID      string    `json:"model_id"`
	PromptSHA256 string    `json:"prompt_sha256"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	Invoker      string    `json:"invoker"`

	// Refused is true when the boundary itself rejected the call — the request
	// had not been redacted, or it named no seam and no invoker — and nothing
	// was forwarded to a provider.
	//
	// A refusal is recorded rather than dropped because the attempt is the
	// interesting event: a service that keeps trying to send unsanitized
	// prompts is a bug that only shows up here. Refused calls are the one case
	// where PromptSHA256 may be empty (see below).
	Refused bool `json:"refused,omitempty"`

	// Err is the error text when the call failed, empty otherwise. A failed
	// call is still a call that was attempted, and an audit trail that records
	// only successes cannot answer "what did this deployment try to send".
	Err string `json:"error,omitempty"`

	// Attributes are facts about the call that only the SEAM knows, recorded
	// alongside the boundary's own fields.
	//
	// A seam that runs several provider calls to answer one question — the
	// grounded query seam translates, then narrates — writes one record of its
	// own carrying what the per-call records cannot say: which query it ended
	// up running, how many tools it called, whether it refused.
	//
	// The rule for what may go here is D4.7's: prompts are not stored unless
	// the tenant opts in. A platform-derived artefact — a canonical query the
	// formatter produced, a count, an outcome — is not a prompt and belongs
	// here unconditionally. The user's own text belongs here only behind that
	// opt-in.
	//
	// [WithAudit] sets exactly ONE key, [AuditAttrPrompt], and only when the
	// tenant has opted in ([RecordQuestionsAllowed]). That is the opt-in
	// implemented at the boundary rather than once per seam, so a seam added
	// tomorrow neither has to remember it nor can get it wrong. Everything else
	// in this map came from a seam.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// AuditAttrPrompt is the [AuditRecord.Attributes] key [WithAudit] writes the
// prompt under when the tenant has opted in to question recording (D4.7).
//
// It is the REDACTED prompt: audit sits inside redaction, so the text recorded
// here is byte-for-byte the text the provider received, secrets already
// replaced. Recording the unredacted form would put in the audit trail exactly
// what the boundary exists to keep out of a provider.
const AuditAttrPrompt = "prompt"

// MaxAuditedPromptBytes caps what [AuditAttrPrompt] carries.
//
// The prompt is stored in `audit.activity_logs`, a table read by people and
// kept under its own retention policy; an unbounded copy of every prompt a
// deployment sends would make it a second store of the tenant's data with
// different rules from the first. A cut prompt is marked with
// [auditedPromptTruncatedMarker] so a reader is never shown a fragment that
// looks like the whole thing.
const MaxAuditedPromptBytes = 4096

const auditedPromptTruncatedMarker = "\n…[truncated]"

// AuditSink receives one record per provider call. Implementations write to
// the audit service, a log, or a test buffer.
//
// Record must not return an error: an audit sink that can fail a completion
// would make the audit trail a source of outages, and one that silently
// swallows its own failures is the "check that cannot fail" hazard. Sinks log
// their own write failures.
type AuditSink interface {
	Record(ctx context.Context, rec AuditRecord)
}

// SinkFunc adapts a function to AuditSink.
type SinkFunc func(ctx context.Context, rec AuditRecord)

// Record calls f.
func (f SinkFunc) Record(ctx context.Context, rec AuditRecord) { f(ctx, rec) }

// WithAudit returns p wrapped so every call emits exactly one AuditRecord,
// whether it succeeded, failed, or was refused. A nil sink returns p unchanged;
// a nil provider becomes [NoneProvider], because a decorator that panics on
// first use is a worse answer than one that degrades to no-AI.
//
// # Audit goes INSIDE redaction
//
// Use [Boundary], which wires it that way. This decorator hashes exactly the
// request it forwards, and it REFUSES a request that has not been through
// [Redact] — [ErrNotSanitized], with an audit record marked Refused so the
// attempt is visible.
//
// That refusal is what makes the ordering structural rather than advisory. The
// tempting composition, WithAudit(WithRedaction(p), sink), reads correctly and
// is wrong: WithRedaction forwards a scrubbed COPY downstream, so audit would
// hash the request it was handed — the unredacted one. The digest would be of
// text that was never sent, and two prompts differing only in a secret value
// would hash differently, which is the opposite of what the hash is for. Now it
// simply fails, on the first call, everywhere.
//
// It also refuses a request that does not name one of the eight seams and an
// invoker ([ErrUnattributed]): D4.7 wants to know which user or rule invoked
// the call, and an empty string is not an answer to that.
//
// # The tenant kill switch is enforced here too
//
// A third refusal: a request whose context carries tenant controls with
// AssistantDisabled set is refused with [ErrTenantDisabled] and recorded, and
// nothing is forwarded. The primary enforcement is at the call site, which
// answers the user with its deterministic path instead of a failure — but this
// is the one place EVERY generative call passes through, so a seam whose caller
// stamped the context cannot send a prompt for a tenant that turned the
// assistant off, whatever its own code forgot. Same shape as the providers
// re-checking `req.IsSanitized()` after [Boundary] already guaranteed it.
//
// An unstamped context is not a refusal. Absence of a stamp is absence of a
// recorded decision, not a decision — a platform-scope call (a platform admin
// drafting into the shared catalogue, the nightly catalogue gap pass) has no
// tenant to consult, and failing closed on it would turn "nobody asked" into
// "somebody said no". That is why the call-site check is the primary one and
// this is the second lock.
func WithAudit(p Provider, sink AuditSink) Provider {
	if p == nil {
		p = NoneProvider{}
	}
	if sink == nil {
		return p
	}
	return auditingProvider{inner: p, sink: sink, now: time.Now}
}

// Boundary wraps p with redaction and audit, in the one order that records what
// was actually sent: redaction outermost, audit inside it.
//
//	provider = ai.Boundary(provider, sink)
//
// A nil provider degrades to [NoneProvider]; a nil sink means no audit trail
// (and is not what a deployment that sends prompts anywhere should run with).
func Boundary(p Provider, sink AuditSink) Provider {
	return WithRedaction(WithAudit(p, sink))
}

type auditingProvider struct {
	inner Provider
	sink  AuditSink
	now   func() time.Time
}

func (a auditingProvider) Name() string    { return a.inner.Name() }
func (a auditingProvider) Available() bool { return a.inner.Available() }

func (a auditingProvider) Complete(ctx context.Context, req Request) (Response, error) {
	// Both refusals come before the call, and both are recorded. The hash this
	// decorator writes is the hash of the request it forwards, so a request it
	// will not forward is the one case that has no prompt digest to record.
	if !req.IsSanitized() {
		a.refuse(ctx, req, ErrNotSanitized)
		return Response{}, ErrNotSanitized
	}
	if err := checkAttribution(req); err != nil {
		a.refuse(ctx, req, err)
		return Response{}, err
	}
	if TenantControlsFrom(ctx).AssistantDisabled {
		a.refuse(ctx, req, ErrTenantDisabled)
		return Response{}, ErrTenantDisabled
	}

	resp, err := a.inner.Complete(ctx, req)

	rec := AuditRecord{
		At:           a.now(),
		Seam:         req.Seam,
		Provider:     a.inner.Name(),
		ModelID:      resp.ModelID,
		PromptSHA256: PromptHash(req),
		InputTokens:  resp.InputTokens,
		OutputTokens: resp.OutputTokens,
		Invoker:      req.Invoker,
	}
	if rec.ModelID == "" {
		// A provider that failed before choosing a model still has a requested
		// one worth recording. Empty stays empty rather than becoming "unknown":
		// "we did not record it" and "the model is named unknown" are different
		// facts and the audit trail keeps them different.
		rec.ModelID = req.Model
	}
	if err != nil {
		rec.Err = err.Error()
	}
	rec.Attributes = promptAttribute(ctx, req)
	a.sink.Record(ctx, rec)

	return resp, err
}

// promptAttribute returns the Attributes map carrying the prompt, or nil.
//
// nil rather than an empty map so the field stays absent from the serialised
// record — "no attributes" and "an empty attributes object" read differently to
// every consumer, and this one means the first.
func promptAttribute(ctx context.Context, req Request) map[string]string {
	if !RecordQuestionsAllowed(ctx) {
		return nil
	}
	return map[string]string{AuditAttrPrompt: auditedPrompt(req)}
}

// auditedPrompt renders the turns of a request for the audit trail, bounded.
//
// The MESSAGES only. The system prompt is ours — constant per seam, already in
// the repository, and recording a copy of it on every call would bury the one
// part that varies. Request.Context is grounding data: rows the platform
// selected and already holds, unbounded, and not what a person typed. What D4.7
// means by "the prompt" on a surface where a user asks a question is the
// question, and that is a message.
func auditedPrompt(req Request) string {
	var b strings.Builder
	for i, m := range req.Messages {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(m.Role)
		b.WriteString(": ")
		b.WriteString(m.Content)
		if b.Len() > MaxAuditedPromptBytes {
			break
		}
	}
	out := b.String()
	if len(out) <= MaxAuditedPromptBytes {
		return out
	}
	// Cut on a rune boundary: activity_logs is read by people and a half
	// character is a corruption a reader would report as one.
	cut := MaxAuditedPromptBytes
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return out[:cut] + auditedPromptTruncatedMarker
}

// checkAttribution enforces D4.7's "which user or rule invoked it". An
// unrecognised seam is rejected alongside an empty invoker: both make the
// record unable to answer the question it exists for, and a typo'd seam name
// would quietly create a ninth bucket nothing ever reports on.
func checkAttribution(req Request) error {
	if !req.Seam.Valid() {
		return fmt.Errorf("%w: seam %q is not one of the eight", ErrUnattributed, req.Seam)
	}
	if strings.TrimSpace(req.Invoker) == "" {
		return fmt.Errorf("%w: seam %q named no invoker", ErrUnattributed, req.Seam)
	}
	return nil
}

// refuse records an attempt that never reached a provider.
func (a auditingProvider) refuse(ctx context.Context, req Request, cause error) {
	rec := AuditRecord{
		At:       a.now(),
		Seam:     req.Seam,
		Provider: a.inner.Name(),
		ModelID:  req.Model,
		Invoker:  req.Invoker,
		Refused:  true,
		Err:      cause.Error(),
	}
	// The digest is only ever taken of text that has been through the redactor.
	// Hashing a request refused FOR not being sanitized would put a digest of
	// raw, secret-bearing prompt text in the audit trail — the exact thing the
	// ordering rule exists to prevent — so that record carries no hash at all.
	// Empty here means "we did not record it", which is a different fact from
	// any digest we could invent, and the trail keeps them different.
	if req.IsSanitized() {
		rec.PromptSHA256 = PromptHash(req)
		// Same guard, same reason: the opt-in permits recording the text that
		// crossed the boundary, and a request refused FOR not having crossed it
		// has no such text. A refusal the tenant opted into seeing (the kill
		// switch, an unattributed call) still carries its prompt.
		rec.Attributes = promptAttribute(ctx, req)
	}
	a.sink.Record(ctx, rec)
}

// PromptHash is the stable SHA-256 of everything in req that forms the prompt:
// the seam, the model, the system prompt, each message, and the grounding
// context. Field lengths are hashed alongside the fields so that moving a
// boundary between two adjacent strings changes the digest — without them,
// System "ab" + message "c" and System "a" + message "bc" would collide.
//
// It is deterministic across processes and releases: same prompt, same digest,
// so an operator can see the same question being asked a thousand times.
// Request.Context maps are hashed through their sorted keys for the same
// reason — Go's map iteration order is randomised per run, and a digest that
// changed on every call would record nothing at all.
func PromptHash(req Request) string {
	h := sha256.New()

	writeField(h, string(req.Seam))
	writeField(h, req.Model)
	writeField(h, req.System)

	writeLen(h, len(req.Messages))
	for _, m := range req.Messages {
		writeField(h, m.Role)
		writeField(h, m.Content)
	}

	writeLen(h, len(req.Context))
	for _, c := range req.Context {
		hashMap(h, c)
	}

	return hex.EncodeToString(h.Sum(nil))
}
