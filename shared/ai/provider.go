// Package ai is the provider boundary: the one place a prompt leaves this
// process, and the vocabulary every AI seam shares.
//
// The product is AI-native and never AI-dependent (ADR-0008). Every AI
// capability sits behind a seam in shared/ai/seams with a null default, and
// every generative seam reaches a model through the [Provider] interface
// defined here. A deployment that configures nothing gets [NoneProvider],
// which is not a stub that pretends: it reports Available() == false and
// returns [ErrUnavailable], so a caller must decide what to do without a model
// rather than receive a fabricated answer.
//
// # The boundary rule
//
// A prompt is an exfiltration path, and unlike a leak into our own database it
// leaves no trace on the system that owned the secret. ADR-0008 D4.5: every
// prompt and every tool result crossing this boundary passes through
// shared/redact, the same redactor the interrogators use.
//
// That rule is enforced structurally rather than by convention. [Request] has
// an unexported sanitized flag that only [Redact] can set — no caller can forge
// it — and every Provider in this package refuses a request without it,
// NoneProvider included, so a caller who forgot the boundary fails in
// development, where AI_PROVIDER is none, instead of the first time an operator
// configures a real model.
//
// The intended wiring is one call:
//
//	p, err := ai.NewFromEnv()          // none unless AI_PROVIDER says otherwise
//	p = ai.Boundary(p, sink)           // redaction outside, audit inside
//
// [Boundary] composes the two decorators in the only order that works.
// Redaction is OUTERMOST, so audit sees — and hashes — exactly the request it
// forwards to the provider (ADR-0008 D4.7). Wrapped the other way round,
// ai.WithAudit(ai.WithRedaction(p), sink), audit would hash the request it was
// handed while redaction forwarded a scrubbed copy downstream: the recorded
// digest would be of text that was never sent, and two prompts differing only
// in a secret would record as different prompts. That order no longer merely
// misreports — [WithAudit] refuses an unsanitized request outright, so it fails
// loudly, on the first call, in every deployment.
//
// This package deliberately contains no model client. The Anthropic and
// OpenAI-compatible implementations live in shared/ai/ee/providers and
// register here through [RegisterProvider]; they are Enterprise by ADR-0008's
// edition placement, so a Core build has the seam, the vocabulary and the
// boundary, and no way to reach a model. [NewFromEnv] says so out loud rather
// than resolving to something that fails later.
package ai

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Seam names the AI capability a request belongs to. It is recorded on every
// audit event so an operator can answer "what is this deployment sending to a
// model, and on whose behalf" per capability, not just in aggregate.
type Seam string

// The eight seams of ADR-0008 D1. The first three are classical (in-process,
// no provider); the last five are generative and cross this boundary.
const (
	SeamMatcher       Seam = "matcher"
	SeamClassifier    Seam = "classifier"
	SeamDriftDetector Seam = "drift_detector"
	SeamEnricher      Seam = "enricher"
	SeamNarrator      Seam = "narrator"
	SeamQuery         Seam = "query"
	SeamAuthor        Seam = "author"
	SeamRemediator    Seam = "remediator"
)

// allSeams is the canonical order: the three classical seams, then the five
// generative ones. It is the single list — [AllSeams], [Seam.Valid] and the
// seams registry's slot table all derive from it, so a ninth seam is added in
// one place or not at all.
var allSeams = []Seam{
	SeamMatcher, SeamClassifier, SeamDriftDetector,
	SeamEnricher, SeamNarrator, SeamQuery, SeamAuthor, SeamRemediator,
}

// AllSeams returns the eight seams of ADR-0008 D1, classical first. The slice
// is a copy; mutating it changes nothing.
func AllSeams() []Seam { return append([]Seam(nil), allSeams...) }

// Valid reports whether s is one of the eight. An audit record whose seam is
// something else cannot answer "what is this deployment sending, per
// capability", which is the question D4.7 exists to answer.
func (s Seam) Valid() bool {
	for _, known := range allSeams {
		if s == known {
			return true
		}
	}
	return false
}

// ProviderNone is the name of the provider a deployment gets when it has
// configured nothing. It is a real, selectable value, not a zero value.
const ProviderNone = "none"

var (
	// ErrUnavailable is returned when no model is configured, or the configured
	// one cannot be reached. Callers treat it as "answer without a model" — the
	// null seam behaviour — never as a failure to report to the user as an error
	// in the underlying data.
	ErrUnavailable = errors.New("ai: no provider available")

	// ErrNotSanitized is returned when a request reaches a provider without
	// having passed through WithRedaction. It is a programming error, not a
	// runtime condition, and it is deliberately louder than ErrUnavailable: the
	// boundary being skipped is the bug that matters even when nothing would
	// have been sent.
	ErrNotSanitized = errors.New("ai: request did not pass the redaction boundary")

	// ErrUnattributed is returned by WithAudit for a request that does not name
	// a known seam and an invoker. ADR-0008 D4.7 requires the audit event to say
	// "which user or rule invoked it"; a record with an empty invoker answers
	// the question with a blank, which is worse than refusing because it looks
	// like an answer. The refusal is itself audited.
	ErrUnattributed = errors.New("ai: request does not say which seam and which invoker it is for")

	// ErrUnknownProvider is returned by NewFromEnv when AI_PROVIDER names
	// something this build does not have. NewFromEnv still returns NoneProvider
	// alongside it, so a caller that logs and continues degrades to no-AI rather
	// than to a nil interface.
	ErrUnknownProvider = errors.New("ai: unknown provider")

	// ErrProviderUnavailable is returned when a provider IS configured but its
	// endpoint could not answer: a 5xx, an overloaded signal, a refused
	// connection, a timeout — after the retries are spent.
	//
	// It WRAPS ErrUnavailable on purpose. A caller asking "can I answer without
	// a model?" gets the same yes it gets when nothing is configured, because
	// the honest answer in both cases is that there is no model output. A
	// caller that wants to tell an outage from an empty configuration — the
	// Settings page's `configured_unavailable` state — tests for this error
	// specifically.
	ErrProviderUnavailable = fmt.Errorf("ai: the configured provider could not be reached: %w", ErrUnavailable)

	// ErrUnauthorized is returned when the provider rejected our credential:
	// 401, 403, or 402 (a billing problem is the provider declining to serve
	// this account, which the operator fixes the same way — by looking at the
	// account).
	//
	// It deliberately does NOT wrap ErrUnavailable. An outage resolves itself;
	// a bad key does not, and a seam that quietly degrades to no-AI on a 401
	// would leave an operator staring at a capability they paid for and turned
	// on, with nothing anywhere saying why it never answers.
	ErrUnauthorized = errors.New("ai: provider rejected the credential")

	// ErrRateLimited is returned when the provider is throttling us. Callers
	// that need the wait use errors.As with [*RateLimitError]; callers that
	// only need the category use errors.Is with this.
	ErrRateLimited = errors.New("ai: provider rate limited the request")

	// ErrInvalidResponse is returned when the endpoint answered with something
	// this client cannot read: a non-JSON body, JSON in an unexpected shape, or
	// a body past the size cap. It is separate from ErrProviderUnavailable
	// because "it answered with garbage" and "it did not answer" are different
	// facts, and pointing an operator at the wrong one wastes their afternoon.
	// Usually it means BaseURL points at something that is not a model API.
	ErrInvalidResponse = errors.New("ai: provider returned a response this client cannot read")

	// ErrRefused is returned when the model itself declined to answer. The call
	// succeeded, the tokens were spent, and there is no output.
	//
	// It is an error rather than an empty Response because an empty string
	// reads exactly like a short answer. This is the house shape — "did not
	// answer" must not render as "answered with nothing" — and it is the reason
	// a refusal is not silently flattened into Response.Text.
	ErrRefused = errors.New("ai: the model declined to answer")

	// ErrTenantDisabled is returned by WithAudit for a request made on behalf
	// of a tenant that has turned the AI assistant off (Settings → AI
	// assistant). The refusal is audited like the other two, because a
	// deployment still trying to make generative calls for a tenant that said
	// no is exactly the thing an operator would want to see.
	//
	// It WRAPS ErrUnavailable, for the reason ErrProviderUnavailable does: a
	// seam asking "can I answer without a model?" gets the same yes it gets for
	// an unconfigured deployment, so every existing degradation path — the
	// narrator's fallback to rules, the author's 503 — already handles it
	// without knowing the switch exists. A caller that wants to tell "your
	// organization turned this off" from "no provider is configured" — which is
	// what the user needs to be told, since one of them they can fix — tests
	// for this error specifically.
	ErrTenantDisabled = fmt.Errorf("ai: the tenant has turned the AI assistant off: %w", ErrUnavailable)
)

// RateLimitError carries what a 429 told us. Get at it with errors.As.
type RateLimitError struct {
	// Provider is the provider name, for a log line that says who throttled us.
	Provider string

	// RetryAfter is how long the provider asked us to wait. It is only
	// meaningful when RetryAfterKnown is true.
	RetryAfter time.Duration

	// RetryAfterKnown reports whether the response actually carried a
	// Retry-After header.
	//
	// A separate bool rather than "zero means unknown", because zero is a
	// legitimate value meaning "retry immediately", and collapsing the two
	// would turn "the provider did not say" into "the provider said go now" —
	// the not-assessed-rendered-as-assessed bug, in a retry loop.
	RetryAfterKnown bool

	// Detail is the provider's message, with any credential scrubbed out.
	Detail string
}

// Error implements error.
func (e *RateLimitError) Error() string {
	wait := "no Retry-After given"
	if e.RetryAfterKnown {
		wait = "retry after " + e.RetryAfter.String()
	}
	if e.Detail == "" {
		return fmt.Sprintf("ai: %s rate limited the request (%s)", e.Provider, wait)
	}
	return fmt.Sprintf("ai: %s rate limited the request (%s): %s", e.Provider, wait, e.Detail)
}

// Unwrap makes errors.Is(err, ErrRateLimited) true for every rate-limit error,
// so a caller that only cares about the category needs no type assertion.
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// Message is one turn of a prompt. Role is "user" or "assistant"; the system
// prompt lives on the Request rather than in this list.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request is everything crossing the provider boundary.
//
// Note what is NOT here: no tenant id, and no database handle. ADR-0008 D6
// puts tenant isolation in the tool layer — a generative seam calls the MCP
// tools, which run under the caller's RLS, and passes their results in as
// Context. A model cannot see a row the user cannot, because the model never
// sees the database at all.
type Request struct {
	// Seam is which capability is asking. Recorded in the audit event.
	Seam Seam `json:"seam"`

	// Model optionally pins a model id; empty means the provider's default.
	Model string `json:"model,omitempty"`

	// System is the system prompt.
	System string `json:"system,omitempty"`

	// Messages is the conversation.
	Messages []Message `json:"messages,omitempty"`

	// Context is structured grounding data — tool results, rows, catalogue
	// entries — kept separate from the prose so it can be redacted by field
	// name rather than by scanning text. Prefer putting facts here.
	Context []map[string]any `json:"context,omitempty"`

	// MaxTokens caps the response. Zero means the provider's default.
	MaxTokens int `json:"max_tokens,omitempty"`

	// Invoker is the user id or rule name on whose behalf the call is made.
	// Recorded in the audit event (ADR-0008 D4.7).
	Invoker string `json:"invoker,omitempty"`

	// sanitized reports that this request has passed through [Redact].
	//
	// Unexported, and with no json tag, deliberately. It was an exported bool
	// once, which meant any caller — and every test in this package — could
	// write `Sanitized: true` and satisfy the boundary without going anywhere
	// near the redactor. A flag a caller can forge is not a structural
	// guarantee, it is a comment with a type. [Redact] is the only thing that
	// sets it, and the absence of a json tag stops a request that round-trips
	// through JSON from arriving pre-blessed.
	sanitized bool
}

// IsSanitized reports whether this request has been through [Redact].
//
// Providers check it and refuse a request without it. There is deliberately no
// setter: the only way to hold a sanitized Request is to have been handed one
// by [Redact].
func (r Request) IsSanitized() bool { return r.sanitized }

// cloneRequest returns a deep copy: Messages and Context get their own backing
// storage, and Context's maps are copied recursively.
//
// A shallow copy shares that storage, so a caller mutating the map it passed in
// would retroactively change what a recorded request says was sent — the audit
// trail lying about history, in the one place built to stop that.
func cloneRequest(r Request) Request {
	out := r
	if r.Messages != nil {
		out.Messages = append([]Message(nil), r.Messages...)
	}
	if r.Context != nil {
		out.Context = make([]map[string]any, len(r.Context))
		for i, c := range r.Context {
			out.Context[i] = cloneMap(c)
		}
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

// cloneValue copies the container types a decoded-JSON context can hold. A
// scalar is immutable enough to share; a container this does not know about is
// returned as-is rather than reflected over, which is the same bounded choice
// redact.Any makes.
func cloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(typed))
		for i, item := range typed {
			out[i] = cloneMap(item)
		}
		return out
	case []string:
		return append([]string(nil), typed...)
	default:
		return v
	}
}

// Response is what came back.
type Response struct {
	// Text is the model's output. It is commentary until something cites a row
	// (ADR-0008 D4.4): a seam that turns this into a stored fact without a
	// citation is violating the honesty rules.
	Text string `json:"text"`

	// ModelID identifies what produced it and is carried onto every inferred
	// value the seam derives from it (ADR-0008 D4.1).
	ModelID string `json:"model_id"`

	// InputTokens and OutputTokens are 0 for providers that do not meter.
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`

	// Truncated reports that the model hit the token cap mid-answer rather
	// than finishing. The text is real — it is genuinely what the model said —
	// but it stops in the middle, and a cut-off paragraph reads like a complete
	// one. A seam that persists or cites this output has to know.
	Truncated bool `json:"truncated,omitempty"`
}

// Provider is a model endpoint. Implementations are registered by phase-4
// work; this package ships only NoneProvider and MockProvider.
type Provider interface {
	// Name is the configuration name — "none", "anthropic", "openai-compatible".
	Name() string

	// Complete runs one completion.
	Complete(ctx context.Context, req Request) (Response, error)

	// Available reports whether a call could succeed. A UI asks this to decide
	// whether to offer an AI affordance at all, rather than offering one that
	// always errors.
	Available() bool
}

// NoneProvider is the default: no model, and it says so.
//
// It exists so the seam is present in every deployment — Core, air-gapped, and
// the developer's laptop — and so the code path that would call a model is
// exercised everywhere rather than only where one is configured.
type NoneProvider struct{}

// Name returns ProviderNone.
func (NoneProvider) Name() string { return ProviderNone }

// Available always reports false. There is no model here and pretending
// otherwise is the "did not check rendered as passed" bug in a new coat.
func (NoneProvider) Available() bool { return false }

// Complete always fails. It checks the redaction boundary FIRST, before the
// unavailability it is certain of, because a caller that skipped WithRedaction
// has a bug that will only bite when a real provider is configured — and every
// developer runs with AI_PROVIDER=none. This is the cheapest place to catch it.
func (NoneProvider) Complete(_ context.Context, req Request) (Response, error) {
	if !req.IsSanitized() {
		return Response{}, ErrNotSanitized
	}
	return Response{}, ErrUnavailable
}

// MockProvider is a canned-response provider for tests. It records every
// request it receives so a test can assert what crossed the boundary.
type MockProvider struct {
	// ProviderName overrides the reported name; defaults to "mock".
	ProviderName string

	// Responses are returned in order; the last one repeats once exhausted.
	Responses []Response

	// Err, when set, is returned instead of a response.
	Err error

	// Unavailable makes Available() report false without changing Complete.
	Unavailable bool

	mu       sync.Mutex
	requests []Request
	calls    int
}

// Name returns ProviderName, or "mock".
func (m *MockProvider) Name() string {
	if m.ProviderName != "" {
		return m.ProviderName
	}
	return "mock"
}

// Available reports true unless Unavailable is set.
func (m *MockProvider) Available() bool { return !m.Unavailable }

// Complete records the request and returns the next canned response. Like
// every provider here it refuses an unsanitized request, so a test that omits
// WithRedaction fails rather than quietly proving nothing.
func (m *MockProvider) Complete(_ context.Context, req Request) (Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, cloneRequest(req))
	m.calls++

	if !req.IsSanitized() {
		return Response{}, ErrNotSanitized
	}
	if m.Err != nil {
		return Response{}, m.Err
	}
	if len(m.Responses) == 0 {
		return Response{ModelID: "mock-model"}, nil
	}
	i := m.calls - 1
	if i >= len(m.Responses) {
		i = len(m.Responses) - 1
	}
	return m.Responses[i], nil
}

// Requests returns a deep copy of every request the mock received, in order.
// Deep, because a slice header is not a copy: a caller that mutated the
// Messages or Context it passed in could otherwise change what the mock says it
// received, after the fact.
func (m *MockProvider) Requests() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, len(m.requests))
	for i, r := range m.requests {
		out[i] = cloneRequest(r)
	}
	return out
}

// LastRequest returns a deep copy of the most recent request, and false if
// there was none.
func (m *MockProvider) LastRequest() (Request, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		return Request{}, false
	}
	return cloneRequest(m.requests[len(m.requests)-1]), true
}

// NewFromEnv lives in registry.go, beside the registration hook it consults.
