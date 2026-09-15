package ai

import (
	"context"
	"regexp"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// WithRedaction returns p wrapped so that every request is scrubbed before it
// reaches the provider, and marked sanitized so the provider will accept it.
//
// Prefer [Boundary], which composes this with [WithAudit] in the only order
// that records what was actually sent.
//
// ADR-0008 D4.5, verbatim: "Every prompt and every tool result crossing the
// provider boundary passes through deviceinterrogation.Sanitize (or its
// generalised successor), the same redactor the interrogators use. Key
// material, credentials, and the fields that redactor names cannot reach a
// model."
//
// Three passes, because a prompt has three shapes and only one of them has
// field names:
//
//  1. Request.Context — structured grounding data. Walked by shared/redact,
//     name-based, exactly as an interrogation result is. This is the path
//     callers should prefer: it is the one with real field names to judge.
//  2. PEM private-key blocks anywhere in any string, redacted by shape. That
//     rule lives in shared/redact.TextPEM and applies to every string leaf of
//     the Context as well as to the prose, because a pasted key has no field
//     name to catch it by and Context is the path callers are told to prefer.
//  3. The prose key/value rule — `name: value`, `name = value`,
//     `"name": "value"` — judged by the same predicate, redact.IsSecretName.
//     This is the shape a prompt takes when someone formats a row into a
//     sentence. It runs over System, the messages, AND every string leaf of
//     the Context: a row rendered to a string before it was put in the context
//     map has prose inside a structured field, and pass 1 cannot see into it.
//
// Pass 3 over-redacts by design: a sentence containing "the password: field"
// loses the rest of the line. At this boundary that is the correct direction to
// be wrong in, and what stops it from eating the question being asked is
// redact.IsSecretName — partly the crypto-posture allowlist (key_size,
// public_key, host_key_type, …), and mostly the fact that ordinary posture
// names like cipher_suite and authmethod match no secret fragment at all.
// (redact.IsMustNotRedact("cipher_suite") is false: it is not on the allowlist,
// it simply never looked secret.)
//
// A nil provider becomes [NoneProvider]. Degrading to no-AI beats panicking on
// first use at whichever call site wired it; note that only a nil INTERFACE is
// caught here, not a nil concrete pointer stored in one.
func WithRedaction(p Provider) Provider {
	if p == nil {
		p = NoneProvider{}
	}
	return redactingProvider{inner: p}
}

type redactingProvider struct {
	inner Provider
}

func (r redactingProvider) Name() string    { return r.inner.Name() }
func (r redactingProvider) Available() bool { return r.inner.Available() }

func (r redactingProvider) Complete(ctx context.Context, req Request) (Response, error) {
	return r.inner.Complete(ctx, Redact(req))
}

// Redact returns a scrubbed copy of req, marked sanitized. WithRedaction
// applies it; it is exported so a caller assembling a prompt can scrub early
// and assert on the result in a test.
//
// The input is not mutated: callers may still hold the unredacted context for
// their own (already tenant-scoped, already authorised) purposes.
func Redact(req Request) Request {
	out := req
	out.System = redactText(req.System)

	if req.Messages != nil {
		out.Messages = make([]Message, len(req.Messages))
		for i, m := range req.Messages {
			out.Messages[i] = Message{Role: m.Role, Content: redactText(m.Content)}
		}
	}
	if req.Context != nil {
		out.Context = make([]map[string]any, len(req.Context))
		for i, c := range req.Context {
			// Name-based first (redact.Map, which also masks PEM blocks in
			// every string it walks), then the prose rule over what survived.
			// Context was only ever name-scrubbed, while the docs tell callers
			// to PREFER putting facts here — so a row rendered to a string
			// ("admin_password: hunter2" as one value of an innocent key) went
			// out in clear down the path we recommend.
			out.Context[i], _ = redactProse(redact.Map(c)).(map[string]any)
		}
	}

	out.sanitized = true
	return out
}

// redactProse applies the prose key/value rule to every string leaf of an
// already name-scrubbed value. The containers it walks are the ones redact.Any
// walks, for the same reason: enumerated, not reflected over.
func redactProse(v any) any {
	switch typed := v.(type) {
	case string:
		return redactText(typed)
	case map[string]any:
		if typed == nil {
			return nil // a nil map stays nil rather than becoming an empty one
		}
		out := make(map[string]any, len(typed))
		for k, item := range typed {
			out[k] = redactProse(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactProse(item)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(typed))
		for i, item := range typed {
			out[i], _ = redactProse(item).(map[string]any)
		}
		return out
	case []string:
		out := make([]string, len(typed))
		for i, item := range typed {
			out[i] = redactText(item)
		}
		return out
	default:
		return v
	}
}

// fieldNameSeparator matches a field NAME and the separator after it — and
// deliberately NOTHING of the value: `name:`, `name =`, `"name":`.
//
// Matching the name alone is the whole fix for the hole this rule used to have.
// The old pattern matched name AND value in one go, with the unquoted
// alternative running `[^,}\]\n\r]*` to the next delimiter. On a
// space-separated line —
//
//	cipher_suite: TLS_AES_256_GCM_SHA384 key_size: 2048 admin_password: hunter2
//
// — the first, innocent pair swallowed the rest of the line as its "value", the
// regex engine resumed past the end of it, and `admin_password: hunter2` was
// never evaluated at all: the secret crossed the boundary in clear. Same for an
// unquoted nested object, `{"config": {"password": "x"}, "key_size": 2048}`.
//
// Because a non-secret name now consumes nothing, the scan cannot skip a later
// secret one. A pair is only consumed when its name is secret.
//
// The optional closing quote covers both `"name":` and `'name':`; the value's
// own quoting is judged separately, by markerFor.
var fieldNameSeparator = regexp.MustCompile(`([A-Za-z0-9_.\-]{1,64})["']?\s*[:=]\s*`)

// nextPairStart finds where a following `name:` pair begins, so an unquoted
// value ends at the next field rather than eating it.
var nextPairStart = regexp.MustCompile(`\s["']?[A-Za-z0-9_.\-]{1,64}["']?\s*[:=]`)

// valueTerminators end an unquoted value even without a following pair.
const valueTerminators = ",}]\n\r"

// redactText scrubs PEM private keys and secret-looking key/value pairs out of
// free text.
func redactText(s string) string {
	if s == "" {
		return s
	}

	s = redact.TextPEM(s)

	matches := fieldNameSeparator.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}

	var b strings.Builder
	cursor := 0 // everything before this has been written out
	for _, m := range matches {
		nameStart, afterSeparator := m[0], m[1]
		if nameStart < cursor {
			// Inside a value we already consumed and replaced. A secret value
			// that itself looks like `a: b` must not be partially rewritten.
			continue
		}
		if !redact.IsSecretName(s[m[2]:m[3]]) {
			continue
		}
		value := s[afterSeparator:]
		if n := markerExtent(value); n > 0 {
			// Already redacted by an earlier pass. Copy the marker through
			// untouched instead of re-marking it.
			//
			// Without this, redaction is not idempotent and does not merely
			// waste work — it CORRUPTS. `[redacted]` ends in `]`, which is a
			// value terminator, so valueExtent stops one byte short and the
			// rewrite emits a fresh `[redacted]` followed by the old closing
			// bracket: `admin_password: [redacted]]`, then `]]`, growing by a
			// byte per pass. Two consequences, both bad. The prompt hash of
			// "the same question" changes with how many times the text has been
			// through the boundary, which is exactly what ADR-0008 D4.7's
			// digest is supposed to make answerable. And a caller that scrubs
			// early — ai.Redact is exported so it can — and then indexes into
			// the result finds every offset shifted by the time the boundary's
			// own pass is done, so a byte span it recorded names different text
			// than it read. The author seam cites pasted standards by byte
			// offset and does exactly that.
			b.WriteString(s[cursor : afterSeparator+n])
			cursor = afterSeparator + n
			continue
		}
		n := valueExtent(value)
		if n == 0 {
			// Nothing followed the separator. Writing a marker here would claim
			// a value was present and removed, which is not what happened.
			continue
		}
		b.WriteString(s[cursor:afterSeparator])
		b.WriteString(markerFor(value[:n]))
		cursor = afterSeparator + n
	}
	b.WriteString(s[cursor:])
	return b.String()
}

// markerExtent returns the length of the redaction marker at the start of s, in
// whichever quoting markerFor would have produced, or 0 if s does not begin
// with one.
//
// It is how redactText recognises its own output. Judging the quotes matters:
// `"[redacted]"` must be consumed WITH its quotes, or the closing one would be
// left behind as a stray byte in the same way the bracket was.
func markerExtent(s string) int {
	for _, form := range [...]string{
		`"` + redact.Marker + `"`,
		`'` + redact.Marker + `'`,
		redact.Marker,
	} {
		if strings.HasPrefix(s, form) {
			return len(form)
		}
	}
	return 0
}

// valueExtent returns the length of the value at the start of s.
func valueExtent(s string) int {
	if s == "" {
		return 0
	}
	if s[0] == '"' || s[0] == '\'' {
		return quotedExtent(s)
	}

	end := len(s)
	if i := strings.IndexAny(s, valueTerminators); i >= 0 {
		end = i
	}
	// …or the start of the next field, which is what a space-separated line of
	// pairs looks like. Without this the value runs to the next comma or
	// newline and takes every later pair on the line with it.
	if loc := nextPairStart.FindStringIndex(s); loc != nil && loc[0] < end {
		end = loc[0]
	}
	return end
}

// quotedExtent returns the length of the quoted string at the start of s,
// including both quotes, honouring backslash escapes.
func quotedExtent(s string) int {
	quote := s[0]
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // whatever follows is escaped, including a quote
		case quote:
			return i + 1
		}
	}
	// Unterminated. Redact to the end of the line rather than guess where the
	// value stopped: over-redaction is the correct direction to be wrong in
	// here, and a truncated prompt is a visible failure while a leaked
	// credential is not.
	if nl := strings.IndexAny(s, "\n\r"); nl >= 0 {
		return nl
	}
	return len(s)
}

// markerFor preserves the quoting style of the value it replaces, so redacting
// inside a JSON blob leaves valid JSON. A reader who sees "[redacted]" in a
// payload knows the backstop fired; a reader who sees malformed JSON learns
// nothing useful.
func markerFor(value string) string {
	switch value[0] {
	case '"':
		return `"` + redact.Marker + `"`
	case '\'':
		return `'` + redact.Marker + `'`
	default:
		return redact.Marker
	}
}
