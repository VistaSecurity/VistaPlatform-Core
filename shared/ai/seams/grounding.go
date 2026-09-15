package seams

import "github.com/vistasecurity/vistaplatform/shared/query/queryerr"

// GroundingRefusal is what a query seam's refusal carries when a provider
// ANSWERED and what it wrote did not validate.
//
// # Why this interface exists in Core at all
//
// The implementation that produces it — `shared/ai/ee/query`'s `ErrNotGrounded`
// — is Enterprise, and the export deletes it. The consumer that has to render
// it is an ordinary Core HTTP handler: the ask endpoint is mounted in every
// edition (it answers 402 in Core, exactly as the remediator's drafting routes
// do), so a Core build compiles the code that turns a refusal into a response
// body even though a Core build can never produce one. That handler therefore
// may not name the concrete type, and an `errors.As` against an interface
// declared HERE is the only way it can reach the diagnostics.
//
// # Why the diagnostics and not just the message
//
// `ErrNotGrounded` deliberately does not wrap [ai.ErrUnavailable] — a provider
// answered, twice, and the validator said exactly why. Those `{code, message,
// span, suggestion}` diagnostics are the one thing a person can act on: "no
// field `hostnaem` on assets, did you mean `hostname`?" is a better answer to a
// mistyped question than a confidently wrong row set. Collapsing them into a
// flattened string at the service boundary would show the user a shrug, which
// is precisely the outcome the error type was shaped to avoid.
//
// The endpoint renders them in the SAME wire shape QUERY_LANGUAGE §10 fixes for
// a query the user typed by hand, because to the reader they are the same thing:
// the reason a predicate was refused, against a predicate they can now edit.
//
// # The attempted query is not the canonical query
//
// [GroundingQuery] is the model's raw output. It never reached the formatter, it
// may be empty (a model that answered with no fenced block produced no query at
// all), and — since the language's bare-term form is a free-text search — it can
// legitimately BE the user's question, quoted. It is returned to the caller who
// asked the question, which is the one place it is not a disclosure; it is kept
// out of the audit record unless the tenant opted in (ADR-0008 D4.7), which is
// `ErrNotGrounded`'s own business and not this interface's.
type GroundingRefusal interface {
	error

	// GroundingQuery is the last query the model produced, or "" when it
	// produced none. An empty string says so rather than standing in for one.
	GroundingQuery() string

	// GroundingDiagnostics are the validator's errors against that query,
	// verbatim. Empty when there was no query to diagnose — a different fact
	// from "it was diagnosed and found clean".
	GroundingDiagnostics() queryerr.List

	// GroundingAttempts is how many translation turns were spent, so a caller
	// can tell "failed twice" from "refused before asking".
	GroundingAttempts() int
}
