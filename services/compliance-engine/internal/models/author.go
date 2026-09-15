package models

// AuthorAvailability reports whether this deployment's ADR-0008 **Author** seam
// can answer — that is, whether "Draft from a standard…" is offered at all.
//
// It lives in Core, and Core serves it, because the question has an answer in
// every edition and the honest Core answer is "no". A UI that had to infer
// availability from a 404 could not tell a Core build from a broken route, and
// a UI that simply showed the button would offer a person a capability that
// answers 503.
//
// Three fields rather than a bool, because the two "no" answers have different
// fixes: an operator who configured a provider and still sees no button needs
// to know which of the two they are looking at.
type AuthorAvailability struct {
	// Available is whether a drafting call could succeed right now.
	Available bool `json:"available"`

	// Reason is why not, empty when Available.
	Reason string `json:"reason,omitempty"`

	// Provider is the configured provider's name ("none", "anthropic",
	// "openai-compatible"), for a Settings page and a support ticket.
	Provider string `json:"provider,omitempty"`
}

// Reasons an author seam cannot answer.
const (
	// AuthorReasonEdition — this build has no generative author at all. Core
	// ships the seam and its null default; the model clients are Enterprise.
	AuthorReasonEdition = "edition"

	// AuthorReasonNoProvider — the build has the seam, but AI_PROVIDER names
	// nothing reachable. The operator configures a provider.
	AuthorReasonNoProvider = "no_provider"
)
