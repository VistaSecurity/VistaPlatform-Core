// Package edition is the wiring seam between Core's provider registry and the
// Enterprise provider implementations.
//
// It exists because of an import cycle and an edition boundary that would
// otherwise collide.
//
// The generative providers (Anthropic, OpenAI-compatible) are Enterprise under
// ADR-0008's edition placement, so they live under an ee/ tree that the
// open-source export deletes wholesale. They implement shared/ai's Provider
// interface, so they import shared/ai. That means shared/ai cannot import them
// back — under `-tags ee` the cycle is real, tags or no tags — so the blank
// import that runs their registration init has to sit in a THIRD package. This
// is it.
//
// The pattern is the one every carved service already uses: a Core-side package
// with a no-op default, and an `//go:build ee` file beside it that wires the
// Enterprise implementation in. Deleting the ee/ tree leaves this package
// compiling and reporting, truthfully, that nothing is linked.
//
// # How a binary uses it
//
// A service that wants generative AI imports this package for its side effect
// and then configures a provider the ordinary way:
//
//	import (
//	    "github.com/vistasecurity/vistaplatform/shared/ai"
//	    _ "github.com/vistasecurity/vistaplatform/shared/ai/edition"
//	)
//
//	provider, err := ai.NewFromEnv()   // "none" unless AI_PROVIDER says otherwise
//	if err != nil {
//	    log.WithError(err).Warn("AI provider not configured")   // never fatal
//	}
//	provider = ai.Boundary(provider, sink)
//
// The import is unconditional. The build tag decides what it brings: an
// Enterprise build gets the providers registered, a Core build gets nothing
// registered and ai.NewFromEnv returns NoneProvider with ai.ErrUnknownProvider
// for a kind it cannot construct. No caller needs a build tag of its own, and
// no caller can accidentally depend on an ee/ package directly.
package edition

// linked is set by the ee-tagged init in this package. It is a plain bool
// rather than a check against ai.RegisteredProviders(), because the question it
// answers is "was this binary built with the Enterprise providers compiled in"
// — which stays true and answerable even if a future build registers a provider
// from somewhere else.
var linked bool

// Linked reports whether the Enterprise generative providers are compiled into
// this binary.
//
// It is for a Settings page and a support log, and it is deliberately
// three-valued-honest in the small: a Core binary reports false rather than
// letting "no provider configured" and "no provider available in this edition"
// look like the same thing to an operator trying to work out why the AI
// assistant panel is missing.
func Linked() bool { return linked }
