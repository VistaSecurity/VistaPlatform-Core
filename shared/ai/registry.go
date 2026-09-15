package ai

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// ProviderFactory builds a provider from a configuration. It returns an error
// rather than a broken provider: a misconfigured endpoint must fail where the
// operator can see it, not on the first prompt.
type ProviderFactory func(cfg ProviderConfig) (Provider, error)

var (
	providerMu sync.RWMutex
	// providerFactories is empty in a Core build and stays empty. The
	// Enterprise providers package registers into it from an init that only an
	// `//go:build ee` file pulls in, so Core does not merely lack the
	// implementations — it cannot name them either, and [New] says so.
	providerFactories = map[string]ProviderFactory{}
)

// ErrProviderRegistration is returned by [RegisterProvider] for a registration
// this package will not accept: a duplicate, an empty name, a nil factory, or
// an attempt to redefine "none".
var ErrProviderRegistration = fmt.Errorf("ai: provider registration rejected")

// RegisterProvider makes a provider kind selectable by name.
//
// The rules are the seams registry's rules, for the same reasons:
//
//   - "none" is reserved. Re-registering it would let a build redefine what
//     "no AI configured" means, which is the one thing every deployment relies
//     on being true.
//   - A duplicate is an error, not a silent overwrite. Two registrations of
//     "anthropic" means two implementations disagree about what that word
//     means, and last-writer-wins would pick between them by link order.
//   - A nil factory is an error. It would resolve to a nil Provider at the
//     first call, and the failure would surface as a panic somewhere far away.
//
// It is safe for concurrent use, though the intended caller is an init in the
// Enterprise providers package.
func RegisterProvider(name string, factory ProviderFactory) error {
	key := NormalizeKind(name)
	switch {
	case key == "":
		return fmt.Errorf("%w: empty provider name", ErrProviderRegistration)
	case key == ProviderNone:
		return fmt.Errorf("%w: %q is reserved", ErrProviderRegistration, ProviderNone)
	case factory == nil:
		return fmt.Errorf("%w: %q has a nil factory", ErrProviderRegistration, key)
	}

	providerMu.Lock()
	defer providerMu.Unlock()
	if _, exists := providerFactories[key]; exists {
		return fmt.Errorf("%w: %q is already registered", ErrProviderRegistration, key)
	}
	providerFactories[key] = factory
	return nil
}

// RegisteredProviders returns the kinds this build can construct, sorted.
// "none" is not in the list: it needs no factory and is always available.
//
// A Settings page uses it to offer only what the running binary can actually
// do, rather than offering a choice that resolves to nothing.
func RegisteredProviders() []string {
	providerMu.RLock()
	defer providerMu.RUnlock()

	out := make([]string, 0, len(providerFactories))
	for name := range providerFactories {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// New builds the provider a configuration names.
//
// It never panics and never returns a nil Provider. Every failure path returns
// [NoneProvider] alongside the error, so a caller that logs and continues
// degrades to no-AI rather than to a nil interface — which is the difference
// between a capability being off and a service falling over.
//
// The three failures it distinguishes, because an operator needs to tell them
// apart:
//
//   - The kind is not registered ([ErrUnknownProvider]). Either a typo, or a
//     Core build being asked for an Enterprise provider. Both mean "this
//     binary cannot do that", and neither should be silent.
//   - The factory rejected the configuration. A missing credential, a base URL
//     that is not a URL, a private endpoint without the flag.
//   - The factory returned nil with no error. A bug in the factory, caught here
//     rather than at the first prompt.
func New(cfg ProviderConfig) (Provider, error) {
	cfg = cfg.WithDefaults()

	if cfg.Kind == "" || cfg.Kind == ProviderNone {
		return NoneProvider{}, nil
	}

	providerMu.RLock()
	factory, ok := providerFactories[cfg.Kind]
	providerMu.RUnlock()

	if !ok {
		err := fmt.Errorf("%w %q; falling back to %q", ErrUnknownProvider, cfg.Kind, ProviderNone)
		logrus.WithFields(logrus.Fields{
			"ai_provider": cfg.Kind,
			"registered":  strings.Join(RegisteredProviders(), ","),
		}).Warn("AI_PROVIDER names a provider this build does not have; AI features stay unavailable")
		return NoneProvider{}, err
	}

	p, err := factory(cfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"ai_provider": cfg.Kind,
			"error":       err.Error(),
		}).Warn("AI provider is configured but could not be constructed; AI features stay unavailable")
		return NoneProvider{}, fmt.Errorf("ai: provider %q: %w", cfg.Kind, err)
	}
	if p == nil {
		// Typed-nil's cousin: a factory that returns (nil, nil). Handing that
		// back would satisfy every `!= nil` check upstream and panic on the
		// first Complete.
		return NoneProvider{}, fmt.Errorf("ai: provider %q returned no provider and no error", cfg.Kind)
	}
	return p, nil
}

// NewFromEnv selects a provider from the environment, defaulting to none.
//
// It is [New] over [ProviderConfigFromEnv], and it inherits both guarantees:
// never a panic, never a nil Provider. An unrecognised AI_PROVIDER yields
// NoneProvider together with [ErrUnknownProvider], logged as well as returned,
// because a typo in a deployment's environment must not be able to silently
// disable a capability an operator believes they turned on — and must not be
// able to take a service down either.
//
// In a Core build "anthropic" and "openai_compat" are unrecognised. That is not
// a gap to paper over: the generative implementations are Enterprise (ADR-0008
// edition placement), so Core naming one of them is exactly the case this
// error reports.
func NewFromEnv() (Provider, error) {
	return New(ProviderConfigFromEnv())
}
