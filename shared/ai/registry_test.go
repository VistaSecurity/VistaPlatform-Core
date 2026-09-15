package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stubProvider is a provider a test can register, distinguishable by name.
type stubProvider struct {
	name string
	cfg  ProviderConfig
}

func (s *stubProvider) Name() string    { return s.name }
func (s *stubProvider) Available() bool { return true }
func (s *stubProvider) Complete(_ context.Context, req Request) (Response, error) {
	if !req.IsSanitized() {
		return Response{}, ErrNotSanitized
	}
	return Response{Text: "stub", ModelID: s.cfg.Model}, nil
}

// withEmptyRegistry replaces the process-wide factory map for one test and puts
// the original back afterwards.
//
// The empty map is the CORE state — a build with no ee/ tree registers nothing
// — so a test that starts from it is testing what a Core deployment does, in a
// repository whose test binary may have linked anything.
func withEmptyRegistry(t *testing.T) {
	t.Helper()
	providerMu.Lock()
	original := providerFactories
	providerFactories = map[string]ProviderFactory{}
	providerMu.Unlock()

	t.Cleanup(func() {
		providerMu.Lock()
		providerFactories = original
		providerMu.Unlock()
	})
}

// This is the guard mutation-test ADR-0008's edition split needs, stated in
// both polarities in one place: remove the ee registration and "anthropic" must
// degrade to NoneProvider with an error — never a panic, never a nil interface,
// never a provider that pretends. Put a registration back and the same name
// resolves.
//
// It matters because the failure it guards against is invisible at build time.
// A Core checkout has no ee/ tree at all, so nothing in it can be compiled to
// prove this; the only place the property can be asserted is here, against an
// emptied registry.
func TestNewFromEnv_EnterpriseNamesDegradeToNoneWithoutTheEeRegistration(t *testing.T) {
	for _, kind := range []string{ProviderAnthropic, ProviderOpenAICompat} {
		t.Run(kind+"/core build", func(t *testing.T) {
			withEmptyRegistry(t)
			t.Setenv("AI_PROVIDER", kind)

			p, err := NewFromEnv()

			if p == nil {
				t.Fatal("nil Provider; a caller that logs the error and continues would panic")
			}
			if _, isNone := p.(NoneProvider); !isNone {
				t.Fatalf("got %T, want NoneProvider", p)
			}
			if !errors.Is(err, ErrUnknownProvider) {
				t.Fatalf("err = %v, want ErrUnknownProvider", err)
			}
			if p.Available() {
				t.Error("the fallback reported itself available")
			}

			// And the seam still refuses an unsanitized request ahead of the
			// unavailability, so a caller who skipped the boundary still finds
			// out here.
			if _, err := p.Complete(context.Background(), Request{}); !errors.Is(err, ErrNotSanitized) {
				t.Errorf("Complete err = %v, want ErrNotSanitized", err)
			}
		})

		t.Run(kind+"/enterprise build", func(t *testing.T) {
			withEmptyRegistry(t)
			if err := RegisterProvider(kind, func(cfg ProviderConfig) (Provider, error) {
				return &stubProvider{name: kind, cfg: cfg}, nil
			}); err != nil {
				t.Fatalf("RegisterProvider: %v", err)
			}
			t.Setenv("AI_PROVIDER", kind)

			p, err := NewFromEnv()
			if err != nil {
				t.Fatalf("NewFromEnv: %v", err)
			}
			if p.Name() != kind {
				t.Fatalf("Name() = %q, want %q", p.Name(), kind)
			}
		})
	}
}

func TestRegisterProvider_RejectsWhatWouldRedefineTheVocabulary(t *testing.T) {
	ok := func(ProviderConfig) (Provider, error) { return &stubProvider{name: "x"}, nil }

	cases := []struct {
		name    string
		key     string
		factory ProviderFactory
	}{
		{name: "empty name", key: "   ", factory: ok},
		// Re-registering "none" would let a build redefine what "no AI
		// configured" means — the one thing every deployment relies on.
		{name: "the reserved none", key: ProviderNone, factory: ok},
		{name: "nil factory", key: "nilly", factory: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEmptyRegistry(t)
			if err := RegisterProvider(tc.key, tc.factory); !errors.Is(err, ErrProviderRegistration) {
				t.Fatalf("err = %v, want ErrProviderRegistration", err)
			}
		})
	}

	t.Run("duplicate", func(t *testing.T) {
		withEmptyRegistry(t)
		if err := RegisterProvider("dup", ok); err != nil {
			t.Fatalf("first registration: %v", err)
		}
		// Last-writer-wins would pick between two implementations of the same
		// name by link order, which is not a decision anybody made.
		if err := RegisterProvider("dup", ok); !errors.Is(err, ErrProviderRegistration) {
			t.Fatalf("second registration err = %v, want ErrProviderRegistration", err)
		}
	})
}

func TestRegisterProvider_FoldsTheSpellingsOfOneKindTogether(t *testing.T) {
	withEmptyRegistry(t)
	if err := RegisterProvider(ProviderOpenAICompat, func(ProviderConfig) (Provider, error) {
		return &stubProvider{name: ProviderOpenAICompat}, nil
	}); err != nil {
		t.Fatalf("RegisterProvider: %v", err)
	}

	// An operator who writes any of these has configured the thing they meant.
	for _, spelling := range []string{"openai_compat", "OpenAI-Compatible", "  openai-compat  ", "openai"} {
		t.Run(spelling, func(t *testing.T) {
			p, err := New(ProviderConfig{Kind: spelling})
			if err != nil {
				t.Fatalf("New(%q): %v", spelling, err)
			}
			if p.Name() != ProviderOpenAICompat {
				t.Fatalf("Name() = %q, want %q", p.Name(), ProviderOpenAICompat)
			}
		})
	}
}

func TestNew_FactoryFailuresStillYieldAUsableProvider(t *testing.T) {
	sentinel := errors.New("no API key")

	t.Run("factory returns an error", func(t *testing.T) {
		withEmptyRegistry(t)
		if err := RegisterProvider("broken", func(ProviderConfig) (Provider, error) {
			return nil, sentinel
		}); err != nil {
			t.Fatalf("RegisterProvider: %v", err)
		}

		p, err := New(ProviderConfig{Kind: "broken"})
		if !errors.Is(err, sentinel) {
			t.Fatalf("err = %v, want it to wrap the factory's error", err)
		}
		if _, isNone := p.(NoneProvider); !isNone {
			t.Fatalf("got %T, want NoneProvider", p)
		}
	})

	// (nil, nil) is the typed-nil bug's cousin: handing it back would satisfy
	// every `!= nil` check upstream and panic at the first Complete.
	t.Run("factory returns nothing at all", func(t *testing.T) {
		withEmptyRegistry(t)
		if err := RegisterProvider("empty", func(ProviderConfig) (Provider, error) {
			return nil, nil
		}); err != nil {
			t.Fatalf("RegisterProvider: %v", err)
		}

		p, err := New(ProviderConfig{Kind: "empty"})
		if err == nil {
			t.Fatal("err = nil; a factory returning no provider and no error is a bug that must be reported")
		}
		if _, isNone := p.(NoneProvider); !isNone {
			t.Fatalf("got %T, want NoneProvider", p)
		}
		if _, err := p.Complete(context.Background(), Redact(Request{})); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Complete err = %v, want ErrUnavailable (i.e. no panic)", err)
		}
	})
}

func TestRegisteredProviders_ListsWhatThisBuildCanConstruct(t *testing.T) {
	withEmptyRegistry(t)

	if got := RegisteredProviders(); len(got) != 0 {
		t.Fatalf("a Core build lists %v; it must list nothing", got)
	}

	for _, kind := range []string{ProviderOpenAICompat, ProviderAnthropic} {
		if err := RegisterProvider(kind, func(ProviderConfig) (Provider, error) {
			return &stubProvider{name: kind}, nil
		}); err != nil {
			t.Fatalf("RegisterProvider(%q): %v", kind, err)
		}
	}

	got := RegisteredProviders()
	want := []string{ProviderAnthropic, ProviderOpenAICompat} // sorted
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (sorted)", got, want)
		}
	}
}

func TestRateLimitError_KeepsNotStatedApartFromZero(t *testing.T) {
	// 0 with RetryAfterKnown false means "the provider did not say"; 0 with it
	// true means "retry now". Collapsing them is the not-assessed-rendered-as-
	// assessed bug, inside a retry loop.
	silent := &RateLimitError{Provider: "anthropic"}
	if !errors.Is(silent, ErrRateLimited) {
		t.Error("a RateLimitError must satisfy errors.Is(err, ErrRateLimited)")
	}
	if silent.RetryAfterKnown {
		t.Error("a zero RateLimitError claims a Retry-After it never saw")
	}
	if got := silent.Error(); !strings.Contains(got, "no Retry-After given") {
		t.Errorf("Error() = %q, want it to say the header was absent", got)
	}
}

// ErrProviderUnavailable wraps ErrUnavailable so a caller asking the seam
// question ("can I answer without a model?") gets the same answer for an
// outage as for an unconfigured deployment, while an operator-facing caller can
// still tell them apart.
func TestErrProviderUnavailable_IsAlsoErrUnavailable(t *testing.T) {
	if !errors.Is(ErrProviderUnavailable, ErrUnavailable) {
		t.Error("ErrProviderUnavailable must wrap ErrUnavailable")
	}
	if errors.Is(ErrUnavailable, ErrProviderUnavailable) {
		t.Error("plain ErrUnavailable must NOT read as a provider outage")
	}
	// A bad credential must not degrade quietly: it needs an operator.
	if errors.Is(ErrUnauthorized, ErrUnavailable) {
		t.Error("ErrUnauthorized must not wrap ErrUnavailable — a bad key needs fixing, not degrading around")
	}
}
