package ai

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProviderConfigFromEnv_ReadsTheDocumentedVariables(t *testing.T) {
	t.Setenv("AI_PROVIDER", "  OpenAI-Compatible ")
	t.Setenv("AI_BASE_URL", " http://ollama.internal:11434/v1 ")
	t.Setenv("AI_MODEL", " llama3.3:70b ")
	t.Setenv("AI_API_KEY_ENV", "MY_LOCAL_TOKEN")
	t.Setenv("AI_ALLOW_PRIVATE_ENDPOINTS", "true")
	t.Setenv("AI_MAX_TOKENS", "2048")
	t.Setenv("AI_TIMEOUT", "45s")

	cfg := ProviderConfigFromEnv()

	if cfg.Kind != ProviderOpenAICompat {
		t.Errorf("Kind = %q, want %q", cfg.Kind, ProviderOpenAICompat)
	}
	if cfg.BaseURL != "http://ollama.internal:11434/v1" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.Model != "llama3.3:70b" {
		t.Errorf("Model = %q", cfg.Model)
	}
	if cfg.APIKeyEnv != "MY_LOCAL_TOKEN" {
		t.Errorf("APIKeyEnv = %q", cfg.APIKeyEnv)
	}
	if !cfg.AllowPrivateEndpoints {
		t.Error("AllowPrivateEndpoints = false; the operator said true")
	}
	if cfg.MaxTokens != 2048 {
		t.Errorf("MaxTokens = %d", cfg.MaxTokens)
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout = %s", cfg.Timeout)
	}
}

func TestProviderConfigFromEnv_DefaultsToNoneAndSaysNothingElse(t *testing.T) {
	for _, v := range []string{"", "none"} {
		t.Setenv("AI_PROVIDER", v)
		t.Setenv("AI_BASE_URL", "")
		t.Setenv("AI_ALLOW_PRIVATE_ENDPOINTS", "")

		cfg := ProviderConfigFromEnv()

		if cfg.Kind != ProviderNone && cfg.Kind != "" {
			t.Errorf("AI_PROVIDER=%q gave Kind %q", v, cfg.Kind)
		}
		// The default has to be the safe one: a deployment that configures
		// nothing must not be reachable at a private address by accident.
		if cfg.AllowPrivateEndpoints {
			t.Error("AllowPrivateEndpoints defaulted to true")
		}
		if cfg.MaxTokens != DefaultMaxTokens {
			t.Errorf("MaxTokens = %d, want the default %d", cfg.MaxTokens, DefaultMaxTokens)
		}
		if cfg.Timeout != DefaultTimeout {
			t.Errorf("Timeout = %s, want the default %s", cfg.Timeout, DefaultTimeout)
		}
	}
}

func TestProviderConfig_APIKeyIsReadFromTheEnvironmentAtUse(t *testing.T) {
	t.Setenv("SOME_OTHER_KEY", "sk-from-the-named-variable")
	t.Setenv("ANTHROPIC_API_KEY", "sk-from-the-default-variable")

	t.Run("named variable wins", func(t *testing.T) {
		cfg := ProviderConfig{Kind: ProviderAnthropic, APIKeyEnv: "SOME_OTHER_KEY"}
		if got := cfg.APIKey(); got != "sk-from-the-named-variable" {
			t.Errorf("APIKey() = %q", got)
		}
	})

	t.Run("kind default when unnamed", func(t *testing.T) {
		cfg := ProviderConfig{Kind: ProviderAnthropic}
		if got := cfg.APIKey(); got != "sk-from-the-default-variable" {
			t.Errorf("APIKey() = %q", got)
		}
	})

	// An empty key is a real answer, not a failure: a local endpoint has none.
	t.Run("no key is not an error", func(t *testing.T) {
		cfg := ProviderConfig{Kind: ProviderOpenAICompat, APIKeyEnv: "DEFINITELY_UNSET_KEY_VAR"}
		if got := cfg.APIKey(); got != "" {
			t.Errorf("APIKey() = %q, want empty", got)
		}
	})

	// A rotated key is picked up without rebuilding the provider, because it
	// was never cached anywhere.
	t.Run("reads today's value", func(t *testing.T) {
		cfg := ProviderConfig{Kind: ProviderAnthropic, APIKeyEnv: "ROTATING_KEY"}
		t.Setenv("ROTATING_KEY", "first")
		if got := cfg.APIKey(); got != "first" {
			t.Fatalf("APIKey() = %q", got)
		}
		t.Setenv("ROTATING_KEY", "second")
		if got := cfg.APIKey(); got != "second" {
			t.Fatalf("APIKey() = %q after rotation", got)
		}
	})
}

// The config is meant to be persisted by the Settings page and logged when a
// provider is constructed. Neither is safe if a credential can reach the
// struct, so the structural claim — there is no field it could live in — is
// pinned here rather than left to review.
func TestProviderConfig_CannotCarryACredential(t *testing.T) {
	const secret = "sk-ant-super-secret-value"
	t.Setenv("ANTHROPIC_API_KEY", secret)

	cfg := ProviderConfig{Kind: ProviderAnthropic, Model: "claude-fable-5-1"}.WithDefaults()

	if cfg.APIKey() != secret {
		t.Fatal("the test did not actually set the key it is looking for")
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Errorf("marshalled config contains the credential: %s", encoded)
	}
	if strings.Contains(cfg.String(), secret) {
		t.Errorf("String() contains the credential: %s", cfg.String())
	}
	// It should still say WHICH variable, so an operator can find it.
	if !strings.Contains(cfg.String(), "ANTHROPIC_API_KEY") {
		t.Errorf("String() = %q, want it to name the key variable", cfg.String())
	}
}

func TestDefaultAPIKeyEnv(t *testing.T) {
	cases := map[string]string{
		ProviderAnthropic:    "ANTHROPIC_API_KEY",
		ProviderOpenAICompat: "OPENAI_API_KEY",
		"openai-compatible":  "OPENAI_API_KEY",
		ProviderNone:         "",
		"":                   "",
	}
	for kind, want := range cases {
		if got := DefaultAPIKeyEnv(kind); got != want {
			t.Errorf("DefaultAPIKeyEnv(%q) = %q, want %q", kind, got, want)
		}
	}
}
