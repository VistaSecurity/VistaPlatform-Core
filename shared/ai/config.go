package ai

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/config"
)

// The provider kinds this vocabulary knows about. They are names, not
// implementations: Core recognises them here so an operator's configuration is
// readable everywhere, while the code that can actually answer to them is
// registered by the Enterprise providers package (ADR-0008 edition placement).
//
// A Core build that sees one of these in AI_PROVIDER returns [NoneProvider]
// together with [ErrUnknownProvider] — the capability is absent and says so,
// which is the whole point of naming the kinds in one place.
const (
	// ProviderAnthropic is the Anthropic Messages API.
	ProviderAnthropic = "anthropic"

	// ProviderOpenAICompat is the OpenAI chat-completions shape against a
	// configurable base URL: hosted OpenAI, vLLM, Ollama, LM Studio.
	ProviderOpenAICompat = "openai_compat"
)

// Defaults for the knobs an operator usually leaves alone.
const (
	// DefaultMaxTokens caps a response. It is deliberately generous: a cap that
	// truncates mid-sentence produces output that reads finished and is not,
	// which is the same "looks like an answer" hazard the honesty rules exist
	// for. A seam that wants a short answer sets Request.MaxTokens.
	DefaultMaxTokens = 16000

	// DefaultTimeout bounds ONE attempt, not the whole call. A thinking model
	// answering a grounded question routinely takes tens of seconds, and a
	// self-hosted endpoint on modest hardware takes longer.
	DefaultTimeout = 120 * time.Second
)

// ProviderConfig is everything needed to reach a model endpoint, except the
// credential.
//
// # Why the key is not a field
//
// There is no APIKey string here, and that is the design. The struct is meant
// to be storable — phase 4's Settings → AI assistant page persists exactly this
// shape per tenant (ADR-0006 D7) — and a struct that can be logged, marshalled
// into a jsonb column, or echoed back to a UI must not be able to carry a
// credential. It carries the NAME of the environment variable instead, and
// [ProviderConfig.APIKey] reads it at the moment of use. A configuration row
// that leaks is a configuration row, not a key.
type ProviderConfig struct {
	// Kind selects the provider: "", "none", "anthropic", "openai_compat".
	Kind string `json:"kind"`

	// BaseURL overrides the endpoint. Required for "openai_compat" (there is
	// no sensible default for "the customer's own endpoint"); optional for
	// "anthropic", which defaults to the public API.
	BaseURL string `json:"base_url,omitempty"`

	// Model is the model id to send. Empty means the provider's default.
	Model string `json:"model,omitempty"`

	// APIKeyEnv names the environment variable holding the credential. Empty
	// means the kind's conventional variable (see [DefaultAPIKeyEnv]).
	APIKeyEnv string `json:"api_key_env,omitempty"`

	// AllowPrivateEndpoints permits an endpoint on a loopback, private, or
	// link-local address.
	//
	// Default false, and the default is the important half. Every other
	// outbound call in this codebase goes through the SSRF-guarded dialer
	// because the host is tenant-supplied and a private address means someone
	// is pointing us at our own cluster. Here a private address is ALSO the
	// legitimate case — a customer running Ollama or vLLM beside the platform —
	// so the guard cannot simply be dropped, and it cannot simply be kept. It
	// becomes an explicit decision the operator records, one that a tenant
	// pasting a URL into a settings field cannot make for them.
	AllowPrivateEndpoints bool `json:"allow_private_endpoints"`

	// MaxTokens caps the response when a Request does not. Zero means
	// [DefaultMaxTokens].
	MaxTokens int `json:"max_tokens,omitempty"`

	// Timeout bounds one HTTP attempt. Zero means [DefaultTimeout].
	Timeout time.Duration `json:"timeout,omitempty"`
}

// DefaultAPIKeyEnv returns the conventional environment variable for a kind,
// or "" for a kind that needs no credential.
//
// "openai_compat" returns OPENAI_API_KEY, but a bearer token is OPTIONAL there:
// a local Ollama or LM Studio endpoint has no credential at all, and demanding
// one would make the air-gapped case unconfigurable.
func DefaultAPIKeyEnv(kind string) string {
	switch NormalizeKind(kind) {
	case ProviderAnthropic:
		return "ANTHROPIC_API_KEY"
	case ProviderOpenAICompat:
		return "OPENAI_API_KEY"
	default:
		return ""
	}
}

// NormalizeKind lowercases and trims a configured kind, and folds the spelling
// variants of the OpenAI-compatible name onto one value. An operator who writes
// "openai-compatible" has configured the thing they meant to.
func NormalizeKind(kind string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	switch k {
	case "openai-compat", "openai-compatible", "openai_compatible", "openai":
		return ProviderOpenAICompat
	default:
		return k
	}
}

// WithDefaults returns a copy with the zero fields filled in. Providers call it
// so every one of them reads the same defaults from the same place.
func (c ProviderConfig) WithDefaults() ProviderConfig {
	out := c
	out.Kind = NormalizeKind(out.Kind)
	if out.APIKeyEnv == "" {
		out.APIKeyEnv = DefaultAPIKeyEnv(out.Kind)
	}
	if out.MaxTokens <= 0 {
		out.MaxTokens = DefaultMaxTokens
	}
	if out.Timeout <= 0 {
		out.Timeout = DefaultTimeout
	}
	return out
}

// APIKey reads the credential from the environment variable this config names,
// at the moment of use. It is never cached on the struct, so a rotated key is
// picked up by the next request and a dumped config never contains one.
//
// An empty result is a real answer: "openai_compat" against a local endpoint
// legitimately has no key, and the provider decides whether it needs one.
func (c ProviderConfig) APIKey() string {
	name := c.APIKeyEnv
	if name == "" {
		name = DefaultAPIKeyEnv(c.Kind)
	}
	if name == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}

// ProviderConfigFromEnv reads the configuration an operator set in the
// environment. It reads no credential — only the NAME of the variable holding
// one.
//
//	AI_PROVIDER                 none | anthropic | openai_compat
//	AI_BASE_URL                 endpoint override (required for openai_compat)
//	AI_MODEL                    model id override
//	AI_API_KEY_ENV              which env var holds the key
//	AI_ALLOW_PRIVATE_ENDPOINTS  true to permit a private/loopback endpoint
//	AI_MAX_TOKENS               response cap
//	AI_TIMEOUT                  per-attempt timeout, e.g. "90s"
func ProviderConfigFromEnv() ProviderConfig {
	return ProviderConfig{
		Kind:                  config.GetEnv("AI_PROVIDER", ProviderNone),
		BaseURL:               strings.TrimSpace(config.GetEnv("AI_BASE_URL", "")),
		Model:                 strings.TrimSpace(config.GetEnv("AI_MODEL", "")),
		APIKeyEnv:             strings.TrimSpace(config.GetEnv("AI_API_KEY_ENV", "")),
		AllowPrivateEndpoints: config.GetEnvAsBool("AI_ALLOW_PRIVATE_ENDPOINTS", false),
		MaxTokens:             config.GetEnvAsInt("AI_MAX_TOKENS", 0),
		Timeout:               config.GetEnvAsDuration("AI_TIMEOUT", 0),
	}.WithDefaults()
}

// String renders the config for a log line. It exists so that logging a config
// is an ordinary thing to do: there is no credential in the struct, and this
// method makes that legible rather than something a reader has to verify.
func (c ProviderConfig) String() string {
	return fmt.Sprintf(
		"ai.ProviderConfig{kind:%s base_url:%q model:%q api_key_env:%s allow_private:%t max_tokens:%d timeout:%s}",
		c.Kind, c.BaseURL, c.Model, c.APIKeyEnv, c.AllowPrivateEndpoints, c.MaxTokens, c.Timeout)
}
