package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/ai"
	auditmw "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// admin-ui → Settings → AI assistant: the platform half of model-provider
// configuration.
//
//	GET    /ai                   what is set, what is in effect, the two tenant switches
//	PUT    /ai/provider          set the default provider for every tenant
//	DELETE /ai/provider          clear it (the environment's, if any, takes over)
//	POST   /ai/provider/test     try the values in the form, unsaved
//	PUT    /ai/tenant-policy     whether tenants may connect their own; whether theirs may be private
//
// All behind platform.settings.
//
// # Order of precedence
//
// A provider set here OVERRIDES the one the environment names (the chart's
// `ai.*` values). Something a platform administrator set in a console should
// visibly win over a value nobody can see from that console; the page shows
// both and says which is in effect. A tenant's own provider, where tenants are
// permitted one, wins over both for that tenant.
//
// # Why these writes use the platform administrator's pool
//
// The `ai.*` rows of platform_settings decide where every tenant's prompts are
// sent and what address space a tenant may aim the platform at. The table's
// write guard refuses them from the tenant-scoped application role, so a
// request-driven write on that pool — an injection in some tenant-facing
// handler — cannot repoint the platform's model at a host of the attacker's
// choosing. db here is the bypass pool, the one legitimate writer.

// PlatformAIHandlers serves the platform's AI provider settings.
type PlatformAIHandlers struct {
	db       *sql.DB
	resolver *ai.Resolver
	sink     ai.AuditSink
}

// NewPlatformAIHandlers wires them. db must be the platform administrator's
// (bypass) pool; resolver is the service's own.
func NewPlatformAIHandlers(db *sql.DB, resolver *ai.Resolver, sink ai.AuditSink) *PlatformAIHandlers {
	return &PlatformAIHandlers{db: db, resolver: resolver, sink: sink}
}

// platformAIProvider is a stored provider as the console may show it. The
// operator set the base URL and sees it in full; nobody sees the key.
type platformAIProvider struct {
	Kind                  string `json:"kind"`
	BaseURL               string `json:"base_url,omitempty"`
	Model                 string `json:"model,omitempty"`
	AllowPrivateEndpoints bool   `json:"allow_private_endpoints"`
	HasKey                bool   `json:"has_key"`
	APIKeyHint            string `json:"api_key_hint,omitempty"`
}

// platformAIEnvironment is what the environment names, for the "also set at
// install" line. Kind and model only — the same two facts the tenant page has
// always shown.
type platformAIEnvironment struct {
	Kind  string `json:"kind"`
	Model string `json:"model,omitempty"`
}

// platformAIStatus is the body of GET and of every write.
type platformAIStatus struct {
	// ProviderKinds are the kinds this build can connect to. Empty in Core.
	ProviderKinds []string `json:"provider_kinds"`

	// CanStoreCredentials is whether this deployment has the encryption key a
	// stored API key needs. False means a provider that needs a key cannot be
	// saved here, and the page says why before the save fails.
	CanStoreCredentials bool `json:"can_store_credentials"`

	// Provider is the default set here, absent when none is.
	Provider *platformAIProvider `json:"provider,omitempty"`

	// Environment is the provider the environment names, absent when it names
	// none.
	Environment *platformAIEnvironment `json:"environment,omitempty"`

	// InEffect is which of the two answers for a tenant with no provider of
	// its own: "platform" (set here), "environment" or "none".
	InEffect string `json:"in_effect"`

	// Available is whether the provider in effect can answer.
	Available bool `json:"available"`

	// Problem is why not, when one is configured and cannot.
	Problem string `json:"problem,omitempty"`

	TenantProvidersAllowed        bool `json:"tenant_providers_allowed"`
	TenantPrivateEndpointsAllowed bool `json:"tenant_private_endpoints_allowed"`
}

func (h *PlatformAIHandlers) status(ctx context.Context) (platformAIStatus, error) {
	settings, err := ai.ReadPlatformAISettings(ctx, h.db)
	if err != nil {
		return platformAIStatus{}, err
	}
	res, err := h.resolver.ForPlatform(ctx)
	if err != nil {
		return platformAIStatus{}, err
	}

	out := platformAIStatus{
		ProviderKinds:                 ai.RegisteredProviders(),
		CanStoreCredentials:           h.resolver.Cipher().Usable(),
		InEffect:                      string(res.Source),
		Available:                     res.Provider.Available(),
		TenantProvidersAllowed:        settings.TenantProvidersAllowed,
		TenantPrivateEndpointsAllowed: settings.TenantPrivateEndpointsAllowed,
	}
	if sp := settings.Provider; sp != nil {
		out.Provider = &platformAIProvider{
			Kind:                  sp.Kind,
			BaseURL:               sp.BaseURL,
			Model:                 sp.Model,
			AllowPrivateEndpoints: sp.AllowPrivateEndpoints,
			HasKey:                sp.APIKeyEnc != "",
			APIKeyHint:            sp.APIKeyHint,
		}
	}
	if _, env, _ := h.resolver.Environment(); env.Kind != "" && env.Kind != ai.ProviderNone {
		out.Environment = &platformAIEnvironment{Kind: env.Kind, Model: env.Model}
	}
	if !out.Available && res.Source != ai.SourceNone {
		out.Problem = platformProviderProblem(res.Err)
	}
	return out, nil
}

// platformProviderProblem is the sentence for a configured provider that
// cannot answer. Written for the operator, who can act on all of these.
func platformProviderProblem(err error) string {
	switch {
	case err == nil:
		return "The configured provider reports that it is not available."
	case errors.Is(err, ai.ErrNoMasterKey):
		return "This deployment has no encryption key (ENCRYPTION_MASTER_KEY), so the saved API key cannot be read."
	case errors.Is(err, ai.ErrPrivateEndpoint):
		return "The endpoint is on a private address and private endpoints are not allowed for it."
	case errors.Is(err, ai.ErrUnknownProvider):
		return "This build does not include that provider. The model clients are part of Vista Platform Enterprise."
	default:
		return "The configured provider could not be set up. Save it again; if the encryption key was changed, the API key has to be re-entered."
	}
}

func (h *PlatformAIHandlers) respond(c *gin.Context) {
	st, err := h.status(c.Request.Context())
	if err != nil {
		log.Printf("[platform-ai] read settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the AI assistant settings"})
		return
	}
	c.JSON(http.StatusOK, st)
}

// Get serves GET /ai.
func (h *PlatformAIHandlers) Get(c *gin.Context) { h.respond(c) }

// platformAIProviderRequest is the body of PUT /ai/provider and of the test.
type platformAIProviderRequest struct {
	Kind                  string `json:"kind"`
	BaseURL               string `json:"base_url"`
	Model                 string `json:"model"`
	AllowPrivateEndpoints bool   `json:"allow_private_endpoints"`

	// APIKey: omitted keeps the stored key (same kind and base URL only);
	// empty means this endpoint has no credential.
	APIKey *string `json:"api_key"`
}

type platformProviderCandidate struct {
	stored    ai.StoredProvider
	plainKey  string
	reusedKey bool
}

// prepare decodes and validates a provider request, answering the request
// itself when it refuses.
func (h *PlatformAIHandlers) prepare(c *gin.Context) (platformProviderCandidate, bool) {
	var none platformProviderCandidate

	var req platformAIProviderRequest
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return none, false
	}
	req.Kind = ai.NormalizeKind(req.Kind)
	req.BaseURL = strings.TrimSpace(req.BaseURL)
	req.Model = strings.TrimSpace(req.Model)

	kinds := ai.RegisteredProviders()
	if len(kinds) == 0 {
		c.JSON(http.StatusPaymentRequired, gin.H{"error": "Connecting a model provider is part of Vista Platform Enterprise."})
		return none, false
	}
	known := false
	for _, k := range kinds {
		known = known || k == req.Kind
	}
	if !known {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Choose a provider: " + strings.Join(kinds, " or ") + "."})
		return none, false
	}
	if req.Kind == ai.ProviderOpenAICompat {
		if req.BaseURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Enter the endpoint's base URL."})
			return none, false
		}
		if req.Model == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Enter the model id the endpoint serves."})
			return none, false
		}
	}

	cand := platformProviderCandidate{stored: ai.StoredProvider{
		Kind: req.Kind, BaseURL: req.BaseURL, Model: req.Model, AllowPrivateEndpoints: req.AllowPrivateEndpoints,
	}}

	if req.APIKey != nil {
		cand.plainKey = strings.TrimSpace(*req.APIKey)
	} else {
		settings, err := ai.ReadPlatformAISettings(c.Request.Context(), h.db)
		if err != nil {
			log.Printf("[platform-ai] read settings: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the AI assistant settings"})
			return none, false
		}
		if existing := settings.Provider; existing != nil && existing.APIKeyEnc != "" {
			// The same rule the tenant form has, for the same reason: a stored
			// key is delivered only to the endpoint it was stored for.
			if !existing.SameEndpoint(cand.stored) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "The provider or its address changed, so the API key has to be entered again."})
				return none, false
			}
			plain, err := h.resolver.Cipher().Open(existing.APIKeyEnc)
			if err != nil {
				c.JSON(http.StatusConflict, gin.H{"error": "The saved API key can no longer be read. Enter it again."})
				return none, false
			}
			cand.plainKey, cand.reusedKey = plain, true
			cand.stored.APIKeyEnc, cand.stored.APIKeyHint = existing.APIKeyEnc, existing.APIKeyHint
		}
	}

	if _, err := ai.BuildUnsaved(cand.stored, cand.plainKey, cand.stored.AllowPrivateEndpoints); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": platformConfigProblem(err)})
		return none, false
	}
	return cand, true
}

func platformConfigProblem(err error) string {
	switch {
	case errors.Is(err, ai.ErrPrivateEndpoint):
		return "That address is on a private network. If it is your own model endpoint, turn on “This endpoint is on a private network” and save again."
	case strings.Contains(err.Error(), "no API key"):
		return "Enter the API key for this provider."
	case strings.Contains(err.Error(), "base URL"):
		return "The base URL is not usable: it must be an http or https address with a host."
	default:
		return "That provider configuration could not be used."
	}
}

// requirePlatformActor is the authenticated platform user, answering 401 when
// the request carries none. Who changed where every tenant's prompts go is not
// something to record as nobody.
func requirePlatformActor(c *gin.Context) (uuid.UUID, bool) {
	id := platformActor(c)
	if id == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
		return uuid.Nil, false
	}
	return id, true
}

// PutProvider serves PUT /ai/provider.
func (h *PlatformAIHandlers) PutProvider(c *gin.Context) {
	actor, ok := requirePlatformActor(c)
	if !ok {
		return
	}
	cand, ok := h.prepare(c)
	if !ok {
		return
	}
	if !cand.reusedKey {
		enc, hint, err := h.resolver.Cipher().Seal(cand.plainKey)
		if errors.Is(err, ai.ErrNoMasterKey) {
			c.JSON(http.StatusConflict, gin.H{"error": "This deployment has no encryption key (ENCRYPTION_MASTER_KEY), so an API key cannot be stored."})
			return
		}
		if err != nil {
			log.Printf("[platform-ai] seal key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the provider"})
			return
		}
		cand.stored.APIKeyEnc, cand.stored.APIKeyHint = enc, hint
	}
	if err := ai.SetPlatformProvider(c.Request.Context(), h.db, actor, cand.stored); err != nil {
		log.Printf("[platform-ai] save provider: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the provider"})
		return
	}
	h.respond(c)
}

// DeleteProvider serves DELETE /ai/provider.
func (h *PlatformAIHandlers) DeleteProvider(c *gin.Context) {
	if _, ok := requirePlatformActor(c); !ok {
		return
	}
	if err := ai.DeletePlatformProvider(c.Request.Context(), h.db); err != nil {
		log.Printf("[platform-ai] delete provider: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear the provider"})
		return
	}
	h.respond(c)
}

// platformAITenantPolicyRequest is the body of PUT /ai/tenant-policy. Pointers,
// so one switch can be sent without knowing the other.
type platformAITenantPolicyRequest struct {
	TenantProvidersAllowed        *bool `json:"tenant_providers_allowed"`
	TenantPrivateEndpointsAllowed *bool `json:"tenant_private_endpoints_allowed"`
}

// PutTenantPolicy serves PUT /ai/tenant-policy.
func (h *PlatformAIHandlers) PutTenantPolicy(c *gin.Context) {
	actor, ok := requirePlatformActor(c)
	if !ok {
		return
	}
	var req platformAITenantPolicyRequest
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if req.TenantProvidersAllowed == nil && req.TenantPrivateEndpointsAllowed == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No settings to update"})
		return
	}
	ctx := c.Request.Context()
	current, err := ai.ReadPlatformAISettings(ctx, h.db)
	if err != nil {
		log.Printf("[platform-ai] read settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the AI assistant settings"})
		return
	}
	providers, private := current.TenantProvidersAllowed, current.TenantPrivateEndpointsAllowed
	if req.TenantProvidersAllowed != nil {
		providers = *req.TenantProvidersAllowed
	}
	if req.TenantPrivateEndpointsAllowed != nil {
		private = *req.TenantPrivateEndpointsAllowed
	}
	if err := ai.SetPlatformTenantSwitches(ctx, h.db, actor, providers, private); err != nil {
		log.Printf("[platform-ai] save tenant policy: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the settings"})
		return
	}
	h.respond(c)
}

// platformAITestResult is the body of the test.
type platformAITestResult struct {
	OK        bool   `json:"ok"`
	ModelID   string `json:"model_id,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

const platformProviderTestBudget = 45 * time.Second

// TestProvider serves POST /ai/provider/test: one five-word prompt, through the
// real boundary, to the configuration in the form. It carries no data.
func (h *PlatformAIHandlers) TestProvider(c *gin.Context) {
	actor, ok := requirePlatformActor(c)
	if !ok {
		return
	}
	cand, ok := h.prepare(c)
	if !ok {
		return
	}
	provider, err := ai.BuildUnsaved(cand.stored, cand.plainKey, cand.stored.AllowPrivateEndpoints)
	if err != nil {
		c.JSON(http.StatusOK, platformAITestResult{Reason: "error", Message: platformConfigProblem(err)})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), platformProviderTestBudget)
	defer cancel()
	ctx = auditmw.WithAIActor(ctx, uuid.Nil, "platform")

	started := time.Now()
	resp, err := ai.Boundary(provider, h.sink).Complete(ctx, ai.Request{
		Seam:      ai.SeamQuery,
		Invoker:   actor.String(),
		Model:     cand.stored.Model,
		System:    "This is a connection test from Vista Platform.",
		Messages:  []ai.Message{{Role: "user", Content: "Reply with the single word OK."}},
		MaxTokens: 64,
	})
	out := platformAITestResult{LatencyMS: time.Since(started).Milliseconds()}
	host := cand.stored.Host()
	if host == "" {
		host = "the provider"
	}
	switch {
	case err == nil:
		out.OK, out.ModelID = true, resp.ModelID
	case errors.Is(err, ai.ErrUnauthorized):
		out.Reason, out.Message = "unauthorized", "Reached "+host+", but it rejected the API key."
	case errors.Is(err, ai.ErrPrivateEndpoint):
		out.Reason, out.Message = "private_endpoint", platformConfigProblem(err)
	case errors.Is(err, ai.ErrRateLimited):
		out.Reason, out.Message = "rate_limited", "Reached "+host+", and it is rate-limiting this key right now. The connection itself works."
	case errors.Is(err, ai.ErrProviderUnavailable), errors.Is(err, context.DeadlineExceeded):
		out.Reason, out.Message = "unreachable", "Could not get an answer from "+host+". Check the address, and that this cluster is allowed to reach it (egress policy, DNS, a private address without the private-network switch)."
	default:
		out.Reason, out.Message = "error", host+" answered, but not with something usable. Check the model id."
	}
	c.JSON(http.StatusOK, out)
}
