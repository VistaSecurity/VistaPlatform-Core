package api

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

// Settings → AI assistant, the provider half: a tenant connecting, testing and
// disconnecting a model provider of its own.
//
//	PUT    /tenant/ai/provider        connect or change
//	DELETE /tenant/ai/provider        disconnect
//	POST   /tenant/ai/provider/test   try the values in the form, unsaved
//
// All three require settings.update, like PUT /tenant/ai.
//
// # What a tenant cannot do here
//
//   - Decide that a private address is acceptable. That is one switch, held by
//     whoever runs the deployment; a tenant's request has no field for it and
//     the stored row is never read for it.
//   - Reuse a stored key against a different endpoint. A save that changes the
//     kind or the base URL must carry the key again — otherwise anyone who may
//     edit the settings could repoint the endpoint at a host of their own and
//     have the platform deliver a credential they were never shown.
//   - Read the key back. Nothing here returns it; the status carries the last
//     four characters.

// aiProviderRequest is the body of PUT and of the test.
type aiProviderRequest struct {
	Kind    string `json:"kind"`
	BaseURL string `json:"base_url"`
	Model   string `json:"model"`

	// APIKey is a pointer because "not sent" and "sent empty" are different
	// requests: omitted keeps the stored key (same endpoint only), and an empty
	// string means this endpoint has no credential.
	APIKey *string `json:"api_key"`
}

// aiProviderTestResponse is the body of the test.
type aiProviderTestResponse struct {
	OK        bool   `json:"ok"`
	ModelID   string `json:"model_id,omitempty"`
	LatencyMS int64  `json:"latency_ms,omitempty"`

	// Reason classifies a failure: "unauthorized", "unreachable",
	// "private_endpoint", "rate_limited" or "error".
	Reason string `json:"reason,omitempty"`

	// Message is the sentence the form shows.
	Message string `json:"message,omitempty"`
}

// providerTestBudget bounds a connection test. Long enough for a self-hosted
// model on modest hardware to answer five words, short enough that a wrong
// address is reported while the person is still looking at the form.
const providerTestBudget = 45 * time.Second

func decodeAIProviderRequest(c *gin.Context) (aiProviderRequest, error) {
	var req aiProviderRequest
	if c.Request.Body == nil {
		return req, errors.New("empty request body")
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	req.Kind = ai.NormalizeKind(req.Kind)
	req.BaseURL = strings.TrimSpace(req.BaseURL)
	req.Model = strings.TrimSpace(req.Model)
	return req, nil
}

// providerCandidate is a decoded, permitted, validated request: the stored
// shape it would become, the credential in clear for building it, and whether
// that credential is the one already stored.
type providerCandidate struct {
	stored       ai.StoredProvider
	plainKey     string
	reusedKey    bool
	allowPrivate bool
}

// prepareTenantProvider runs everything PUT and the test share, and answers the
// request itself when it refuses. ok is false when it has.
func (d aiDeployment) prepareTenantProvider(c *gin.Context, tenantID uuid.UUID) (providerCandidate, bool) {
	var none providerCandidate
	if d.resolver == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Provider settings are not available on this deployment."})
		return none, false
	}

	req, err := decodeAIProviderRequest(c)
	if err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "This endpoint takes kind, base_url, model and api_key: " + err.Error()})
			return none, false
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return none, false
	}

	kinds := ai.RegisteredProviders()
	if len(kinds) == 0 {
		// Core. The page never offers the form here; a direct call gets the
		// same answer every other Enterprise capability gives.
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

	ctx := c.Request.Context()
	described, err := d.resolver.DescribeTenant(ctx, tenantID)
	if err != nil {
		log.Printf("[ai-settings] tenant permission for %s: %v", tenantID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the AI assistant settings"})
		return none, false
	}
	perm := described.Permission
	switch {
	case !perm.PlatformAllows:
		c.JSON(http.StatusForbidden, gin.H{"error": "Whoever runs this deployment has not allowed organizations to connect their own model provider."})
		return none, false
	case !perm.PlanAllows:
		c.JSON(http.StatusPaymentRequired, gin.H{"error": "Your plan does not include connecting your own model provider."})
		return none, false
	}

	if req.Kind == ai.ProviderOpenAICompat {
		// Said here, in the form's words. The client constructor refuses these
		// too, but in an operator's words — it names environment variables a
		// tenant has never seen.
		if req.BaseURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Enter the endpoint's base URL."})
			return none, false
		}
		if req.Model == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Enter the model id your endpoint serves."})
			return none, false
		}
	}

	cand := providerCandidate{
		stored:       ai.StoredProvider{Kind: req.Kind, BaseURL: req.BaseURL, Model: req.Model},
		allowPrivate: perm.PrivateEndpoints,
	}

	if req.APIKey != nil {
		cand.plainKey = strings.TrimSpace(*req.APIKey)
	} else {
		existing := described.TenantStored
		if existing != nil && existing.APIKeyEnc != "" {
			if !existing.SameEndpoint(cand.stored) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "The provider or its address changed, so the API key has to be entered again."})
				return none, false
			}
			plain, err := d.resolver.Cipher().Open(existing.APIKeyEnc)
			if err != nil {
				log.Printf("[ai-settings] open stored key for %s: %v", tenantID, err)
				c.JSON(http.StatusConflict, gin.H{"error": "The saved API key can no longer be read. Enter it again."})
				return none, false
			}
			cand.plainKey = plain
			cand.reusedKey = true
			cand.stored.APIKeyEnc = existing.APIKeyEnc
			cand.stored.APIKeyHint = existing.APIKeyHint
		}
	}

	// Build it, which is the validation: the URL's shape, a literal private
	// address, a missing credential where one is required.
	if _, err := ai.BuildUnsaved(cand.stored, cand.plainKey, cand.allowPrivate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": providerConfigProblem(err)})
		return none, false
	}
	return cand, true
}

// providerConfigProblem is the sentence for a configuration the client
// constructor refused.
func providerConfigProblem(err error) string {
	switch {
	case errors.Is(err, ai.ErrPrivateEndpoint):
		return "That address is on a private network. Whoever runs this deployment has to allow private endpoints for organizations before one can be used."
	case strings.Contains(err.Error(), "no API key"):
		return "Enter the API key for this provider."
	case strings.Contains(err.Error(), "base URL"):
		return "The base URL is not usable: it must be an http or https address with a host."
	default:
		return "That provider configuration could not be used."
	}
}

// putTenantAIProviderHandler serves PUT /tenant/ai/provider.
func putTenantAIProviderHandler(db *sql.DB, dep aiDeployment) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := tenantIDFromContext(c)
		if !ok {
			return
		}
		userID, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}
		cand, ok := dep.prepareTenantProvider(c, tenantID)
		if !ok {
			return
		}

		if !cand.reusedKey {
			enc, hint, err := dep.resolver.Cipher().Seal(cand.plainKey)
			if errors.Is(err, ai.ErrNoMasterKey) {
				c.JSON(http.StatusConflict, gin.H{"error": "This deployment cannot store credentials yet: whoever runs it needs to set its encryption key."})
				return
			}
			if err != nil {
				log.Printf("[ai-settings] seal key for %s: %v", tenantID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the provider"})
				return
			}
			cand.stored.APIKeyEnc, cand.stored.APIKeyHint = enc, hint
		}

		ctx := c.Request.Context()
		if err := ai.SetTenantProvider(ctx, db, tenantID, userID, cand.stored); err != nil {
			log.Printf("[ai-settings] save provider for %s: %v", tenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the provider"})
			return
		}
		respondWithTenantAIStatus(c, db, dep, tenantID)
	}
}

// deleteTenantAIProviderHandler serves DELETE /tenant/ai/provider.
func deleteTenantAIProviderHandler(db *sql.DB, dep aiDeployment) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := tenantIDFromContext(c)
		if !ok {
			return
		}
		userID, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}
		// No permission check beyond the route's: removing your own provider
		// must stay possible after a plan change took the capability away, or
		// the credential would be stranded in the row with no way to delete it.
		if err := ai.DeleteTenantProvider(c.Request.Context(), db, tenantID, userID); err != nil {
			log.Printf("[ai-settings] delete provider for %s: %v", tenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disconnect the provider"})
			return
		}
		respondWithTenantAIStatus(c, db, dep, tenantID)
	}
}

// respondWithTenantAIStatus answers a write with the same body GET returns, so
// the page replaces its state from the response.
func respondWithTenantAIStatus(c *gin.Context, db *sql.DB, dep aiDeployment, tenantID uuid.UUID) {
	tc, err := ai.TenantAIControls(c.Request.Context(), db, tenantID)
	if err != nil {
		log.Printf("[ai-settings] read tenant AI controls for %s: %v", tenantID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Saved, but the settings could not be read back. Reload the page."})
		return
	}
	dep.respond(c, tenantID, tc)
}

// testTenantAIProviderHandler serves POST /tenant/ai/provider/test.
//
// It sends one five-word prompt through the real boundary — redacted, audited,
// attributed to the person who pressed the button — to the configuration in
// the form, which need not have been saved. It carries no tenant data.
//
// The tenant's kill switch applies. "No generative call runs for your
// organization" has no exception for a test, and a page that could send a
// prompt while saying the assistant is off would be saying something untrue.
func testTenantAIProviderHandler(db *sql.DB, dep aiDeployment) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := tenantIDFromContext(c)
		if !ok {
			return
		}
		userID, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}
		cand, ok := dep.prepareTenantProvider(c, tenantID)
		if !ok {
			return
		}

		controls, err := ai.TenantAIControls(c.Request.Context(), db, tenantID)
		if err != nil {
			log.Printf("[ai-settings] read tenant AI controls for %s: %v", tenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the AI assistant settings"})
			return
		}
		if controls.AssistantDisabled {
			c.JSON(http.StatusConflict, gin.H{"error": "The AI assistant is turned off for your organization, so nothing was sent. Turn it on to test a provider."})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), providerTestBudget)
		defer cancel()
		ctx = auditmw.WithAIActor(ctx, tenantID, "tenant")
		ctx = ai.WithTenantControls(ctx, controls)

		c.JSON(http.StatusOK, runProviderTest(ctx, cand, userID.String(), dep.sink))
	}
}

// runProviderTest builds the candidate and asks it for one word.
func runProviderTest(ctx context.Context, cand providerCandidate, invoker string, sink ai.AuditSink) aiProviderTestResponse {
	provider, err := ai.BuildUnsaved(cand.stored, cand.plainKey, cand.allowPrivate)
	if err != nil {
		return aiProviderTestResponse{Reason: "error", Message: providerConfigProblem(err)}
	}
	started := time.Now()
	resp, err := ai.Boundary(provider, sink).Complete(ctx, ai.Request{
		Seam:      ai.SeamQuery,
		Invoker:   invoker,
		Model:     cand.stored.Model,
		System:    "This is a connection test from Vista Platform.",
		Messages:  []ai.Message{{Role: "user", Content: "Reply with the single word OK."}},
		MaxTokens: 64,
	})
	elapsed := time.Since(started).Milliseconds()
	if err == nil {
		return aiProviderTestResponse{OK: true, ModelID: resp.ModelID, LatencyMS: elapsed}
	}

	out := aiProviderTestResponse{LatencyMS: elapsed}
	host := cand.stored.Host()
	if host == "" {
		host = "the provider"
	}
	switch {
	case errors.Is(err, ai.ErrUnauthorized):
		out.Reason, out.Message = "unauthorized", "Reached "+host+", but it rejected the API key."
	case errors.Is(err, ai.ErrPrivateEndpoint):
		out.Reason, out.Message = "private_endpoint", providerConfigProblem(err)
	case errors.Is(err, ai.ErrRateLimited):
		out.Reason, out.Message = "rate_limited", "Reached "+host+", and it is rate-limiting this key right now. The connection itself works."
	case errors.Is(err, ai.ErrProviderUnavailable), errors.Is(err, context.DeadlineExceeded):
		out.Reason, out.Message = "unreachable", "Could not get an answer from "+host+". Check the address, and that this deployment is allowed to reach it."
	default:
		out.Reason, out.Message = "error", host+" answered, but not with something usable. Check the model id."
	}
	return out
}
