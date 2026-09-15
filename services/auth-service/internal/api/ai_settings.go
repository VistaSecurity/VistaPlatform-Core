package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/ai"
	aiedition "github.com/vistasecurity/vistaplatform/shared/ai/edition"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

// Settings → AI assistant, tenant plane: `GET`/`PUT /tenant/ai`.
//
// # Why auth-service owns it
//
// It already owns `tenant_admin_settings` — `SetTenantOnboardingRequired` and
// `GetTenantAdminSettingsConfig` are in this package — and the two tenant AI
// controls live in that same jsonb blob. It also already serves the tenant
// plane's other "what is this deployment like" reads (`/tenant/features`,
// `/tenant/trial-status`), which is what the status half of this is.
//
// # What it can honestly say about the deployment, and what it cannot
//
// The seams live in other services: the narrator in cbom-service, the author in
// compliance-engine, the enricher in admin-service. This service cannot see
// which implementation any of them registered, and an endpoint that claimed to
// would be guessing.
//
// What it CAN observe is exactly the two facts that decide whether any of them
// can reach a model at all, and both are properties of the deployment rather
// than of one process:
//
//   - the provider environment (`AI_PROVIDER` and friends), which the chart
//     sets on every backend from one place; and
//   - whether this binary links the Enterprise providers
//     ([edition.Linked]), which is a property of the image line — every
//     service in a release is built with the same tags.
//
// Those two, plus [seams.Catalogue]'s per-seam facts, are what the page shows.
// A seam is reported `live` when something could actually answer through it;
// anything less certain than that is reported false, because a settings page
// saying a capability is on when it is not is the failure this whole area is
// written against.
//
// # No secret ever crosses
//
// The response carries the provider KIND and the model id. Not the base URL
// (which is an internal endpoint on a self-hosted deployment), not the name of
// the environment variable holding the key, and — there being no such field in
// [ai.ProviderConfig] at all — not the key. A test asserts the first two are
// absent from the serialised body.

// authoringDisabledInterim mirrors the interim, deployment-wide disable of
// AI-assisted authoring on TENANT custom policies.
//
// It is NOT a tenant setting and is not writable here. Custom policies are not
// evaluated yet — they produce no finding and no score for any tenant — so
// authoring them (by hand or with the author seam) is switched off until that
// is fixed. Tracking:.
//
// The user-facing copy for it lives in ONE place, the `authoringDisabled` entry
// on the `custom-policies` item in `frontend-v2/src/sections/settings/nav.ts`,
// and the AI assistant page renders that copy rather than a second sentence
// saying the same thing differently. This constant is the boolean half.
//
// WHEN IS FIXED: flip this to false AND delete the `authoringDisabled`
// entry in nav.ts. Either one alone leaves the product telling a user two
// different things about the same capability.
const authoringDisabledInterim = true

// aiSeamStatus is one row of the "what is turned on" table.
type aiSeamStatus struct {
	Key string `json:"key"`

	// Live is whether something can answer through this seam in this
	// deployment right now. For a classical seam that means a deterministic
	// implementation ships and is the default; for a generative one it
	// additionally means this build has the providers and the environment
	// names a reachable one.
	Live bool `json:"live"`

	// Built is whether an implementation a user can reach exists in the product
	// at all, in ANY edition. It is edition-INDEPENDENT and provider-
	// independent, which is exactly why it has to be on the wire beside Live:
	// the two reasons Live can be false are "your edition does not have it" and
	// "nobody has written it yet", and a client that can see only Live has to
	// guess between them.
	//
	// It guessed wrong. A Core build reports edition_linked:false, so an
	// unbuilt Enterprise-family seam looked identical to a built one and the
	// page labelled it "Enterprise" — telling a Core reader that a capability
	// nothing implements is theirs on upgrade. The same seam on an Enterprise
	// build correctly read "Not yet built". Whether something has been written
	// is not a fact about the reader's licence.
	Built bool `json:"built"`

	// EditionRequired is "core" or "enterprise".
	EditionRequired string `json:"edition_required"`

	// Family is "classical" or "generative". Only generative seams send
	// anything to a provider, which is the distinction the page groups on.
	Family string `json:"family"`

	// Surface is where a user meets this seam, absent when nothing consumes it
	// yet.
	Surface string `json:"surface,omitempty"`

	// RuleDefault is what answers when no model does. Never empty: it is the
	// product's central claim, stated per seam.
	RuleDefault string `json:"rule_default"`
}

// aiTenantControls is the tenant half of the response.
type aiTenantControls struct {
	// RecordQuestions and AssistantDisabled are the tenant's own, writable
	// through PUT.
	RecordQuestions   bool `json:"record_questions"`
	AssistantDisabled bool `json:"assistant_disabled"`

	// AuthoringDisabled is READ-ONLY here: it is the interim, not a
	// tenant decision. It is on this object rather than beside it because what
	// a tenant needs to know is one list of "what is switched off for me and
	// why", and splitting it by who owns the switch would put half the answer
	// somewhere else.
	AuthoringDisabled bool `json:"authoring_disabled"`
}

// aiStatusResponse is the body of both GET and PUT. One shape, so a client that
// saves can replace its state from the response rather than re-fetching — and
// so there is one schema for the contract test to hold.
type aiStatusResponse struct {
	// ProviderConfigured is whether a model endpoint is configured AND this
	// build can construct it. False in Core even when AI_PROVIDER names one,
	// which is the truth: a Core build has no provider implementations.
	ProviderConfigured bool `json:"provider_configured"`

	// ProviderName is the provider KIND — "anthropic" or "openai_compat" —
	// absent when nothing is configured. Never the base URL, never the name of
	// the variable holding the credential.
	ProviderName string `json:"provider_name,omitempty"`

	// ModelID is the configured model id, absent when the operator left it to
	// the provider's default.
	ModelID string `json:"model_id,omitempty"`

	// EditionLinked reports whether this build has the generative providers at
	// all. It is what lets the page say "not part of this edition" instead of
	// "nobody has configured this", which are different problems with different
	// fixes and only one of them is the reader's.
	EditionLinked bool `json:"edition_linked"`

	Seams  []aiSeamStatus   `json:"seams"`
	Tenant aiTenantControls `json:"tenant"`
}

// aiDeployment is the deployment-level half of the answer, resolved ONCE at
// wiring time.
//
// Once rather than per request because ai.NewFromEnv logs a warning for an
// unrecognised AI_PROVIDER — correctly, it is a misconfiguration — and a
// settings page polled by every tenant admin would turn that into a log flood.
// Nothing it reads can change without a pod restart: the environment is
// injected at pod start (see the envFrom note in CLAUDE.md) and the build tags
// are the binary's.
type aiDeployment struct {
	providerConfigured bool
	providerName       string
	modelID            string
	editionLinked      bool
	seams              []aiSeamStatus
}

// resolveAIDeployment reads the environment and the build once.
func resolveAIDeployment() aiDeployment {
	cfg := ai.ProviderConfigFromEnv()
	provider, err := ai.NewFromEnv()
	if err != nil {
		// Never fatal. ai.NewFromEnv always returns a usable provider
		// (NoneProvider here), so the only thing lost is the generative half —
		// and an operator who set AI_PROVIDER needs to be told it did not take.
		log.Printf("[ai-settings] AI provider not configured: %v", err)
	}

	dep := aiDeployment{
		providerConfigured: provider != nil && provider.Available(),
		editionLinked:      aiedition.Linked(),
	}
	if dep.providerConfigured {
		dep.providerName = ai.NormalizeKind(cfg.Kind)
		dep.modelID = cfg.Model
	}

	for _, info := range seams.Catalogue() {
		row := aiSeamStatus{
			Key:             string(info.Seam),
			Built:           info.Shipped,
			EditionRequired: info.EditionRequired,
			Family:          info.Family,
			Surface:         info.Surface,
			RuleDefault:     info.RuleDefault,
		}
		switch {
		case !info.Shipped:
			// Nothing implements this seam yet, in any edition. No provider
			// makes that untrue, and reporting it live because one is
			// configured would be the settings page claiming a capability that
			// does not exist.
			row.Live = false
		case info.Family == seams.FamilyClassical:
			// Classical seams run in-process and never consult a provider.
			// Shipped means a deterministic implementation is the default.
			row.Live = true
		default:
			// Generative: needs BOTH the Enterprise implementations in the
			// build and a provider this deployment can reach.
			row.Live = dep.editionLinked && dep.providerConfigured
		}
		dep.seams = append(dep.seams, row)
	}
	return dep
}

// respond writes the deployment half plus a tenant's controls.
func (d aiDeployment) respond(c *gin.Context, tc ai.TenantControls) {
	c.JSON(http.StatusOK, aiStatusResponse{
		ProviderConfigured: d.providerConfigured,
		ProviderName:       d.providerName,
		ModelID:            d.modelID,
		EditionLinked:      d.editionLinked,
		Seams:              d.seams,
		Tenant: aiTenantControls{
			RecordQuestions:   tc.RecordQuestions,
			AssistantDisabled: tc.AssistantDisabled,
			AuthoringDisabled: authoringDisabledInterim,
		},
	})
}

// getTenantAIHandler serves GET /tenant/ai.
func getTenantAIHandler(db *sql.DB, dep aiDeployment) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := tenantIDFromContext(c)
		if !ok {
			return
		}
		tc, err := ai.TenantAIControls(c.Request.Context(), db, tenantID)
		if err != nil {
			log.Printf("[ai-settings] read tenant AI controls for %s: %v", tenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the AI assistant settings"})
			return
		}
		dep.respond(c, tc)
	}
}

// aiControlsRequest is the PUT body. Both fields are pointers so a client can
// send one switch without having to know the other's current value — and so an
// omitted field is distinguishable from `false`, which is a real value here and
// the default one.
type aiControlsRequest struct {
	AssistantDisabled *bool `json:"assistant_disabled"`
	RecordQuestions   *bool `json:"record_questions"`
}

// decodeAIControlsRequest decodes the PUT body and REFUSES a key this endpoint
// does not write.
//
// `TenantAIControlsUpdate` in the spec is `additionalProperties: false`, and a
// server that accepts what its own schema forbids is a server whose schema is a
// comment. The key that makes it matter is `authoring_disabled`: it is reported
// on the same object by GET, it is read-only, and `encoding/json`'s default
// would take a client's attempt to switch it off, answer 200, and return a body
// still saying it is on. "Ignored silently" and "saved" are indistinguishable to
// a caller, which is the shape this repository keeps finding.
//
// gin's ShouldBindJSON cannot do this — it does not set DisallowUnknownFields —
// so the decoder is built here. The error names the offending field, because
// "invalid request body" for a well-formed body sends a client looking for a
// syntax error that is not there.
func decodeAIControlsRequest(c *gin.Context) (aiControlsRequest, error) {
	var req aiControlsRequest
	if c.Request.Body == nil {
		return req, errors.New("empty request body")
	}
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, err
	}
	return req, nil
}

// updateTenantAIHandler serves PUT /tenant/ai.
func updateTenantAIHandler(db *sql.DB, dep aiDeployment) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := tenantIDFromContext(c)
		if !ok {
			return
		}
		userID, err := uuid.Parse(c.GetString("userID"))
		if err != nil {
			// The settings-audit trigger records updated_by, and an unattributed
			// settings change is the shape D4.7 refuses elsewhere. Refuse it
			// here too rather than writing a NULL actor.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		req, err := decodeAIControlsRequest(c)
		if err != nil {
			if strings.Contains(err.Error(), "unknown field") {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "This endpoint writes only assistant_disabled and record_questions: " + err.Error(),
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		if req.AssistantDisabled == nil && req.RecordQuestions == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No settings to update"})
			return
		}

		// Read-modify-write, so a client sending one switch does not silently
		// reset the other to its zero value. The write itself merges into the
		// settings blob, so the tenant's unrelated settings survive either way.
		current, err := ai.TenantAIControls(c.Request.Context(), db, tenantID)
		if err != nil {
			log.Printf("[ai-settings] read-before-write for %s: %v", tenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the AI assistant settings"})
			return
		}
		next := current
		if req.AssistantDisabled != nil {
			next.AssistantDisabled = *req.AssistantDisabled
		}
		if req.RecordQuestions != nil {
			next.RecordQuestions = *req.RecordQuestions
		}

		if err := ai.SetTenantAIControls(c.Request.Context(), db, tenantID, userID, next); err != nil {
			if errors.Is(err, ai.ErrNoTenantScope) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
				return
			}
			log.Printf("[ai-settings] write tenant AI controls for %s: %v", tenantID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the AI assistant settings"})
			return
		}
		dep.respond(c, next)
	}
}

// tenantIDFromContext resolves the caller's tenant, answering the request
// itself on failure. Same two failures every tenant-scoped handler in this
// package has, kept together so they answer identically.
func tenantIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	raw := c.GetString("tenantID")
	if raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return uuid.Nil, false
	}
	return id, true
}
