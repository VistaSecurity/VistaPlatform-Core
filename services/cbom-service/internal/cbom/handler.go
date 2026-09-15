package cbom

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/middleware"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

// generatorVersion is recorded in provenance. Bumped when the generation
// pipeline changes shape (so old artifacts are recognisable as "produced by
// the previous generator").
const generatorVersion = "phase-2.0"

// Artifact list paging. maxArtifactLimit matches the repository's own clamp.
const (
	defaultArtifactLimit = 50
	maxArtifactLimit     = 200
)

// FeatureCBOMSigning is the tenant entitlement for the audit-grade CBOM
// evidence surface: signing, compliance-attestation layers, drift comparison,
// and alternate evidence exports.
const FeatureCBOMSigning = "cbom_signing"

// artifactStore is the persistence surface the Handler needs. *Repository is
// the production implementation; depending on the interface (rather than the
// concrete type) lets the HTTP layer be exercised by the contract test with an
// in-memory stub, no database required. Keep this in sync with the methods
// the handlers below actually call.
type artifactStore interface {
	List(ctx context.Context, tenantID uuid.UUID, scopeID *uuid.UUID, kind ArtifactKind, limit int) ([]Artifact, error)
	Get(ctx context.Context, tenantID, artifactID uuid.UUID) (*Artifact, error)
	GetInlineContent(ctx context.Context, tenantID, artifactID uuid.UUID) ([]byte, error)
	SoftDelete(ctx context.Context, tenantID, artifactID uuid.UUID) error
}

// scopeGetter is the subset of the scopes repository the Handler needs to
// resolve a generate request's scope_id. Matches *scopes.Repository.Get.
type scopeGetter interface {
	Get(ctx context.Context, tenantID, scopeID uuid.UUID) (*scopes.Scope, error)
}

// cbomBuilder is the build-from-inventory step. *Builder is the production
// implementation.
type cbomBuilder interface {
	Build(ctx context.Context, kind ArtifactKind, scope *scopes.Scope, authToken string) (*BuildOutput, error)
}

// ocsfRenderer projects an inventory artifact's canonical bytes into the OCSF
// event stream. *xbom.RenderOCSF is the production implementation; it is a
// function value rather than an interface because there is exactly one method
// and no state.
//
// Unlike the Enterprise ArtifactFormatter this is CORE — a SIEM is where an ops
// team already looks, and putting the one export that reaches them behind a
// paywall would make the free edition unusable in the place it has to work. It
// is injected rather than imported directly only to keep the import graph
// one-way: xbom already depends on this package for ArtifactKind and
// BuildOutput.
type ocsfRenderer func(canonicalBytes []byte) (body []byte, contentType string, err error)

// cbomPersister is the persist-build-to-row step. *Persister is the production
// implementation.
type cbomPersister interface {
	Persist(ctx context.Context, in PersistInput) (*Artifact, error)
}

type featureChecker interface {
	CheckFeatureAccess(tenantID uuid.UUID, feature string) (bool, error)
}

// Handler exposes CBOM artifact endpoints over HTTP. Routes are mounted under
// /api/v1/cbom-service/cbom from cmd/main.go.
type Handler struct {
	repo           artifactStore
	builder        cbomBuilder
	persister      cbomPersister
	scopeRepo      scopeGetter
	storage        sharedstorage.ArtifactStorageService // optional; used for presigned download URLs
	signer         Signer                               // Phase 4: nil-tolerant; used by /verify
	formatter      ArtifactFormatter                    // Enterprise: SPDX/PDF rendering; nil in Core
	ocsf           ocsfRenderer                         // Core: OCSF event-stream projection; nil disables ?format=ocsf
	featureChecker featureChecker                       // tenant runtime entitlement gate
}

// NewHandler wires the artifact REST endpoints. storage may be nil (no S3
// configured); inline-only artifacts still work for list/get/download.
func NewHandler(repo *Repository, builder *Builder, persister *Persister, scopeRepo *scopes.Repository, storage sharedstorage.ArtifactStorageService) *Handler {
	return &Handler{
		repo:      repo,
		builder:   builder,
		persister: persister,
		scopeRepo: scopeRepo,
		storage:   storage,
	}
}

// RegisterRoutes mounts the artifact endpoints. Caller is responsible for
// applying auth + tenant middleware to the group. writeGate guards generate /
// delete / verify (evidence-grade artifact mutation —); list, get
// and download stay tenant-wide reads.
func (h *Handler) RegisterRoutes(rg *gin.RouterGroup, writeGate ...gin.HandlerFunc) {
	rg.POST("/cbom/generate", append(append([]gin.HandlerFunc{}, writeGate...), h.generate)...)
	rg.GET("/cbom/artifacts", h.list)
	rg.GET("/cbom/artifacts/:id", h.get)
	rg.GET("/cbom/artifacts/:id/download", h.download)
	rg.DELETE("/cbom/artifacts/:id", append(append([]gin.HandlerFunc{}, writeGate...), h.softDelete)...)
	rg.POST("/cbom/artifacts/:id/verify", append(append([]gin.HandlerFunc{}, writeGate...), h.verify)...)
}

// SetSigner wires the Phase 4 signer used by the verify endpoint.
// Optional — when unset, /verify checks the hash only and reports the
// artifact as "unsigned" or "signature not verifiable here."
func (h *Handler) SetSigner(s Signer) { h.signer = s }

// SetArtifactFormatter wires the Enterprise renderer for the alternate download
// formats (SPDX, PDF). Unset in Core, where /download?format=spdx|pdf answers
// 402 Payment Required.
//
// Callers must pass a genuinely nil interface when there is no renderer — a nil
// *Concrete boxed into ArtifactFormatter is non-nil and would defeat the gate,
// which is why the Enterprise implementation is a value type.
func (h *Handler) SetArtifactFormatter(f ArtifactFormatter) { h.formatter = f }

// SetOCSFRenderer wires the Core OCSF projection used by
// /download?format=ocsf. Unwired, that format answers 501 — "this deployment
// cannot render it", which is a wiring fault, not a missing subscription and
// not a malformed request.
func (h *Handler) SetOCSFRenderer(r ocsfRenderer) { h.ocsf = r }

// SetFeatureChecker wires the tenant runtime entitlement gate. Leaving it nil
// fails closed for paid CBOM evidence features; Core artifact generation and
// CycloneDX download remain available.
func (h *Handler) SetFeatureChecker(fc featureChecker) { h.featureChecker = fc }

// generate — POST /cbom/generate. Body: { scope_id, name? }. Snapshots
// inventory matching the scope as of now and writes one immutable artifact.
//
// Phase 2 is sync — the call returns once the artifact row is committed.
// Tens of MB / thousands of components fit well under typical HTTP timeouts.
// If we observe large tenants pushing past 30s we'll move to async/queue.
func (h *Handler) generate(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	userID, _ := middleware.GetUserIDFromContext(c)

	var req GenerateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sharedapi.BadRequest(c, "invalid request body")
		return
	}

	// An omitted kind is `cbom` — what this endpoint produced before kinds
	// existed, so no client changes meaning by not changing. An unknown one is
	// 400 and names the vocabulary rather than silently defaulting: a typo'd
	// "sboM" that quietly produced a CBOM would be discovered by an auditor,
	// not by the person who typed it.
	kind := req.Kind
	if kind == "" {
		kind = KindCBOM
	}
	if !kind.IsValid() {
		sharedapi.BadRequest(c, fmt.Sprintf("kind must be one of: %s", kindVocabulary()))
		return
	}

	cbomSigningEntitled, ok := h.cbomSigningEntitled(c, tenantID)
	if !ok {
		return
	}
	sign := BoolDefault(req.Sign, cbomSigningEntitled)
	includeAttestation := BoolDefault(req.IncludeAttestation, cbomSigningEntitled)
	if !cbomSigningEntitled && (boolPtrTrue(req.Sign) || boolPtrTrue(req.IncludeAttestation)) {
		h.respondCBOMSigningRequired(c)
		return
	}

	// Resolve scope first — fail fast if missing / not authorized.
	scope, err := h.scopeRepo.Get(c.Request.Context(), tenantID, req.ScopeID)
	if errors.Is(err, scopes.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "scope not found"})
		return
	}
	if err != nil {
		log.Printf("resolve scope: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	authToken := extractAuthToken(c)
	if authToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	build, err := h.builder.Build(ctx, kind, scope, authToken)
	if errors.Is(err, ErrKindUnavailable) {
		// 501, not 400 and not 500: the kind is one this build recognises, the
		// request is well-formed, and the deployment simply has no assembler
		// wired for it. Reporting it as a client error would send someone to
		// fix a request that was correct.
		c.JSON(http.StatusNotImplemented, gin.H{
			"error": fmt.Sprintf("this deployment cannot generate a %s artifact", kind),
		})
		return
	}
	var invalidScope *InvalidScopeQueryError
	if errors.As(err, &invalidScope) {
		// 422, not 500: the request is well-formed, but the scope's stored
		// query no longer validates, so the artifact this would produce is not
		// the one the scope describes. Producing a wider CBOM and saying
		// nothing is the bug being avoided, so refusing is the correct answer.
		//
		// The body carries QUERY_LANGUAGE §10's diagnostics, not a sentence:
		// the fix is to go and edit the scope, and the person doing that needs
		// to know WHICH term stopped validating.
		body := gin.H{"error": invalidScope.Error(), "query": invalidScope.Query}
		if qe, ok := scopes.AsInvalidQuery(invalidScope); ok {
			diagnostics := make([]gin.H, 0, len(qe.Errors))
			for _, e := range qe.Errors {
				item := gin.H{
					"code":    string(e.Code),
					"message": e.Message,
					"span":    gin.H{"start": e.Span.Start, "end": e.Span.End},
				}
				if e.Suggestion != "" {
					item["suggestion"] = e.Suggestion
				}
				diagnostics = append(diagnostics, item)
			}
			body["errors"] = diagnostics
		}
		c.JSON(http.StatusUnprocessableEntity, body)
		return
	}
	if err != nil {
		log.Printf("build cbom: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	artifact, err := h.persister.Persist(ctx, PersistInput{
		Scope:                scope,
		Build:                build,
		Name:                 req.Name,
		GeneratedBy:          userID,
		InputDataFreshnessAt: time.Now().UTC(), // Phase 2 stub; Phase 3 should query last-sensor-sweep
		Provenance: Provenance{
			GeneratorService: "cbom-service",
			GeneratorVersion: generatorVersion,
			RequestID:        c.GetHeader("X-Request-ID"),
		},
		// Phase 4 toggles are audit-ready by default only for entitled tenants.
		// Core/unentitled tenants still generate canonical CycloneDX artifacts.
		IncludeAttestation: includeAttestation,
		Sign:               sign,
	})
	if err != nil {
		log.Printf("persist cbom: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Degradations are reported, not just logged. Both of these used to be
	// server-side log lines only, so a caller had no way to tell an artifact
	// stored in the object store from one that fell back to the database, or an
	// artifact with nothing to attest from one whose attestation query failed.
	c.JSON(http.StatusAccepted, GenerateResponse{
		ArtifactID:       artifact.ID,
		Status:           "ready",
		StorageDegraded:  artifact.StorageDegraded,
		AttestationError: artifact.AttestationError,
	})
}

// list — GET /cbom/artifacts?scope_id=&limit=.
func (h *Handler) list(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}

	var scopeFilter *uuid.UUID
	if s := c.Query("scope_id"); s != "" {
		parsed, err := uuid.Parse(s)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope_id"})
			return
		}
		scopeFilter = &parsed
	}

	// ?kind=. Absent means every kind, not `cbom` — this is one list of the
	// tenant's artifacts, and defaulting the filter would hide the SBOM someone
	// just generated behind a filter they never set. An unknown value is 400
	// rather than "matches nothing", which would read as an empty inventory.
	kindFilter := ArtifactKind(c.Query("kind"))
	if kindFilter != "" && !kindFilter.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("kind must be one of: %s", kindVocabulary())})
		return
	}

	// ?limit=N, documented in the OpenAPI spec and previously ignored — the
	// value was hardcoded at 50 with a comment claiming otherwise. Out-of-range
	// and unparseable values fall back to the default rather than erroring; the
	// repository clamps again as a backstop.
	limit := defaultArtifactLimit
	if raw := c.Query("limit"); raw != "" {
		parsed, convErr := strconv.Atoi(raw)
		if convErr != nil || parsed < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be a positive integer"})
			return
		}
		if parsed > maxArtifactLimit {
			parsed = maxArtifactLimit
		}
		limit = parsed
	}

	artifacts, err := h.repo.List(c.Request.Context(), tenantID, scopeFilter, kindFilter, limit)
	if err != nil {
		log.Printf("list artifacts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"artifacts": artifacts})
}

// get — GET /cbom/artifacts/:id.
func (h *Handler) get(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	artifactID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid artifact id"})
		return
	}
	a, err := h.repo.Get(c.Request.Context(), tenantID, artifactID)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "artifact not found"})
		return
	}
	if err != nil {
		log.Printf("get artifact: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, a)
}

// download — GET /cbom/artifacts/:id/download?format=cyclonedx|spdx|pdf.
//
//	cyclonedx → canonical bytes verbatim. This is the format the
//	            content_hash refers to; re-download is byte-stable.
//	spdx      → re-rendered from the canonical bytes by the Enterprise
//	            ArtifactFormatter. The hash on the row continues to refer to
//	            the cyclonedx canonical form.
//	pdf       → same projection, same renderer.
//
// Edition: cyclonedx is Core — it is the CBOM standard and every build must
// serve it. spdx and pdf require the Enterprise renderer; a Core build answers
// 402 Payment Required for them (see the gate below).
func (h *Handler) download(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	artifactID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid artifact id"})
		return
	}
	format := DownloadFormat(c.DefaultQuery("format", string(FormatCycloneDX)))
	if !format.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "format must be one of: cyclonedx, spdx, pdf, ocsf"})
		return
	}

	// Edition gate. Checked before touching the database: there is nothing
	// this build can do with the row, so reading it would only burn a query.
	// 402 (not 400/404) because the request is well-formed and the artifact
	// question is irrelevant — the deployment simply doesn't include the
	// renderer.
	if !format.IsCore() && h.formatter == nil {
		c.JSON(http.StatusPaymentRequired, gin.H{
			"error": fmt.Sprintf(
				"%s export requires an Enterprise license; this deployment serves the canonical cyclonedx format",
				format),
		})
		return
	}
	if !format.IsCore() {
		cbomSigningEntitled, ok := h.cbomSigningEntitled(c, tenantID)
		if !ok {
			return
		}
		if !cbomSigningEntitled {
			h.respondCBOMSigningRequired(c)
			return
		}
	}

	a, err := h.repo.Get(c.Request.Context(), tenantID, artifactID)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "artifact not found"})
		return
	}
	if err != nil {
		log.Printf("get artifact: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Kind compatibility, checked AFTER the edition gate so the two answers
	// stay distinguishable: 402 is "your deployment/subscription cannot render
	// this format at all", 400 is "this format is not defined for this kind of
	// artifact". A Core install asking for SPDX gets the first whatever the
	// kind is, which is what it got before kinds existed.
	if msg, ok := formatKindMismatch(format, a.ArtifactKind); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	// OCSF is Core but it is a PROJECTION, not the stored bytes — so it falls
	// through to the byte-loading path below rather than the verbatim/redirect
	// one. Handled here as its own case because the renderer is Core-wired and
	// its absence is a 501, not the 402 the Enterprise formats answer with.
	if format == FormatOCSF && h.ocsf == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "this deployment cannot render the OCSF event stream"})
		return
	}

	// CycloneDX serves verbatim. Inline returns bytes directly; storage
	// returns a presigned redirect (URL strategy is configured server-side).
	if format.ServesCanonicalBytes() {
		if a.HasInlineContent {
			bytes, err := h.repo.GetInlineContent(c.Request.Context(), tenantID, artifactID)
			if err != nil {
				log.Printf("read inline content: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
				return
			}
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="cbom-%s.%s"`, a.ID.String(), format.FilenameSuffix()))
			c.Data(http.StatusOK, "application/vnd.cyclonedx+json", bytes)
			return
		}
		if h.storage == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "storage not configured but artifact has storage_key"})
			return
		}
		tenant := tenantID
		url, urlErr := h.storage.GetURL(c.Request.Context(), sharedstorage.ArtifactTypeCBOM, a.StorageKey, &tenant)
		if urlErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "presign url: " + urlErr.Error()})
			return
		}
		c.Redirect(http.StatusFound, url)
		return
	}

	// SPDX, PDF and OCSF need the bytes server-side to re-render. Read them
	// from inline content or, for object-stored artifacts, by streaming from
	// storage.
	var bytes []byte
	if a.HasInlineContent {
		bytes, err = h.repo.GetInlineContent(c.Request.Context(), tenantID, artifactID)
		if err != nil {
			log.Printf("read inline content: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	} else {
		if h.storage == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "storage not configured but artifact has storage_key"})
			return
		}
		tenant := tenantID
		bytes, err = ReadStoredBytes(c.Request.Context(), h.storage, a.StorageKey, &tenant)
		if err != nil {
			log.Printf("read stored content: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	}
	var (
		body        []byte
		contentType string
	)
	if format == FormatOCSF {
		body, contentType, err = h.ocsf(bytes)
	} else {
		// The renderer owns unmarshalling the canonical document as well as the
		// projection, so Core carries no knowledge of the alternate formats'
		// shapes — only their names.
		body, contentType, err = h.formatter.Render(bytes, string(format))
	}
	if err != nil {
		log.Printf("%s render: %v", format, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="cbom-%s.%s"`, a.ID.String(), format.FilenameSuffix()))
	c.Data(http.StatusOK, contentType, body)
}

// verify — POST /cbom/artifacts/:id/verify. Recomputes the SHA-256 over the
// stored bytes and compares it to the row's content_hash; recomputes the
// HMAC if the artifact was signed and a signer is wired. Returns a
// VerifyResponse the UI can render as "Hash OK, signature OK" etc.
//
// Bytes come from inline content or, for object-stored artifacts, by streaming
// from storage. If they cannot be obtained, the hash/signature fields
// stay unset and the UI greys the result.
//
// Three outcomes, not two, and the difference matters to whoever is holding the
// evidence: hash_valid=true is "verified"; hash_valid=false WITH a non-empty
// hash_recomputed is a genuine mismatch (the bytes changed); hash_valid=false
// with hash_recomputed ABSENT means the bytes could not be read and nothing was
// compared. Telling an operator with an untampered artifact that its integrity
// check failed is the failure mode this shape exists to avoid, so do not
// collapse the third case into the second.
func (h *Handler) verify(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	artifactID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid artifact id"})
		return
	}
	a, err := h.repo.Get(c.Request.Context(), tenantID, artifactID)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "artifact not found"})
		return
	}
	if err != nil {
		log.Printf("get artifact: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	resp := VerifyResponse{
		ArtifactID:   a.ID,
		HashStored:   a.ContentHash,
		SignatureKID: a.SignatureKID,
	}

	// Hash check requires the bytes — from inline content or, for object-stored
	// artifacts, by streaming from storage.
	//
	// A read failure here is "not checked", not "failed": the artifact may be
	// perfectly intact and merely unreachable (credentials rotated, object
	// expired, storage unwired). The response says so by leaving HashRecomputed
	// empty, and the operator is told so by the drawer. But an unreachable
	// artifact is an operational fault someone has to fix, and swallowing the
	// error silently left no trace of it anywhere — so it is logged.
	var bytes []byte
	if a.HasInlineContent {
		if b, berr := h.repo.GetInlineContent(c.Request.Context(), tenantID, artifactID); berr == nil {
			bytes = b
		} else {
			log.Printf("verify %s: inline content unreadable, hash not checked: %v", artifactID, berr)
		}
	} else if h.storage != nil && a.StorageKey != "" {
		tenant := tenantID
		if b, berr := ReadStoredBytes(c.Request.Context(), h.storage, a.StorageKey, &tenant); berr == nil {
			bytes = b
		} else {
			log.Printf("verify %s: stored bytes unreadable (key %s), hash not checked: %v", artifactID, a.StorageKey, berr)
		}
	} else {
		log.Printf("verify %s: no inline content and no storage wired, hash not checked", artifactID)
	}

	if len(bytes) > 0 {
		sum := sha256Hex(bytes)
		resp.HashRecomputed = sum
		resp.HashValid = sum == a.ContentHash

		// Signature check — only if signed AND signer wired AND hash OK
		// (otherwise reporting "signature valid" against a recomputed
		// hash that differs from the stored one would be misleading).
		if a.SignatureHMAC != "" && h.signer != nil && resp.HashValid {
			ok, verr := h.signer.Verify(a.ContentHash, a.SignatureHMAC, a.SignatureKID)
			if verr == nil {
				resp.SignatureChecked = true
				resp.SignatureValid = ok
			}
		}
	}
	c.JSON(http.StatusOK, resp)
}

// softDelete — DELETE /cbom/artifacts/:id. Soft-delete only.
func (h *Handler) softDelete(c *gin.Context) {
	tenantID, ok := middleware.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id missing"})
		return
	}
	artifactID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid artifact id"})
		return
	}
	err = h.repo.SoftDelete(c.Request.Context(), tenantID, artifactID)
	if errors.Is(err, ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "artifact not found"})
		return
	}
	if err != nil {
		log.Printf("delete artifact: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// extractAuthToken pulls the JWT from Authorization Bearer first, then the
// access_token cookie — same strategy enhanced_reports uses. Required so
// the builder can authenticate against inventory-service.
func extractAuthToken(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
	if len(authHeader) >= 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:]
	}
	if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
		return cookie
	}
	return ""
}

func (h *Handler) cbomSigningEntitled(c *gin.Context, tenantID uuid.UUID) (bool, bool) {
	if h.featureChecker == nil {
		return false, true
	}
	allowed, err := h.featureChecker.CheckFeatureAccess(tenantID, FeatureCBOMSigning)
	if err != nil {
		log.Printf("check %s entitlement for tenant %s: %v", FeatureCBOMSigning, tenantID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify CBOM signing entitlement"})
		return false, false
	}
	return allowed, true
}

func (h *Handler) respondCBOMSigningRequired(c *gin.Context) {
	c.JSON(http.StatusPaymentRequired, gin.H{
		"error": "CBOM signing, compliance attestation, comparison, and alternate evidence formats require an Enterprise subscription",
	})
}

func boolPtrTrue(v *bool) bool {
	return v != nil && *v
}

// kindVocabulary renders the closed kind set for an error message. Generated
// from AllArtifactKinds rather than typed out, so a kind added to the constant
// list cannot be missing from the message that tells a caller what is allowed.
func kindVocabulary() string {
	names := make([]string, 0, len(AllArtifactKinds))
	for _, k := range AllArtifactKinds {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

// formatKindMismatch reports whether a download format is defined for an
// artifact kind, and if not, why.
//
// Two rules, in both directions:
//
//   - OCSF is defined ONLY for `inventory`. It is a device-and-vulnerability
//     event stream, and a CBOM, an SBOM and an HBOM have no devices to project.
//     Serving an empty stream instead would tell a SIEM the tenant has no
//     assets, which is a far worse answer than a refusal.
//   - SPDX and PDF are defined ONLY for `cbom`. Both renderers project the
//     crypto component model — the PDF's sections are certificates, algorithms,
//     protocols and keys — so pointing them at an inventory snapshot produces a
//     document that is empty where it matters and says so nowhere.
//
// Returning a message rather than an error type: the caller's only job is to
// put it in a 400 body, and the reason has to reach the person who asked.
func formatKindMismatch(format DownloadFormat, kind ArtifactKind) (string, bool) {
	// A row written before the column existed reads back as 'cbom' via the
	// COALESCE in the repository, so an empty kind here means a caller built an
	// Artifact by hand. Treat it as cbom rather than refusing every format.
	if kind == "" {
		kind = KindCBOM
	}
	switch format {
	case FormatOCSF:
		if kind != KindInventory {
			return fmt.Sprintf(
				"the OCSF event stream is defined for inventory artifacts; this artifact is a %s", kind), false
		}
	case FormatSPDX, FormatPDF:
		if kind != KindCBOM {
			return fmt.Sprintf(
				"%s export is defined for cbom artifacts; this artifact is a %s", format, kind), false
		}
	}
	return "", true
}
