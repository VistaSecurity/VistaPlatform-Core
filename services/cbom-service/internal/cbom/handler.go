package cbom

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
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
	List(ctx context.Context, tenantID uuid.UUID, scopeID *uuid.UUID, limit int) ([]Artifact, error)
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
	Build(ctx context.Context, scope *scopes.Scope, authToken string) (*BuildOutput, error)
}

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

	build, err := h.builder.Build(ctx, scope, authToken)
	var unsupported *UnsupportedPredicateError
	if errors.As(err, &unsupported) {
		// 422, not 500: the request and the scope are both well-formed, but the
		// artifact this deployment would produce is not the one the scope
		// describes. Producing a wider CBOM and saying nothing is the bug being
		// fixed, so refusing is the correct answer.
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":              unsupported.Error(),
			"unsupported_fields": unsupported.Fields,
		})
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

	artifacts, err := h.repo.List(c.Request.Context(), tenantID, scopeFilter, limit)
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "format must be one of: cyclonedx, spdx, pdf"})
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

	// CycloneDX serves verbatim. Inline returns bytes directly; storage
	// returns a presigned redirect (URL strategy is configured server-side).
	if format.IsCore() {
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

	// SPDX + PDF need the bytes server-side to re-render. Read them from inline
	// content or, for object-stored artifacts, by streaming from storage.
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
	// The renderer owns unmarshalling the canonical document as well as the
	// projection, so Core carries no knowledge of the alternate formats'
	// shapes — only their names.
	body, contentType, err := h.formatter.Render(bytes, string(format))
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
