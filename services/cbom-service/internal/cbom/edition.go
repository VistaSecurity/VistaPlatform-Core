package cbom

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// This file is the Core/Enterprise seam for CBOM evidence.
//
// The open-core split for CBOM is *generation vs evidence and reporting*:
//
//	Core       — scopes, artifact generation, content hashing, CycloneDX
//	             export. Everything needed to produce and read a CBOM.
//	             Artifacts are unsigned.
//	Enterprise — the audit-grade layer on top: Ed25519 signing, compliance
//	             attestation, artifact comparison/drift, and the alternate
//	             export formats (SPDX, PDF).
//
// CycloneDX stays in Core on purpose: it *is* the CBOM standard, so an
// open-source install that couldn't emit it would forfeit the category claim.
// SPDX is an interop convenience and the PDF is the auditor deliverable — those
// are reporting, which is what we monetize.
//
// Core declares the interfaces; the implementations live under
// services/cbom-service/ee/ and are absent from the open-source tree. A Core
// build leaves these nil, and every call site is nil-tolerant, so an
// unsigned/unattested artifact is a normal Core outcome rather than an error
// path. See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5 for
// the repo-wide pattern.
//
// Keep these interfaces minimal: they are the contract the Enterprise build
// must satisfy, and every method added here is a method the open tree can
// see. Types the *database* round-trips (Layer, the signature columns on
// model.go) deliberately stay in Core — a Core install must still be able to
// read, store, and serve an artifact that an Enterprise install signed.

// Signer produces and verifies the detached signature stamped on a CBOM
// artifact. Implemented by the Enterprise build; nil in Core.
//
// The signature is Ed25519 over a canonical Envelope (envelope.go), not over
// the content bytes alone. Core keeps the signature columns and will happily
// serve artifacts carrying them — it simply cannot mint or check one.
type Signer interface {
	// KID returns the id of the key that signs new artifacts. It is stored
	// beside every signature so verification can pick the right key after a
	// rotation.
	KID() string

	// Algorithm names the signature scheme ("ed25519").
	Algorithm() string

	// Sign signs the canonical envelope bytes and returns the hex signature.
	Sign(envelope []byte) (string, error)

	// Verify checks a hex signature over the envelope bytes under the key
	// named by kid — the current key or a retired one from the key history.
	// A kid with no known key returns an error wrapping ErrUnknownKey.
	Verify(ctx context.Context, kid string, envelope []byte, signatureHex string) (bool, error)

	// PublicKeys lists every verification key, current and retired, so a third
	// party can verify an artifact offline.
	PublicKeys(ctx context.Context) ([]SigningKey, error)
}

// ErrUnknownKey means no verification key is recorded for a key id.
var ErrUnknownKey = errors.New("cbom: unknown signing key id")

// SigningKey is the public half of an artifact signing key.
type SigningKey struct {
	KID       string `json:"kid"`
	Algorithm string `json:"algorithm"`
	// PublicKeyPEM is the SubjectPublicKeyInfo ("PUBLIC KEY") PEM.
	PublicKeyPEM string `json:"public_key_pem"`
	// Active marks the key that signs new artifacts.
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// AttestationBuilder assembles the compliance-attestation Layer recorded on
// an artifact. Implemented by the Enterprise build; nil in Core.
type AttestationBuilder interface {
	// Build gathers the compliance state for the given assets into a Layer.
	//
	// tenantID is part of the contract rather than an ambient property of the
	// connection: `findings` is RLS-policied, so an implementation
	// reading it from an unscoped pooled connection sees zero rows and would
	// mint an attestation asserting "no findings" for a tenant that has them.
	// Passing the tenant explicitly makes that impossible to forget.
	Build(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID) (*Layer, error)
}

// ArtifactFormatter re-renders an artifact into an alternate download format,
// from its INTERNAL view (the models.CBOMData document stored beside the
// canonical bytes), never from the canonical CycloneDX bytes themselves. Implemented by the Enterprise build; nil in Core.
//
// Unlike Signer/AttestationBuilder, a nil ArtifactFormatter is *not* silently
// tolerated: the download handler answers 402 Payment Required for the formats
// it can't render. Signing absence is a property of the artifact ("unsigned" is
// a valid CBOM); a missing renderer is a request the edition cannot satisfy, and
// saying so beats emitting a downgraded file.
//
// Note what deliberately stays in Core: the DownloadFormat enum and its
// validation. `?format=spdx` is a *valid* request everywhere — the edition
// decides whether it can be served, so Core must still recognise the name to
// distinguish 402 (valid format, wrong edition) from 400 (nonsense format).
type ArtifactFormatter interface {
	// Render returns the rendered body and the MIME type to serve it as.
	// internalBytes is the artifact's internal view; an implementation handed
	// canonical CycloneDX returns an error wrapping ErrNoInternalView.
	// format is a DownloadFormat value other than cyclonedx (Core serves the
	// canonical bytes verbatim and never calls this for them).
	Render(internalBytes []byte, format string) (body []byte, contentType string, err error)
}

// RegisterUnavailableComparisonRoutes mounts the Core-side 402 for artifact
// comparison. Call it ONLY when the Enterprise comparison hook is nil.
//
// Comparison is Enterprise, and the Enterprise build mounts the real routes
// behind RequireFeature(cbom_signing). A Core build used to mount nothing, so
// `POST /cbom/compare` and `GET /cbom/compare/:base/:head` answered a bare 404
// — indistinguishable from a typo'd URL and, worse, from "those artifacts do
// not exist", which is what an MCP agent calling the compare tool concluded.
// The documented answer (CLAUDE.md, the OpenAPI spec, the downloader's own
// spdx/pdf refusal) is 402 Payment Required, with the same body shape
// RequireFeature writes so a client handles "Core build" and "Core-tier tenant
// on an Enterprise build" in one branch.
//
// Exactly one of this and the Enterprise routes is ever registered, so there is
// no route conflict. Nothing about the comparison implementation leaks into
// Core: what is mounted is two paths and a refusal.
func RegisterUnavailableComparisonRoutes(rg *gin.RouterGroup) {
	refuse := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{
			"error":   "This capability is not included in your subscription",
			"feature": FeatureCBOMSigning,
			"detail":  "CBOM artifact comparison is an Enterprise capability and is not part of this build.",
		})
	}
	rg.POST("/cbom/compare", refuse)
	rg.GET("/cbom/compare/:base/:head", refuse)
}
