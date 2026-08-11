package cbom

import (
	"context"

	"github.com/google/uuid"
)

// This file is the Core/Enterprise seam for CBOM evidence.
//
// The open-core split for CBOM is *generation vs evidence and reporting*:
//
//	Core       — scopes, artifact generation, content hashing, CycloneDX
//	             export. Everything needed to produce and read a CBOM.
//	             Artifacts are unsigned.
//	Enterprise — the audit-grade layer on top: HMAC signing, compliance
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
// Note that Core keeps the `signature_hmac`/`signature_kid` columns and will
// happily serve artifacts carrying them — it simply cannot mint or check one.
type Signer interface {
	// KID returns the key id to store alongside the signature so a future
	// key rotation can still verify old artifacts.
	KID() string

	// Sign computes the signature over the canonical CBOM bytes.
	Sign(canonicalBytes []byte) string

	// Verify constant-time compares a candidate signature for the given
	// content hash and key id. A mismatched kid must return false rather
	// than verifying against the current key.
	Verify(contentHashHex, candidateSignatureHex, kid string) (bool, error)
}

// AttestationBuilder assembles the compliance-attestation Layer recorded on
// an artifact. Implemented by the Enterprise build; nil in Core.
type AttestationBuilder interface {
	// Build gathers the compliance state for the given assets into a Layer.
	//
	// tenantID is part of the contract rather than an ambient property of the
	// connection: `compliance_findings` is RLS-policied, so an implementation
	// reading it from an unscoped pooled connection sees zero rows and would
	// mint an attestation asserting "no findings" for a tenant that has them.
	// Passing the tenant explicitly makes that impossible to forget.
	Build(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID) (*Layer, error)
}

// ArtifactFormatter re-renders an artifact's canonical CycloneDX bytes into an
// alternate download format. Implemented by the Enterprise build; nil in Core.
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
	// format is a DownloadFormat value other than cyclonedx (Core serves the
	// canonical bytes verbatim and never calls this for them).
	Render(canonicalBytes []byte, format string) (body []byte, contentType string, err error)
}
