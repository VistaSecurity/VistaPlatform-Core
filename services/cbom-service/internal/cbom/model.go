// Package cbom implements CBOM Artifact persistence — the Phase 2 capability
// that turns a Scope + a moment in time into a frozen, hashed, optionally-signed
// Cryptographic Bill of Materials retained for evidence purposes.
//
// See docsv4/internal/developer/architecture/cbom/cbom-artifact-shape.md
// for design notes.
package cbom

import (
	"time"

	"github.com/google/uuid"
)

// ArtifactKind names which bill of materials an artifact is (ADR-0005 D6).
//
// One pipeline, four products. A CBOM is the CRYPTO subset of a general
// inventory snapshot, and CycloneDX 1.7 already models the rest — `device`,
// `operating-system`, `platform`, `application`, `library`, `data` component
// types plus `dependencies` for edges — so the kinds share a format, a content
// hash, a signature and a comparison rather than each inventing its own.
//
// The vocabulary is closed and mirrored by the `cbom_artifacts_artifact_kind_check`
// CHECK. Adding a kind is two edits: here and the CHECK.
type ArtifactKind string

const (
	// KindCBOM is the cryptographic bill of materials: certificates,
	// algorithms, protocols, keys and crypto libraries. The original and the
	// default — an omitted `kind` means this, so every pre-existing client
	// keeps the behaviour it had.
	KindCBOM ArtifactKind = "cbom"
	// KindSBOM is the software bill of materials: one component per distinct
	// software product installed on the scope's assets.
	KindSBOM ArtifactKind = "sbom"
	// KindHBOM is the hardware bill of materials: one `device` component per
	// hardware-class asset in scope, carrying its hardware facts.
	KindHBOM ArtifactKind = "hbom"
	// KindInventory is the whole-inventory snapshot: every asset in scope as a
	// component typed by its class, its endpoints as services, its
	// relationships as the dependency graph, and its open vulnerability
	// findings as CycloneDX vulnerabilities.
	KindInventory ArtifactKind = "inventory"
)

// AllArtifactKinds is the closed vocabulary, in the order the UI lists it.
var AllArtifactKinds = []ArtifactKind{KindCBOM, KindSBOM, KindHBOM, KindInventory}

// IsValid reports whether the kind is one this build recognises.
func (k ArtifactKind) IsValid() bool {
	for _, known := range AllArtifactKinds {
		if k == known {
			return true
		}
	}
	return false
}

// String makes ArtifactKind printable without a conversion at every call site.
func (k ArtifactKind) String() string { return string(k) }

// Artifact is the persisted row in `cbom_artifacts`. It captures enough
// provenance to reproduce the snapshot against the inventory state at the
// moment of generation, and to detect tamper (via content_hash, with Phase 4
// signing adding non-repudiation).
type Artifact struct {
	ID                uuid.UUID `json:"id" db:"id"`
	TenantID          uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ScopeID           uuid.UUID `json:"scope_id" db:"scope_id"`
	ScopeVersion      int       `json:"scope_version" db:"scope_version"`
	ScopeNameSnapshot string    `json:"scope_name_snapshot" db:"scope_name_snapshot"`
	Name              string    `json:"name,omitempty" db:"name"`
	// ArtifactKind is which bill of materials this row is. Never empty on a
	// row read back from the database — the column is NOT NULL DEFAULT 'cbom'.
	ArtifactKind ArtifactKind `json:"artifact_kind" db:"artifact_kind"`
	StorageKey   string       `json:"storage_key,omitempty" db:"storage_key"`
	// InlineContent is only populated when shared/storage is not configured
	// (typical dev). Production / customer installs use storage_key.
	HasInlineContent     bool       `json:"has_inline_content" db:"-"`
	ContentHash          string     `json:"content_hash" db:"content_hash"`
	SizeBytes            int64      `json:"size_bytes" db:"size_bytes"`
	ComponentCount       int        `json:"component_count" db:"component_count"`
	CycloneDXSpecVersion string     `json:"cyclonedx_spec_version" db:"cyclonedx_spec_version"`
	InputDataFreshnessAt time.Time  `json:"input_data_freshness_at" db:"input_data_freshness_at"`
	GeneratedAt          time.Time  `json:"generated_at" db:"generated_at"`
	GeneratedBy          uuid.UUID  `json:"generated_by" db:"generated_by"`
	SignatureHMAC        string     `json:"signature_hmac,omitempty" db:"signature_hmac"`
	SignatureKID         string     `json:"signature_kid,omitempty" db:"signature_kid"`
	Provenance           Provenance `json:"provenance" db:"provenance"`
	Layers               []Layer    `json:"layers" db:"layers"`
	DeletedAt            *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`

	// StorageDegraded and AttestationError describe what went wrong while this
	// artifact was being written, for the caller that asked for it. Both are
	// generation-time only — they are not columns, so a later GET does not
	// replay them.
	//
	// They exist because both conditions were previously log-only. An operator
	// reading the API could not distinguish an artifact in the object store from
	// one that fell back to inline storage after an upload failure, nor an
	// artifact with no findings to attest from one whose attestation query
	// errored. Silence read as success in both cases.
	StorageDegraded  string `json:"storage_degraded,omitempty" db:"-"`
	AttestationError string `json:"attestation_error,omitempty" db:"-"`
}

// Provenance carries non-canonical context about how the artifact was
// generated. Stored as JSONB; opaque to most consumers. Phase 4 verify
// recomputes the signature without reading these fields.
type Provenance struct {
	GeneratorService string `json:"generator_service,omitempty"`
	GeneratorVersion string `json:"generator_version,omitempty"`
	RequestID        string `json:"request_id,omitempty"`
}

// Layer is an optional annotation attached to an artifact. Phase 4 introduces
// `compliance_attestation` (framework evaluation snapshot); Phase 5 may add
// `risk_summary`. Each layer carries its own type+version so the schema can
// evolve without breaking older artifacts.
type Layer struct {
	Type    string                 `json:"type"`
	Version string                 `json:"version,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// GenerateRequest is the JSON body for POST /cbom/generate.
type GenerateRequest struct {
	ScopeID uuid.UUID `json:"scope_id" binding:"required"`
	// Kind selects which bill of materials to assemble. Empty means "cbom",
	// which is exactly what this endpoint produced before kinds existed, so an
	// older client's request is unchanged in meaning as well as in shape.
	Kind ArtifactKind `json:"kind,omitempty"`
	// Optional human-meaningful name. Falls back to "<scope> — <date>" when
	// not provided.
	Name string `json:"name,omitempty"`
	// IncludeAttestation attaches a compliance_attestation layer summarizing
	// open findings for the scope's asset set. Default is entitlement-aware:
	// true for cbom_signing tenants, false for Core/unentitled tenants.
	IncludeAttestation *bool `json:"include_attestation,omitempty"`
	// Sign HMAC-signs the artifact. Default is entitlement-aware: true for
	// cbom_signing tenants, false for Core/unentitled tenants.
	Sign *bool `json:"sign,omitempty"`
}

// BoolDefault returns *b if non-nil, else the default. Used to apply
// "default true" semantics to optional bool fields on GenerateRequest.
func BoolDefault(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

// VerifyResponse is the JSON body returned from POST /cbom/artifacts/:id/verify.
type VerifyResponse struct {
	ArtifactID uuid.UUID `json:"artifact_id"`
	// HashValid is true when the stored content_hash matches a re-hash of
	// the canonical bytes loaded from inline_content / storage_key.
	HashValid bool `json:"hash_valid"`
	// HashRecomputed is the SHA-256 we just computed, so the UI can show
	// "expected X, got Y" if it doesn't match.
	HashRecomputed string `json:"hash_recomputed,omitempty"`
	// HashStored is what cbom_artifacts.content_hash records.
	HashStored string `json:"hash_stored"`
	// SignatureValid is true when the stored HMAC matches one we recompute
	// against the platform's current signing key. False+SignatureChecked=true
	// means tamper. SignatureChecked=false means the artifact was unsigned
	// (signature_hmac empty) or the verifier wasn't configured.
	SignatureValid   bool `json:"signature_valid"`
	SignatureChecked bool `json:"signature_checked"`
	// SignatureKID is the kid stored on the artifact (empty for unsigned).
	SignatureKID string `json:"signature_kid,omitempty"`
}

// GenerateResponse is the JSON body returned from POST /cbom/generate.
// 202 Accepted with the artifact_id; consumers poll GET /cbom/artifacts/:id
// (Phase 2 generation is synchronous-but-quick; future could move to async).
type GenerateResponse struct {
	ArtifactID uuid.UUID `json:"artifact_id"`
	Status     string    `json:"status"`
	// StorageDegraded is set when the artifact was produced but not stored the
	// way this deployment is configured to store it (object-store upload failed
	// and the bytes went inline instead). The artifact is complete and valid;
	// the caller may want to regenerate once storage is healthy.
	StorageDegraded string `json:"storage_degraded,omitempty"`
	// AttestationError is set when a compliance-attestation layer was requested
	// and could not be built. Empty means either "not requested" or "built" —
	// the artifact's `layers` says which.
	AttestationError string `json:"attestation_error,omitempty"`
}

// DownloadFormat is the wire format requested via ?format= on download.
type DownloadFormat string

const (
	// FormatCycloneDX is the canonical CycloneDX JSON (see
	// formatters.SpecVersion). This is the same
	// bytes used to compute content_hash, so re-downloads always verify.
	FormatCycloneDX DownloadFormat = "cyclonedx"
	// FormatSPDX is the SPDX 2.3 JSON projection. Enterprise-only — the
	// renderer lives in ee/cbomformats.
	FormatSPDX DownloadFormat = "spdx"
	// FormatPDF is the human-readable PDF rendering. Generated on demand
	// from the CycloneDX bytes; the hash on cbom_artifacts continues to
	// refer to the CycloneDX canonical form. Enterprise-only — the renderer
	// lives in ee/cbomformats.
	FormatPDF DownloadFormat = "pdf"
	// FormatOCSF is the OCSF 1.9.0 event stream (JSON Lines) projected from an
	// `inventory` artifact's canonical bytes: one Device Inventory Info (5001)
	// per asset, one Vulnerability Finding (2002) per vulnerability the
	// artifact records. Core — a SIEM is where an ops team already looks, and
	// gating the one export that reaches them would make the free edition
	// unusable in the place it has to work.
	//
	// Defined only for the `inventory` kind: it is a projection of assets, and
	// a CBOM has none to project. The download handler answers 400 for any
	// other kind rather than emitting an empty stream, because an empty stream
	// reads as "no assets" rather than "wrong artifact".
	FormatOCSF DownloadFormat = "ocsf"
)

// IsValid reports whether the requested format is a format the API recognises.
//
// Edition-independent by design: spdx/pdf are valid requests in every build,
// and it is the download handler's edition gate — not this check — that decides
// whether the running build can render them. Folding the edition in here would
// collapse "wrong edition" (402) into "unknown format" (400).
func (f DownloadFormat) IsValid() bool {
	switch f {
	case FormatCycloneDX, FormatSPDX, FormatPDF, FormatOCSF:
		return true
	}
	return false
}

// IsCore reports whether this build can serve the format without the Enterprise
// renderer: the canonical CycloneDX form and the OCSF event stream.
func (f DownloadFormat) IsCore() bool { return f == FormatCycloneDX || f == FormatOCSF }

// ServesCanonicalBytes reports whether the format IS the stored bytes, verbatim.
//
// Only CycloneDX is, and the distinction is not cosmetic: that path may answer
// with a presigned redirect and never touch the bytes, while every projection —
// OCSF included, Core though it is — has to load them server-side first.
func (f DownloadFormat) ServesCanonicalBytes() bool { return f == FormatCycloneDX }

// FilenameSuffix is the extension used in the download's Content-Disposition.
func (f DownloadFormat) FilenameSuffix() string {
	switch f {
	case FormatSPDX:
		return "spdx.json"
	case FormatPDF:
		return "pdf"
	case FormatOCSF:
		return "ocsf.ndjson"
	default:
		return "cdx.json"
	}
}
