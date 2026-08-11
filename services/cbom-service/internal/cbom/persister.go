package cbom

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

// Persister writes a freshly-built CBOM to storage (S3 if enabled, inline
// JSONB if not), optionally attaches a compliance-attestation layer, optionally
// signs the artifact, and inserts the cbom_artifacts row.
//
// The dual-path (S3 vs inline) makes the feature work both in production
// (where storage is configured per-artifact-type by an admin) and in dev /
// brand-new installs (where storage is disabled by default). The DB CHECK
// constraint `cbom_artifacts_storage_or_inline` enforces exactly-one-of.
type Persister struct {
	repo               *Repository
	storage            sharedstorage.ArtifactStorageService // nil-tolerant: falls back to inline
	signer             Signer                               // optional Phase 4 signer (Enterprise; nil in Core)
	attestationBuilder AttestationBuilder                   // optional Phase 4 attestation (Enterprise; nil in Core)
}

// NewPersister constructs a Persister with only the storage layer. Use
// NewPersisterWithSigning when Phase 4 signing+attestation are wired.
func NewPersister(repo *Repository, storage sharedstorage.ArtifactStorageService) *Persister {
	return &Persister{repo: repo, storage: storage}
}

// NewPersisterWithSigning wires the Phase 4 signer + attestation builder
// alongside the storage layer. Both nil-tolerant: pass nil to skip that
// feature (e.g. operator hasn't set INTERNAL_AUTH_SECRET, or doesn't want
// attestations).
func NewPersisterWithSigning(repo *Repository, storage sharedstorage.ArtifactStorageService, signer Signer, attestation AttestationBuilder) *Persister {
	return &Persister{
		repo:               repo,
		storage:            storage,
		signer:             signer,
		attestationBuilder: attestation,
	}
}

// PersistInput bundles everything Persist needs to create one artifact.
type PersistInput struct {
	Scope                *scopes.Scope
	Build                *BuildOutput
	Name                 string
	GeneratedBy          uuid.UUID
	InputDataFreshnessAt time.Time
	Provenance           Provenance

	// Phase 4 toggles. Default false → no layer/signature, matching pre-Phase-4
	// behavior. The handler sets these from the GenerateRequest.
	IncludeAttestation bool
	Sign               bool
}

// Persist writes the artifact bytes to storage (or inline) and creates the
// cbom_artifacts row. Returns the created Artifact with id/timestamps populated.
func (p *Persister) Persist(ctx context.Context, in PersistInput) (*Artifact, error) {
	if in.Scope == nil {
		return nil, fmt.Errorf("cbom persister: scope cannot be nil")
	}
	if in.Build == nil || len(in.Build.CanonicalBytes) == 0 {
		return nil, fmt.Errorf("cbom persister: empty build output")
	}

	params := insertParams{
		TenantID:             in.Scope.TenantID,
		ScopeID:              in.Scope.ID,
		ScopeVersion:         in.Scope.Version,
		ScopeNameSnapshot:    in.Scope.Name,
		Name:                 in.Name,
		ContentHash:          in.Build.ContentHash,
		SizeBytes:            int64(len(in.Build.CanonicalBytes)),
		ComponentCount:       in.Build.ComponentCount,
		CycloneDXSpecVersion: in.Build.CycloneDXSpecVersion,
		InputDataFreshnessAt: in.InputDataFreshnessAt,
		GeneratedBy:          in.GeneratedBy,
		Provenance:           in.Provenance,
	}

	// Phase 4: attach compliance attestation if requested and the builder
	// is wired. Best-effort — a failure to query findings shouldn't tank
	// CBOM generation, so we log and continue without the layer.
	var attestationError string
	if in.IncludeAttestation && p.attestationBuilder != nil {
		layer, err := p.attestationBuilder.Build(ctx, in.Scope.TenantID, in.Build.AssetIDs)
		switch {
		case err != nil:
			// Absent-because-it-failed and absent-because-clean look identical
			// on the artifact, so say which one happened — in the log AND back
			// to the caller, who is the one holding the evidence.
			log.Printf("[cbom-attest] tenant=%s scope=%s: attestation skipped: %v",
				in.Scope.TenantID, in.Scope.ID, err)
			attestationError = err.Error()
		case layer != nil:
			params.Layers = []Layer{*layer}
		}
		// A nil layer with no error means the scope matched no assets — nothing
		// to attest, which is a legitimate outcome and not worth a log line.
	}

	// Phase 4: sign the canonical bytes if requested and signer is wired.
	// HMAC over the SHA-256 content hash — equivalent to HMAC over the
	// bytes by HMAC's length-extension resistance, but constant-cost.
	if in.Sign && p.signer != nil {
		params.SignatureHMAC = p.signer.Sign(in.Build.CanonicalBytes)
		params.SignatureKID = p.signer.KID()
	}

	// The private diff view rides along regardless of where the canonical bytes
	// end up. See BuildOutput.InternalBytes for why both shapes are kept.
	params.InternalContent = in.Build.InternalBytes

	var storageDegraded string

	// Choose storage path. If shared/storage is enabled for ArtifactTypeCBOM,
	// upload and record the storage_key. Otherwise stash inline. We never
	// store both — the DB CHECK constraint would reject it.
	if p.storage != nil && p.storage.IsEnabled(sharedstorage.ArtifactTypeCBOM) {
		// Filename includes content hash so re-uploads of identical content
		// are idempotent at the object-store layer (S3 dedup on key collision).
		// The artifact_id is the unique handle, but the storage key is
		// content-addressed for free dedup.
		filename := fmt.Sprintf("%s.cdx.json", in.Build.ContentHash[:16])
		tenant := in.Scope.TenantID
		uploadRes, err := p.storage.Upload(
			ctx,
			sharedstorage.ArtifactTypeCBOM,
			&tenant,
			filename,
			bytes.NewReader(in.Build.CanonicalBytes),
			"application/vnd.cyclonedx+json",
			int64(len(in.Build.CanonicalBytes)),
		)
		if err != nil {
			// S3 is configured and enabled but the upload failed — a transient
			// object-store, network, or credential problem. A CBOM artifact is
			// audit-grade evidence the customer is generating on demand; we must
			// not fail the whole generation because the bucket hiccuped. Fall
			// back to inline storage so the artifact is still produced and
			// content-addressable. The artifact is immutable and re-generable, so
			// an operator can regenerate to S3 once it's healthy if they need the
			// object in the bucket.
			log.Printf("[cbom-persister] S3 upload failed for tenant %s, falling back to inline storage: %v", tenant, err)
			params.InlineContent = in.Build.CanonicalBytes
			storageDegraded = fmt.Sprintf("object-store upload failed, artifact stored inline: %v", err)
		} else {
			params.StorageKey = uploadRes.Key
		}
	} else {
		params.InlineContent = in.Build.CanonicalBytes
	}

	artifact, err := p.repo.Create(ctx, params)
	if err != nil {
		return nil, err
	}
	// Transient, generation-time only — see Artifact.StorageDegraded.
	artifact.StorageDegraded = storageDegraded
	artifact.AttestationError = attestationError
	return artifact, nil
}
