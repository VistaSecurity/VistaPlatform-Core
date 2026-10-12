package cbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

// ErrSignerUnavailable is returned by Persist when signing was requested and
// no signer is wired. It is checked before anything is written, so a refusal
// leaves no orphan object or row behind.
var ErrSignerUnavailable = errors.New("cbom persister: signing requested but no signer is configured")

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

	if in.Sign && p.signer == nil {
		return nil, ErrSignerUnavailable
	}

	// The kind rides on the build, not on PersistInput: it is a property of the
	// bytes that were assembled, and taking it from a separate field would let
	// a row claim to be a kind its content is not.
	params := insertParams{
		TenantID:             in.Scope.TenantID,
		ScopeID:              in.Scope.ID,
		ScopeVersion:         in.Scope.Version,
		ScopeNameSnapshot:    in.Scope.Name,
		Name:                 in.Name,
		ArtifactKind:         in.Build.Kind,
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

	// Sign a canonical envelope that binds the content hash to the scope
	// claim, the attestation layers, the kind and the author (envelope.go) —
	// not the bytes alone, which would leave all of those editable behind a
	// still-valid signature. The envelope is stored verbatim so /verify checks
	// the signature over the exact bytes signed.
	if in.Sign {
		env, err := NewEnvelope(in.Build.ContentHash, in.Scope.ID, in.Scope.Version, params.Layers, in.Build.Kind, in.GeneratedBy)
		if err != nil {
			return nil, err
		}
		envBytes, err := env.Bytes()
		if err != nil {
			return nil, err
		}
		sig, err := p.signer.Sign(envBytes)
		if err != nil {
			return nil, fmt.Errorf("cbom persister: sign envelope: %w", err)
		}
		params.Signature = sig
		params.SignatureAlgorithm = p.signer.Algorithm()
		params.SignatureKID = p.signer.KID()
		params.SignedEnvelope = string(envBytes)
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
		//
		// The kind is in the filename because two kinds of the same scope are
		// two different documents and an operator browsing the bucket has
		// nothing else to tell them apart. It cannot break dedup: the hash is
		// over content that differs by kind anyway.
		filename := fmt.Sprintf("%s-%s.cdx.json", in.Build.Kind, in.Build.ContentHash[:16])
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
		// The object was uploaded but no row will ever point at it. Remove it so
		// failed creates do not accumulate orphans in the bucket. Best-effort:
		// the create error is what the caller needs, and a failed delete is
		// logged with the key so an operator can sweep it.
		if params.StorageKey != "" {
			p.removeOrphan(ctx, in.Scope.TenantID, params.StorageKey)
		}
		return nil, err
	}
	// Transient, generation-time only — see Artifact.StorageDegraded.
	artifact.StorageDegraded = storageDegraded
	artifact.AttestationError = attestationError
	return artifact, nil
}

// removeOrphan deletes an object uploaded for an artifact whose row insert
// failed. Keys are content-addressed, so the object is left alone if any row
// (even a soft-deleted one) references it; if that cannot be determined it is
// also left alone, since a stray object is recoverable and a deleted live one
// is not. Best-effort and logged: it never changes the caller's error.
func (p *Persister) removeOrphan(ctx context.Context, tenant uuid.UUID, key string) {
	ctx = context.WithoutCancel(ctx)
	referenced, err := p.repo.StorageKeyReferenced(ctx, tenant, key)
	if err != nil {
		log.Printf("[cbom-persister] orphaned object %q after failed artifact insert (tenant %s): cannot tell whether it is referenced, leaving it: %v", key, tenant, err)
		return
	}
	if referenced {
		return
	}
	if delErr := p.storage.Delete(ctx, sharedstorage.ArtifactTypeCBOM, key, &tenant); delErr != nil {
		log.Printf("[cbom-persister] orphaned object %q after failed artifact insert (tenant %s): delete failed: %v", key, tenant, delErr)
	}
}
