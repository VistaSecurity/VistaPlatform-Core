package cbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/formatters"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
)

// Builder orchestrates one CBOM generation: scope → params → existing
// CBOM-generation pipeline → canonical CycloneDX bytes + SHA-256 hash.
//
// The heavy lifting (querying inventory, walking certificates, assembling
// crypto components) is reused from handlers.CBOMReportHandler — we keep
// that logic in place and add the artifact-shaped wrapper around it.
type Builder struct {
	cbomHandler *handlers.CBOMReportHandler
	xbom        KindAssembler
}

// KindAssembler builds the non-crypto bills of materials — sbom, hbom and
// inventory — from the scope's asset set. Implemented by internal/xbom.
//
// It is an interface, and Builder tolerates a nil one, for the same reason
// every other seam here does: the assembler needs a database handle that the
// contract test (which drives the real router with an in-memory store) has no
// reason to stand up. A nil assembler refuses the three kinds explicitly
// rather than producing an empty document for them.
type KindAssembler interface {
	Assemble(ctx context.Context, kind ArtifactKind, scope *scopes.Scope, assetIDs []uuid.UUID) (*BuildOutput, error)
}

// NewBuilder constructs a Builder that delegates inventory fetching and
// CBOM assembly to the existing CBOMReportHandler.
//
// The `cbom` kind is all this can build. Call SetKindAssembler to add the
// other three.
func NewBuilder(h *handlers.CBOMReportHandler) *Builder {
	return &Builder{cbomHandler: h}
}

// SetKindAssembler wires the asset-first assembler used by the sbom, hbom and
// inventory kinds. Leaving it unset keeps `cbom` working and makes the other
// three answer with a clear error rather than an empty bill of materials.
func (b *Builder) SetKindAssembler(a KindAssembler) { b.xbom = a }

// ErrKindUnavailable reports a kind this build cannot assemble because the
// asset-first assembler was never wired. The HTTP layer turns it into 501.
//
// It is NOT the same as an unknown kind (400): the name is one this build
// recognises, the deployment simply cannot serve it. Collapsing the two would
// tell an operator their request was malformed when it was their wiring that
// was incomplete.
var ErrKindUnavailable = errors.New("cbom builder: this deployment cannot assemble that artifact kind")

// BuildOutput is the result of a Build() call: the canonical bytes for
// hashing/storage, plus the structured metadata we record on the artifact row.
type BuildOutput struct {
	// CanonicalBytes is the JSON serialisation that everything else hashes,
	// signs, and stores. Always CycloneDX shape (formatters.SpecVersion) —
	// SPDX and PDF are projections rendered on download.
	CanonicalBytes []byte
	// InternalBytes is the same snapshot in our own CBOMData shape.
	//
	// It exists because CycloneDX is a publishing format, not a lossless
	// serialisation of our model: converting to it collapses our four component
	// types into "cryptographic-asset" and drops fields the Enterprise diff
	// categorises on (deprecation status, known-vulnerability count, PQC flag).
	// Rebuilding those from cryptoProperties would be guesswork, and guessing
	// wrong would silently mislabel a regression as neutral.
	//
	// So the artifact keeps both: CycloneDX is what we hash, sign and serve —
	// the thing a customer verifies — and this is the private view diff reads.
	// Never served, never hashed.
	InternalBytes []byte
	// ContentHash is hex(sha256(CanonicalBytes)).
	ContentHash string
	// ComponentCount is the number of components in the BOM.
	ComponentCount int
	// CycloneDXSpecVersion is the version we emitted (formatters.SpecVersion).
	CycloneDXSpecVersion string
	// AssetIDs is the deduplicated set of asset UUIDs referenced by
	// components in the BOM. Used by the Phase 4 compliance-attestation
	// layer to scope its findings query.
	AssetIDs []uuid.UUID
	// Kind is which bill of materials these bytes are. Set by Build, carried
	// to the row by Persist — see the note there on why it travels with the
	// bytes rather than alongside them.
	Kind ArtifactKind
}

// Build snapshots inventory matching the given Scope as of now and emits a
// canonical CycloneDX byte stream + content hash.
//
// `authToken` is the JWT to use for service-to-service calls to
// inventory-service. `tenantID` is duplicated on QueryParams.TenantID so the
// internal-call HMAC path can verify against inventory-service (Phase 0 fix).
// `kind` selects which bill of materials to assemble. `cbom` walks the crypto
// pipeline below; the other three go to the asset-first assembler, which starts
// from the SAME scope-resolved asset set so a CBOM and an inventory snapshot of
// one scope always describe the same boundary.
func (b *Builder) Build(ctx context.Context, kind ArtifactKind, scope *scopes.Scope, authToken string) (*BuildOutput, error) {
	if scope == nil {
		return nil, fmt.Errorf("cbom builder: scope cannot be nil")
	}
	if !kind.IsValid() {
		return nil, fmt.Errorf("cbom builder: unknown artifact kind %q", kind)
	}
	if kind != KindCBOM {
		return b.buildNonCrypto(ctx, kind, scope, authToken)
	}

	// The scope's query goes to inventory-service, which selects the assets in
	// SQL through the query language. cbom-service does NOT re-implement the
	// boundary: it used to translate a jsonb predicate into its own in-memory
	// matcher, which is a second opinion about what a scope means, and the
	// failure mode was an artifact covering more than the scope said.
	//
	// The query is validated here rather than assumed valid, because a scope
	// row predates this call: the language may have moved under it.
	params, err := scopeToParams(scope)
	if err != nil {
		return nil, err
	}

	cbomData, err := b.cbomHandler.GenerateCBOMData(ctx, params, authToken, scope.TenantID.String())
	if err != nil {
		return nil, fmt.Errorf("cbom builder: generate: %w", err)
	}

	// Canonical bytes are CycloneDX. This used to marshal cbomData
	// directly, which meant the download endpoint served our internal shape
	// (serial_number, bom_version, report_title) under a
	// Content-Type of application/vnd.cyclonedx+json — advertising a standard
	// while emitting something else, so any consumer trusting the header broke.
	//
	// Compact rather than indented: these bytes are hashed and signed, and
	// whitespace is presentational, so baking it into the hash would let a
	// formatting change invalidate every signature.
	bytes, err := formatters.NewCycloneDXFormatter().FormatCBOMAsCanonicalJSON(cbomData)
	if err != nil {
		return nil, fmt.Errorf("cbom builder: cyclonedx: %w", err)
	}

	// The private view the Enterprise diff reads. See BuildOutput.InternalBytes.
	internalBytes, err := json.Marshal(cbomData)
	if err != nil {
		return nil, fmt.Errorf("cbom builder: marshal internal: %w", err)
	}

	sum := sha256.Sum256(bytes)

	// Collect distinct asset IDs referenced by components. The attestation
	// layer (Phase 4) uses this to scope its findings query. Some
	// components — shared algorithms, for example — have no asset_id; those
	// are skipped silently.
	seen := make(map[uuid.UUID]struct{}, len(cbomData.Components))
	assetIDs := make([]uuid.UUID, 0, len(cbomData.Components))
	for _, c := range cbomData.Components {
		if c.AssetID == "" {
			continue
		}
		id, parseErr := uuid.Parse(c.AssetID)
		if parseErr != nil {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		assetIDs = append(assetIDs, id)
	}

	return &BuildOutput{
		CanonicalBytes:       bytes,
		InternalBytes:        internalBytes,
		ContentHash:          hex.EncodeToString(sum[:]),
		ComponentCount:       len(cbomData.Components),
		CycloneDXSpecVersion: firstNonEmpty(cbomData.SpecVersion, formatters.SpecVersion),
		AssetIDs:             assetIDs,
		Kind:                 KindCBOM,
	}, nil
}

// buildNonCrypto resolves the scope to its asset set and hands it to the
// asset-first assembler.
//
// The asset set is resolved HERE, through inventory-service, rather than in the
// assembler: the assembler reads the inventory tables directly (a join per
// asset-id set, not a second opinion about the boundary), and if it also chose
// WHICH assets, cbom-service would be back to two implementations of what a
// scope means — the exact thing the query-language pipeline removed.
func (b *Builder) buildNonCrypto(ctx context.Context, kind ArtifactKind, scope *scopes.Scope, authToken string) (*BuildOutput, error) {
	if b.xbom == nil {
		return nil, fmt.Errorf("%w: %s", ErrKindUnavailable, kind)
	}

	// Validated, not assumed valid — a scope row predates this call and the
	// language may have moved under it. Same refusal as the CBOM path: an
	// artifact whose contents are wider than its stated boundary is worse than
	// no artifact.
	canonical, err := scopes.ValidateQuery(scope.Query)
	if err != nil {
		return nil, &InvalidScopeQueryError{Query: scope.Query, Err: err}
	}

	assetIDs, err := b.cbomHandler.QueryScopeAssetIDs(ctx, canonical, authToken, scope.TenantID.String())
	if err != nil {
		return nil, fmt.Errorf("cbom builder: resolve scope assets: %w", err)
	}

	out, err := b.xbom.Assemble(ctx, kind, scope, assetIDs)
	if err != nil {
		return nil, err
	}
	out.Kind = kind
	return out, nil
}

// InvalidScopeQueryError reports a scope whose stored query no longer
// validates. The HTTP layer turns it into 422.
//
// It exists because the failure mode it replaces is invisible: a scope naming a
// field the pipeline ignored produced a CBOM covering MORE than the scope said,
// signed and dated, with nothing anywhere to say so. Refusing is the only
// answer that keeps an artifact's boundary claim true.
type InvalidScopeQueryError struct {
	Query string
	Err   error
}

func (e *InvalidScopeQueryError) Error() string {
	return fmt.Sprintf("scope query %q does not validate: %v", e.Query, e.Err)
}

func (e *InvalidScopeQueryError) Unwrap() error { return e.Err }

// scopeToParams turns a Scope into the params map GenerateCBOMData reads.
//
// The whole boundary is one string. What used to be eight predicate fields, a
// reflective translator, a per-field "can this deployment enforce it?" check
// and an in-memory matcher is now: validate, pass through, let the database
// answer.
func scopeToParams(scope *scopes.Scope) (map[string]interface{}, error) {
	canonical, err := scopes.ValidateQuery(scope.Query)
	if err != nil {
		return nil, &InvalidScopeQueryError{Query: scope.Query, Err: err}
	}
	out := map[string]interface{}{
		"includeAlgorithms":   true,
		"includeCertificates": true,
		"includeProtocols":    true,
		"includeKeys":         true,
		"includeLibraries":    true,
	}
	if canonical != "" {
		out[handlers.ParamAssetQuery] = canonical
	}
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
