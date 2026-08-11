package cbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

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
}

// NewBuilder constructs a Builder that delegates inventory fetching and
// CBOM assembly to the existing CBOMReportHandler.
func NewBuilder(h *handlers.CBOMReportHandler) *Builder {
	return &Builder{cbomHandler: h}
}

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
	// layer to scope its compliance_findings query.
	AssetIDs []uuid.UUID
}

// Build snapshots inventory matching the given Scope as of now and emits a
// canonical CycloneDX byte stream + content hash.
//
// `authToken` is the JWT to use for service-to-service calls to
// inventory-service. `tenantID` is duplicated on QueryParams.TenantID so the
// internal-call HMAC path can verify against inventory-service (Phase 0 fix).
func (b *Builder) Build(ctx context.Context, scope *scopes.Scope, authToken string) (*BuildOutput, error) {
	if scope == nil {
		return nil, fmt.Errorf("cbom builder: scope cannot be nil")
	}

	// Translate the scope predicate into the asset-selection rule the assembly
	// applies. Every field the predicate can express is enforced; a field the
	// translator does not know how to enforce is an error, not a silent
	// widening — see ErrUnsupportedPredicate.
	params, unsupported := predicateToParams(scope.Predicate)
	if len(unsupported) > 0 {
		return nil, &UnsupportedPredicateError{Fields: unsupported}
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
	// layer (Phase 4) uses this to scope its compliance_findings query. Some
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
	}, nil
}

// UnsupportedPredicateError reports scope predicate fields the generator cannot
// enforce. The HTTP layer turns it into 422.
//
// It exists because the failure mode it replaces is invisible: a scope naming a
// field the pipeline ignored produced a CBOM covering MORE than the scope said,
// signed and dated, with nothing anywhere to say so. Refusing is the only
// answer that keeps an artifact's boundary claim true.
type UnsupportedPredicateError struct {
	Fields []string
}

func (e *UnsupportedPredicateError) Error() string {
	return fmt.Sprintf("scope predicate uses fields this deployment cannot evaluate: %s",
		strings.Join(e.Fields, ", "))
}

// clauseTranslators maps every JSON field of scopes.PredicateClause to the
// AssetClause field that enforces it.
//
// Keying by the JSON tag and walking the struct reflectively (rather than
// listing fields by hand) is what makes the unsupported-field check able to
// fail: add a field to scopes.PredicateClause and forget to wire it here, and
// any scope using it is rejected at generate time instead of quietly ignored.
// TestPredicateTranslation_CoversEveryPredicateField fails at the same moment,
// so the gap surfaces in CI rather than in a customer's evidence.
var clauseTranslators = map[string]func(*handlers.AssetClause, []string){
	"environment":     func(c *handlers.AssetClause, v []string) { c.Environment = v },
	"asset_type":      func(c *handlers.AssetClause, v []string) { c.AssetType = v },
	"asset_ownership": func(c *handlers.AssetClause, v []string) { c.AssetOwnership = v },
	"asset_status":    func(c *handlers.AssetClause, v []string) { c.AssetStatus = v },
	"business_unit":   func(c *handlers.AssetClause, v []string) { c.BusinessUnit = v },
	"location_region": func(c *handlers.AssetClause, v []string) { c.LocationRegion = v },
	"risk_level":      func(c *handlers.AssetClause, v []string) { c.RiskLevel = v },
	"tags_any_of":     func(c *handlers.AssetClause, v []string) { c.TagsAnyOf = v },
}

// predicateToParams flattens a scope Predicate into the params map shape
// understood by CBOMReportHandler.GenerateCBOMData, and reports any populated
// predicate field it could not translate.
//
// Both clauses are carried through. Exclude used to be dropped entirely, which
// made the seeded "Non-Dev/Test" scope — whose whole definition is an exclude —
// produce byte-for-byte the same artifact as "All". So did AssetType and the
// five other fields a tenant can set through POST /scopes.
//
// Spec: docsv4/internal/developer/architecture/cbom/scope-predicate-shape.md.
func predicateToParams(p scopes.Predicate) (map[string]interface{}, []string) {
	include, unsupportedInclude := translateClause(p.Include)
	exclude, unsupportedExclude := translateClause(p.Exclude)

	out := map[string]interface{}{
		"includeAlgorithms":   true,
		"includeCertificates": true,
		"includeProtocols":    true,
		"includeKeys":         true,
		"includeLibraries":    true,
	}
	predicate := handlers.AssetPredicate{Include: include, Exclude: exclude}
	if !predicate.IsEmpty() {
		out[handlers.ParamAssetPredicate] = predicate
	}
	return out, uniqueSorted(append(unsupportedInclude, unsupportedExclude...))
}

func translateClause(clause *scopes.PredicateClause) (*handlers.AssetClause, []string) {
	if clause == nil {
		return nil, nil
	}

	var (
		out         handlers.AssetClause
		unsupported []string
		populated   bool
	)

	v := reflect.ValueOf(*clause)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() != reflect.Slice || field.Len() == 0 {
			continue
		}
		values, ok := field.Interface().([]string)
		if !ok || len(values) == 0 {
			continue
		}
		name := jsonFieldName(t.Field(i))
		apply, known := clauseTranslators[name]
		if !known {
			unsupported = append(unsupported, name)
			continue
		}
		apply(&out, values)
		populated = true
	}

	if !populated {
		return nil, unsupported
	}
	return &out, unsupported
}

func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	if idx := strings.Index(tag, ","); idx >= 0 {
		tag = tag[:idx]
	}
	if tag == "" || tag == "-" {
		return f.Name
	}
	return tag
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
