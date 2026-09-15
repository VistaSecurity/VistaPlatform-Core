package xbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/cbom"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/formatters"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/models"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
)

// Assembler implements cbom.KindAssembler for the three non-crypto kinds.
type Assembler struct {
	source *Source
	// now and newSerial are injectable so a golden test can pin the two
	// non-deterministic inputs to the canonical bytes. Production leaves them
	// nil and gets time.Now / uuid.New.
	now       func() time.Time
	newSerial func() uuid.UUID
}

// compile-time proof the assembler satisfies the Core seam. If KindAssembler
// changes this breaks here rather than in cmd/main.go.
var _ cbom.KindAssembler = (*Assembler)(nil)

// NewAssembler constructs an Assembler reading through the given Source.
func NewAssembler(source *Source) *Assembler { return &Assembler{source: source} }

// WithClock pins the timestamp and serial number. Test-only in intent, exported
// because the golden test lives in the package's external test file.
func (a *Assembler) WithClock(now func() time.Time, newSerial func() uuid.UUID) *Assembler {
	a.now = now
	a.newSerial = newSerial
	return a
}

// Assemble reads the inventory for the given assets and produces the canonical
// CycloneDX bytes, the private diff view, and the hash over the former.
//
// The asset set arrives resolved — see the package doc for why this does not
// choose it.
func (a *Assembler) Assemble(ctx context.Context, kind cbom.ArtifactKind, scope *scopes.Scope, assetIDs []uuid.UUID) (*cbom.BuildOutput, error) {
	if scope == nil {
		return nil, fmt.Errorf("xbom: scope cannot be nil")
	}
	switch kind {
	case cbom.KindSBOM, cbom.KindHBOM, cbom.KindInventory:
	default:
		return nil, fmt.Errorf("xbom: kind %q is not assembled here", kind)
	}

	snap, err := a.source.Load(ctx, scope.TenantID, assetIDs)
	if err != nil {
		return nil, err
	}

	doc, err := BuildDocument(string(kind), snap, DocumentInput{
		SerialNumber: a.serial(),
		GeneratedAt:  a.clock(),
		ScopeName:    scope.Name,
	})
	if err != nil {
		return nil, err
	}

	// Compact, not indented: these bytes are hashed and signed, so whitespace
	// baked into the hash would let a formatting change invalidate every
	// signature. Same rule the CBOM path follows, for the same reason.
	canonical, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("xbom: marshal canonical: %w", err)
	}

	internal, err := json.Marshal(internalView(kind, doc, scope, a.clock()))
	if err != nil {
		return nil, fmt.Errorf("xbom: marshal internal: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return &cbom.BuildOutput{
		CanonicalBytes:       canonical,
		InternalBytes:        internal,
		ContentHash:          hex.EncodeToString(sum[:]),
		ComponentCount:       EntryCount(doc),
		CycloneDXSpecVersion: formatters.SpecVersion,
		AssetIDs:             assetIDs,
		Kind:                 kind,
	}, nil
}

func (a *Assembler) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now().UTC()
}

func (a *Assembler) serial() uuid.UUID {
	if a.newSerial != nil {
		return a.newSerial()
	}
	return uuid.New()
}

// internalView projects the emitted document into the private models.CBOMData
// shape the Enterprise comparison reads.
//
// It exists for the same reason the CBOM path keeps one: `internal_content` is
// what diff parses, and diff parses it as CBOMData. Without this, comparing two
// SBOMs would unmarshal a CycloneDX document into CBOMData, match nothing, and
// report every component as removed-then-added on both sides — a diff that is
// confidently, quietly wrong.
//
// It is a PROJECTION of the document, not a second walk of the inventory. Two
// walks would be two chances to disagree, and a comparison that disagreed with
// the artifact it compares is worse than no comparison.
//
// Never served, never hashed.
func internalView(kind cbom.ArtifactKind, doc *formatters.CDXDocument, scope *scopes.Scope, generatedAt time.Time) *models.CBOMData {
	components := make([]models.CBOMComponent, 0, len(doc.Components)+len(doc.Services))

	for _, c := range doc.Components {
		comp := models.CBOMComponent{
			ID:     c.BOMRef,
			BOMRef: c.BOMRef,
			Name:   c.Name,
			// The CycloneDX type, carried verbatim. matchKeyFor's switch does
			// not recognise it and falls through to its `ref:` case, which is
			// the CORRECT match key here: our bom-refs are derived from
			// database ids, so `ref:asset/<uuid>` is stable across artifacts
			// and aligns the same asset in both.
			Type:       models.CBOMComponentType(c.Type),
			Properties: internalProperties(c.Properties),
		}
		// A software component's identity is its purl, which the diff's
		// existing library rules already match on — and its version, which
		// isMaterialChange already treats as a material change. Filling
		// LibraryDetails is what gets an SBOM a real diff rather than a
		// ref-only one.
		if kind == cbom.KindSBOM {
			comp.Type = models.CBOMComponentTypeLibrary
			comp.LibraryDetails = &models.CBOMLibraryDetails{
				Name:    c.Name,
				Version: c.Version,
				Vendor:  c.Group,
				CPE:     c.CPE,
				PURL:    c.Purl,
			}
		}
		comp.AssetID = propertyValue(c.Properties, propAssetUID)
		comp.AssetType = propertyValue(c.Properties, propAssetClass)
		comp.Environment = propertyValue(c.Properties, propAssetEnv)
		comp.Hostname = firstNonEmpty(
			propertyValue(c.Properties, propIDPrefix+"fqdn"),
			propertyValue(c.Properties, propIDPrefix+"hostname"),
		)
		components = append(components, comp)
	}

	for _, s := range doc.Services {
		components = append(components, models.CBOMComponent{
			ID:         s.BOMRef,
			BOMRef:     s.BOMRef,
			Name:       s.Name,
			Type:       models.CBOMComponentType("service"),
			AssetID:    propertyValue(s.Properties, propEndpAsset),
			Properties: internalProperties(s.Properties),
		})
	}

	return &models.CBOMData{
		SerialNumber: doc.SerialNumber,
		BOMVersion:   doc.Version,
		GeneratedAt:  generatedAt.UTC(),
		ReportTitle:  documentTitle(string(kind), scope.Name),
		SpecVersion:  doc.SpecVersion,
		Summary:      models.CBOMSummary{TotalComponents: len(components)},
		Components:   components,
	}
}

func internalProperties(props []formatters.CDXProperty) []models.CBOMProperty {
	if len(props) == 0 {
		return nil
	}
	out := make([]models.CBOMProperty, 0, len(props))
	for _, p := range props {
		out = append(out, models.CBOMProperty{Name: p.Name, Value: p.Value})
	}
	return out
}
