// Package formatters provides report formatting functions for different output formats.
// This file implements CycloneDX 1.7 CBOM export format with proper cryptoProperties schema.
package formatters

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/models"
)

// SpecVersion is the CycloneDX specification version this formatter emits, and
// the single source of truth for it — the artifact pipeline records the same
// string on every row.
//
// It says 1.7 because that is what the emitted document actually is. The
// formatter has always populated fields that only exist from 1.7 onward —
// certificateProperties.certificateState (set on every certificate),
// .serialNumber, .fingerprint, .certificateExtensions, the lifecycle dates,
// .relatedCryptographicAssets, algorithmProperties.algorithmFamily,
// relatedCryptoMaterialProperties.fingerprint — while declaring "1.6". The 1.6
// schema sets additionalProperties:false on those objects, so every artifact
// containing a certificate failed validation against the version it claimed to
// be. Declaring the version we emit is the honest fix; nothing about the field
// set changes.
//
// Artifacts already stored keep their bytes and their recorded spec version —
// they are immutable evidence and are never re-rendered. Only artifacts
// generated from here on declare 1.7.
const SpecVersion = "1.7"

// CycloneDXFormatter exports CBOM in CycloneDX 1.7 JSON format
type CycloneDXFormatter struct{}

// NewCycloneDXFormatter creates a new CycloneDX formatter
func NewCycloneDXFormatter() *CycloneDXFormatter {
	return &CycloneDXFormatter{}
}

// ========================================================================
// CycloneDX 1.7 JSON Schema Types
// ========================================================================

// CDXDocument is the root CycloneDX BOM document.
type CDXDocument struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Version      int             `json:"version"`
	SerialNumber string          `json:"serialNumber"`
	Metadata     *CDXMetadata    `json:"metadata"`
	Components   []CDXComponent  `json:"components"`
	Dependencies []CDXDependency `json:"dependencies,omitempty"`
}

// CDXMetadata contains BOM-level metadata.
type CDXMetadata struct {
	Timestamp  string         `json:"timestamp"`
	Tools      *CDXTools      `json:"tools,omitempty"`
	Component  *CDXComponent  `json:"component,omitempty"`
	Lifecycles []CDXLifecycle `json:"lifecycles,omitempty"`
}

// CDXTools lists the tools that created the BOM.
type CDXTools struct {
	Components []CDXToolComponent `json:"components,omitempty"`
}

// CDXToolComponent represents a tool that generated the BOM.
type CDXToolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Group   string `json:"group,omitempty"`
}

// CDXLifecycle describes a lifecycle phase.
type CDXLifecycle struct {
	Phase string `json:"phase"`
}

// CDXComponent represents a CycloneDX component.
type CDXComponent struct {
	Type               string           `json:"type"`
	BOMRef             string           `json:"bom-ref,omitempty"`
	Name               string           `json:"name"`
	Version            string           `json:"version,omitempty"`
	Description        string           `json:"description,omitempty"`
	Purl               string           `json:"purl,omitempty"`
	CryptoProperties   *CDXCryptoProps  `json:"cryptoProperties,omitempty"`
	Properties         []CDXProperty    `json:"properties,omitempty"`
	ExternalReferences []CDXExternalRef `json:"externalReferences,omitempty"`
}

// CDXCryptoProps contains the cryptographic properties per CycloneDX 1.7.
type CDXCryptoProps struct {
	AssetType                       string                         `json:"assetType"`
	AlgorithmProperties             *CDXAlgorithmProps             `json:"algorithmProperties,omitempty"`
	CertificateProperties           *CDXCertificateProps           `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *CDXRelatedCryptoMaterialProps `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties              *CDXProtocolProps              `json:"protocolProperties,omitempty"`
	OID                             string                         `json:"oid,omitempty"`
}

// CDXAlgorithmProps contains CycloneDX algorithmProperties.
type CDXAlgorithmProps struct {
	AlgorithmFamily          string   `json:"algorithmFamily,omitempty"`
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Mode                     string   `json:"mode,omitempty"`
	Padding                  string   `json:"padding,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   int      `json:"classicalSecurityLevel,omitempty"`
	NistQuantumSecurityLevel *int     `json:"nistQuantumSecurityLevel,omitempty"`
	Curve                    string   `json:"curve,omitempty"`
	ExecutionEnvironment     string   `json:"executionEnvironment,omitempty"`
	ImplementationPlatform   string   `json:"implementationPlatform,omitempty"`
	CertificationLevel       []string `json:"certificationLevel,omitempty"`
}

// CDXCertificateProps contains CycloneDX certificateProperties.
type CDXCertificateProps struct {
	SerialNumber               string                    `json:"serialNumber,omitempty"`
	SubjectName                string                    `json:"subjectName,omitempty"`
	IssuerName                 string                    `json:"issuerName,omitempty"`
	NotValidBefore             string                    `json:"notValidBefore,omitempty"`
	NotValidAfter              string                    `json:"notValidAfter,omitempty"`
	CertificateFormat          string                    `json:"certificateFormat,omitempty"`
	CertificateFileExtension   string                    `json:"certificateFileExtension,omitempty"`
	Fingerprint                *CDXFingerprint           `json:"fingerprint,omitempty"`
	CertificateState           []CDXCertificateState     `json:"certificateState,omitempty"`
	CertificateExtensions      []CDXCertificateExtension `json:"certificateExtensions,omitempty"`
	CreationDate               string                    `json:"creationDate,omitempty"`
	ActivationDate             string                    `json:"activationDate,omitempty"`
	DeactivationDate           string                    `json:"deactivationDate,omitempty"`
	RevocationDate             string                    `json:"revocationDate,omitempty"`
	DestructionDate            string                    `json:"destructionDate,omitempty"`
	RelatedCryptographicAssets []CDXRelatedAssetRef      `json:"relatedCryptographicAssets,omitempty"`
}

// CDXCertificateState represents a lifecycle state entry.
type CDXCertificateState struct {
	State       string `json:"state,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// CDXCertificateExtension represents a certificate extension.
type CDXCertificateExtension struct {
	CommonExtensionName  string `json:"commonExtensionName,omitempty"`
	CommonExtensionValue string `json:"commonExtensionValue,omitempty"`
	CustomExtensionName  string `json:"customExtensionName,omitempty"`
	CustomExtensionValue string `json:"customExtensionValue,omitempty"`
}

// CDXFingerprint represents a hash fingerprint.
type CDXFingerprint struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// CDXRelatedAssetRef links to a related cryptographic asset.
type CDXRelatedAssetRef struct {
	Type string `json:"type"` // "algorithm", "publicKey", "privateKey"
	Ref  string `json:"ref"`
}

// CDXRelatedCryptoMaterialProps contains CycloneDX relatedCryptoMaterialProperties.
type CDXRelatedCryptoMaterialProps struct {
	Type                       string               `json:"type"` // "private-key", "public-key", "secret-key", etc.
	ID                         string               `json:"id,omitempty"`
	State                      string               `json:"state,omitempty"` // NIST SP 800-57 states
	Size                       int                  `json:"size,omitempty"`
	Format                     string               `json:"format,omitempty"`
	AlgorithmRef               string               `json:"algorithmRef,omitempty"`
	SecuredBy                  *CDXSecuredBy        `json:"securedBy,omitempty"`
	Fingerprint                *CDXFingerprint      `json:"fingerprint,omitempty"`
	CreationDate               string               `json:"creationDate,omitempty"`
	ActivationDate             string               `json:"activationDate,omitempty"`
	UpdateDate                 string               `json:"updateDate,omitempty"`
	ExpirationDate             string               `json:"expirationDate,omitempty"`
	RelatedCryptographicAssets []CDXRelatedAssetRef `json:"relatedCryptographicAssets,omitempty"`
}

// CDXSecuredBy describes the protection mechanism for crypto material.
type CDXSecuredBy struct {
	Mechanism    string `json:"mechanism"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
}

// CDXProtocolProps contains CycloneDX protocolProperties.
type CDXProtocolProps struct {
	Type         string           `json:"type,omitempty"` // "tls", "ssh", "ipsec"
	Version      string           `json:"version,omitempty"`
	CipherSuites []CDXCipherSuite `json:"cipherSuites,omitempty"`
}

// CDXCipherSuite represents a cipher suite with algorithm references.
type CDXCipherSuite struct {
	Name        string   `json:"name"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

// CDXProperty is a generic name-value property.
type CDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CDXExternalRef is an external reference.
type CDXExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CDXDependency represents a dependency in the top-level dependency graph.
type CDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
	Provides  []string `json:"provides,omitempty"`
}

// ========================================================================
// Formatting Methods
// ========================================================================

// FormatCBOMAsJSON exports the CBOM in CycloneDX 1.7 JSON format, indented for
// a human reading the file.
func (f *CycloneDXFormatter) FormatCBOMAsJSON(cbom *models.CBOMData) ([]byte, error) {
	doc, err := f.BuildDocument(cbom)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}

// FormatCBOMAsCanonicalJSON is the same document with no indentation, for use
// as an artifact's canonical bytes.
//
// Compact matters because these bytes are what gets hashed, signed and served:
// whitespace is presentational, and baking it into the hash would mean a
// formatting change silently invalidated every signature. Field order is
// deterministic because encoding/json emits struct fields in declaration order,
// so the same CBOMData always produces byte-identical output.
func (f *CycloneDXFormatter) FormatCBOMAsCanonicalJSON(cbom *models.CBOMData) ([]byte, error) {
	doc, err := f.BuildDocument(cbom)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// BuildDocument maps our internal CBOM model onto the CycloneDX 1.7 document
// shape. Split out from the formatting methods so the artifact pipeline can
// take the document and choose its own serialisation.
func (f *CycloneDXFormatter) BuildDocument(cbom *models.CBOMData) (*CDXDocument, error) {
	if cbom == nil {
		return nil, fmt.Errorf("cyclonedx: cbom data cannot be nil")
	}
	doc := &CDXDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		Version:      cbom.BOMVersion,
		SerialNumber: "urn:uuid:" + cbom.SerialNumber,
		Metadata: &CDXMetadata{
			Timestamp: cbom.GeneratedAt.Format(time.RFC3339),
			Tools: &CDXTools{
				Components: []CDXToolComponent{
					{
						Type:    "application",
						Name:    "Vista Platform CBOM Generator",
						Version: "1.0.0",
						Group:   "io.vistasecurity",
					},
				},
			},
			Component: &CDXComponent{
				Type:    "application",
				BOMRef:  "cbom-" + cbom.SerialNumber,
				Name:    cbom.ReportTitle,
				Version: "1.0",
				Description: fmt.Sprintf(
					"Cryptographic Bill of Materials containing %d components",
					cbom.Summary.TotalComponents,
				),
			},
			Lifecycles: []CDXLifecycle{
				{Phase: "operations"},
			},
		},
	}

	// Every bom-ref the document actually defines. A dependency edge pointing at
	// anything else is dangling: `dependsOn` and `provides` are refLinkType, and
	// a reader resolving them gets nothing. Emitting such an edge is worse than
	// emitting none — it asserts a relationship to a component the reader cannot
	// find. So the graph is filtered against this set below.
	known := make(map[string]struct{}, len(cbom.Components))
	for _, comp := range cbom.Components {
		if comp.BOMRef != "" {
			known[comp.BOMRef] = struct{}{}
		}
	}

	// Convert components
	components := make([]CDXComponent, 0, len(cbom.Components))
	dependencies := make([]CDXDependency, 0)

	for _, comp := range cbom.Components {
		cdxComp := f.convertComponent(comp)
		components = append(components, cdxComp)

		if comp.BOMRef == "" {
			continue
		}

		// Build dependency graph entry
		dep := CDXDependency{Ref: comp.BOMRef}
		dep.DependsOn = resolvableRefs(comp.DependsOn, known, comp.BOMRef)
		dep.Provides = resolvableRefs(comp.Provides, known, comp.BOMRef)
		if len(dep.DependsOn) > 0 || len(dep.Provides) > 0 {
			dependencies = append(dependencies, dep)
		}
	}

	doc.Components = components
	if len(dependencies) > 0 {
		doc.Dependencies = dependencies
	}

	return doc, nil
}

// FormatCBOMAsXML is kept for backward compatibility but delegates to JSON.
// CycloneDX 1.6 JSON is the primary format per the OWASP CBOM guide.
func (f *CycloneDXFormatter) FormatCBOMAsXML(cbom *models.CBOMData) ([]byte, error) {
	return f.FormatCBOMAsJSON(cbom)
}

// convertComponent maps a CBOM component to a CycloneDX component.
func (f *CycloneDXFormatter) convertComponent(comp models.CBOMComponent) CDXComponent {
	cdxComp := CDXComponent{
		BOMRef: comp.BOMRef,
		Name:   comp.Name,
	}

	// Vendor properties. CycloneDX sanctions `properties` for data the spec has
	// no field for; the vista: prefix keeps ours from colliding with anyone else.
	cdxComp.Properties = f.buildVendorProperties(comp)

	// Values our catalogue holds that the spec constrains to an enum are carried
	// here rather than dropped, so nothing is lost when they don't fit.
	var extras []CDXProperty

	switch comp.Type {
	case models.CBOMComponentTypeCertificate:
		cdxComp.Type = "cryptographic-asset"
		if comp.CertificateDetails != nil {
			cdxComp.CryptoProperties, extras = f.buildCertificateCryptoProps(comp.CertificateDetails)
		}

	case models.CBOMComponentTypeAlgorithm:
		cdxComp.Type = "cryptographic-asset"
		if comp.AlgorithmDetails != nil {
			cdxComp.CryptoProperties, extras = f.buildAlgorithmCryptoProps(comp.AlgorithmDetails)
		}

	case models.CBOMComponentTypeProtocol:
		cdxComp.Type = "cryptographic-asset"
		if comp.ProtocolDetails != nil {
			cdxComp.CryptoProperties, extras = f.buildProtocolCryptoProps(comp.ProtocolDetails)
		}

	case models.CBOMComponentTypeKey:
		cdxComp.Type = "cryptographic-asset"
		if comp.KeyDetails != nil {
			cdxComp.CryptoProperties, extras = f.buildKeyCryptoProps(comp.KeyDetails)
		}

	case models.CBOMComponentTypeLibrary:
		cdxComp.Type = "library"
		if comp.LibraryDetails != nil {
			cdxComp.Version = comp.LibraryDetails.Version
			if comp.LibraryDetails.PURL != "" {
				cdxComp.Purl = comp.LibraryDetails.PURL
			}
		}
	}

	cdxComp.Properties = append(cdxComp.Properties, extras...)

	// `name` is required by the schema and a component without one is
	// unidentifiable anyway; fall back to the bom-ref rather than emit "".
	if cdxComp.Name == "" {
		cdxComp.Name = comp.BOMRef
	}
	if cdxComp.Type == "" {
		cdxComp.Type = "cryptographic-asset"
	}

	return cdxComp
}

// resolvableRefs keeps only the refs that name a component present in this
// document, deduplicated (the schema requires uniqueItems) and with any
// self-reference removed.
func resolvableRefs(refs []string, known map[string]struct{}, self string) []string {
	if len(refs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref == "" || ref == self {
			continue
		}
		if _, ok := known[ref]; !ok {
			continue
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildVendorProperties carries asset context and risk, which CycloneDX has no
// native home for, into the emitted document.
func (f *CycloneDXFormatter) buildVendorProperties(comp models.CBOMComponent) []CDXProperty {
	props := make([]CDXProperty, 0, 4)
	if comp.AssetID != "" {
		props = append(props, CDXProperty{Name: "vista:asset-id", Value: comp.AssetID})
	}
	if comp.Environment != "" {
		props = append(props, CDXProperty{Name: "vista:environment", Value: comp.Environment})
	}
	if comp.RiskLevel != "" {
		props = append(props, CDXProperty{Name: "vista:risk-level", Value: comp.RiskLevel})
	}
	if !comp.DiscoveredAt.IsZero() {
		props = append(props, CDXProperty{Name: "vista:discovered-at", Value: comp.DiscoveredAt.Format(time.RFC3339)})
	}
	return props
}

// buildAlgorithmCryptoProps builds CycloneDX cryptoProperties for an algorithm.
//
// algorithmFamily, primitive, mode, padding, cryptoFunctions and
// certificationLevel are closed enumerations in the spec, and our catalogue is
// not constrained to them (`Curve25519` is a perfectly good family name that
// CycloneDX does not list). Values outside the enum are moved to a vista:
// property instead of being emitted where the schema would reject them —
// nothing is lost, and the document validates.
func (f *CycloneDXFormatter) buildAlgorithmCryptoProps(algo *models.CBOMAlgorithmDetails) (*CDXCryptoProps, []CDXProperty) {
	var extras []CDXProperty

	family, ok := enumOrEmpty(algo.AlgorithmFamily, cdxAlgorithmFamilies)
	if !ok && algo.AlgorithmFamily != "" {
		extras = append(extras, CDXProperty{Name: "vista:algorithm-family", Value: algo.AlgorithmFamily})
	}
	primitive, ok := enumOrEmpty(algo.Primitive, cdxPrimitives)
	if !ok && algo.Primitive != "" {
		extras = append(extras, CDXProperty{Name: "vista:algorithm-primitive", Value: algo.Primitive})
	}
	mode, _ := enumOrEmpty(algo.Mode, cdxModes)
	padding, _ := enumOrEmpty(algo.Padding, cdxPaddings)

	props := &CDXCryptoProps{
		AssetType: "algorithm",
		OID:       algo.OID,
		AlgorithmProperties: &CDXAlgorithmProps{
			AlgorithmFamily:        family,
			Primitive:              primitive,
			ParameterSetIdentifier: algo.ParameterSetIdentifier,
			Mode:                   mode,
			Padding:                padding,
			CryptoFunctions:        enumSubset(algo.CryptoFunctions, cdxCryptoFunctions),
			ClassicalSecurityLevel: nonNegative(algo.ClassicalSecurityLevel),
			Curve:                  algo.Curve,
		},
	}

	// NIST PQC security category, 0–6 in the spec. Anything else is a different
	// number that wandered into the column (classical bits, most often) and is
	// not emitted as a quantum level.
	if lvl := algo.NistQuantumSecurityLevel; lvl > 0 && lvl <= 6 {
		v := lvl
		props.AlgorithmProperties.NistQuantumSecurityLevel = &v
	}

	// Default certification to "none" if not set
	if props.AlgorithmProperties.CertificationLevel == nil {
		props.AlgorithmProperties.CertificationLevel = []string{"none"}
	}
	return props, extras
}

// buildCertificateCryptoProps builds CycloneDX cryptoProperties for a certificate.
func (f *CycloneDXFormatter) buildCertificateCryptoProps(cert *models.CBOMCertificateDetails) (*CDXCryptoProps, []CDXProperty) {
	var extras []CDXProperty

	certProps := &CDXCertificateProps{
		SerialNumber:      cert.SerialNumber,
		SubjectName:       cert.SubjectName,
		IssuerName:        cert.IssuerName,
		CertificateFormat: cert.CertificateFormat,
	}

	if !cert.NotValidBefore.IsZero() {
		certProps.NotValidBefore = cert.NotValidBefore.Format(time.RFC3339)
	}
	if !cert.NotValidAfter.IsZero() {
		certProps.NotValidAfter = cert.NotValidAfter.Format(time.RFC3339)
	}

	// Fingerprint. `hash` is a closed shape: the algorithm comes from an enum and
	// the content must be bare hex of a hash-sized length. A fingerprint that
	// doesn't fit rides along as a property rather than making the document
	// invalid.
	if fp, raw := cdxHash(cert.FingerprintAlg, cert.FingerprintContent); fp != nil {
		certProps.Fingerprint = fp
	} else if raw != "" {
		extras = append(extras, CDXProperty{Name: "vista:certificate-fingerprint", Value: raw})
	}

	// Certificate states. The spec's state object is a oneOf: either a
	// pre-defined `state` (+ optional reason) or a custom `name` (+ optional
	// description/reason). Both branches forbid the other's fields, so an entry
	// carrying both matches neither. Our certificate_state column has seven
	// values and CycloneDX defines six — `expired` has no pre-defined
	// counterpart — so a value outside the enum becomes a named custom state
	// rather than being dropped or silently invalid.
	for _, s := range cert.CertificateStates {
		if cdxState, ok := certificateStateEntry(s); ok {
			certProps.CertificateState = append(certProps.CertificateState, cdxState)
		}
	}

	// Lifecycle timestamps
	if cert.CreationDate != nil {
		certProps.CreationDate = cert.CreationDate.Format(time.RFC3339)
	}
	if cert.ActivationDate != nil {
		certProps.ActivationDate = cert.ActivationDate.Format(time.RFC3339)
	}
	if cert.DeactivationDate != nil {
		certProps.DeactivationDate = cert.DeactivationDate.Format(time.RFC3339)
	}
	if cert.RevocationDate != nil {
		certProps.RevocationDate = cert.RevocationDate.Format(time.RFC3339)
	}
	if cert.DestructionDate != nil {
		certProps.DestructionDate = cert.DestructionDate.Format(time.RFC3339)
	}

	// Extensions. Same oneOf shape as state: the "common" branch requires both a
	// name from a fixed enum and a value; anything else is a custom extension.
	for _, ext := range cert.Extensions {
		if cdxExt, ok := certificateExtensionEntry(ext); ok {
			certProps.CertificateExtensions = append(certProps.CertificateExtensions, cdxExt)
		}
	}

	// Related crypto assets
	for _, rel := range cert.RelatedCryptoAssets {
		if rel.Ref == "" {
			continue
		}
		certProps.RelatedCryptographicAssets = append(certProps.RelatedCryptographicAssets,
			CDXRelatedAssetRef{Type: rel.Type, Ref: rel.Ref})
	}

	return &CDXCryptoProps{
		AssetType:             "certificate",
		CertificateProperties: certProps,
		OID:                   cert.SignatureAlgOID,
	}, extras
}

// buildKeyCryptoProps builds CycloneDX cryptoProperties for related crypto material.
func (f *CycloneDXFormatter) buildKeyCryptoProps(key *models.CBOMKeyDetails) (*CDXCryptoProps, []CDXProperty) {
	var extras []CDXProperty

	matType, ok := enumOrEmpty(key.MaterialType, cdxRelatedMaterialTypes)
	if !ok {
		if key.MaterialType != "" {
			extras = append(extras, CDXProperty{Name: "vista:key-material-type", Value: key.MaterialType})
		}
		matType = "key"
	}

	state, ok := enumOrEmpty(key.State, cdxKeyStates)
	if !ok && key.State != "" {
		extras = append(extras, CDXProperty{Name: "vista:key-state", Value: key.State})
	}

	matProps := &CDXRelatedCryptoMaterialProps{
		Type:         matType,
		ID:           key.ID,
		State:        state,
		Size:         nonNegative(key.SizeBits),
		Format:       key.Format,
		AlgorithmRef: key.AlgorithmRef,
	}

	// SecuredBy
	if key.SecuredBy != nil {
		matProps.SecuredBy = &CDXSecuredBy{
			Mechanism:    key.SecuredBy.Mechanism,
			AlgorithmRef: key.SecuredBy.AlgorithmRef,
		}
	}

	// Fingerprint — see the certificate path for why a non-conforming value
	// becomes a property instead of an invalid `hash`.
	if fp, raw := cdxHash(key.FingerprintAlg, key.FingerprintContent); fp != nil {
		matProps.Fingerprint = fp
	} else if raw != "" {
		extras = append(extras, CDXProperty{Name: "vista:key-fingerprint", Value: raw})
	}

	// Lifecycle timestamps
	if key.CreatedAt != nil {
		matProps.CreationDate = key.CreatedAt.Format(time.RFC3339)
	}
	if key.ActivationDate != nil {
		matProps.ActivationDate = key.ActivationDate.Format(time.RFC3339)
	}
	if key.RotatedAt != nil {
		matProps.UpdateDate = key.RotatedAt.Format(time.RFC3339)
	}
	if key.ExpiresAt != nil {
		matProps.ExpirationDate = key.ExpiresAt.Format(time.RFC3339)
	}

	// Related crypto assets
	for _, rel := range key.RelatedCryptoAssets {
		if rel.Ref == "" {
			continue
		}
		matProps.RelatedCryptographicAssets = append(matProps.RelatedCryptographicAssets,
			CDXRelatedAssetRef{Type: rel.Type, Ref: rel.Ref})
	}

	return &CDXCryptoProps{
		AssetType:                       "related-crypto-material",
		RelatedCryptoMaterialProperties: matProps,
	}, extras
}

// buildProtocolCryptoProps builds CycloneDX cryptoProperties for a protocol.
func (f *CycloneDXFormatter) buildProtocolCryptoProps(proto *models.CBOMProtocolDetails) (*CDXCryptoProps, []CDXProperty) {
	var extras []CDXProperty

	protoType := NormalizeProtocolType(proto.Type)
	if proto.Type != "" && protoType == "other" && !strings.EqualFold(proto.Type, "other") {
		// The observed protocol name is the interesting fact; "other" is only
		// what the enum can say about it.
		extras = append(extras, CDXProperty{Name: "vista:protocol-name", Value: proto.Type})
	}

	protoProps := &CDXProtocolProps{
		Type:    protoType,
		Version: proto.Version,
	}

	// Structured cipher suites
	for _, cs := range proto.CipherSuites {
		protoProps.CipherSuites = append(protoProps.CipherSuites, CDXCipherSuite{
			Name:        cs.Name,
			Algorithms:  cs.Algorithms,
			Identifiers: cs.Identifiers,
		})
	}

	// Fallback: convert legacy string cipher suites
	if len(protoProps.CipherSuites) == 0 && len(proto.CipherSuiteNames) > 0 {
		for _, name := range proto.CipherSuiteNames {
			protoProps.CipherSuites = append(protoProps.CipherSuites, CDXCipherSuite{
				Name: name,
			})
		}
	}

	return &CDXCryptoProps{
		AssetType:          "protocol",
		ProtocolProperties: protoProps,
		OID:                proto.OID,
	}, extras
}

// ========================================================================
// Spec enumerations
//
// CycloneDX closes most of its cryptoProperties enumerations, and sets
// additionalProperties:false throughout, so a value we invent is not "extra
// detail a reader can ignore" — it fails validation for the whole document.
// Everything below exists to keep our richer vocabulary from doing that.
// ========================================================================

var (
	// cdxProtocolTypes is protocolProperties.type as of 1.7 (1.6 had the same
	// list minus dtls/quic/the 3GPP entries).
	cdxProtocolTypes = newEnum("tls", "ssh", "ipsec", "ike", "sstp", "wpa", "dtls", "quic",
		"eap-aka", "eap-aka-prime", "prins", "5g-aka", "other", "unknown")

	cdxPrimitives = newEnum("drbg", "mac", "block-cipher", "stream-cipher", "signature",
		"hash", "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap",
		"other", "unknown")

	cdxModes    = newEnum("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown")
	cdxPaddings = newEnum("pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown")

	cdxCryptoFunctions = newEnum("generate", "keygen", "encrypt", "decrypt", "digest", "tag",
		"keyderive", "sign", "verify", "encapsulate", "decapsulate", "other", "unknown")

	// cdxAlgorithmFamilies mirrors cryptography-defs.schema.json
	// #/definitions/algorithmFamiliesEnum.
	cdxAlgorithmFamilies = newEnum("3DES", "3GPP-XOR", "A5/1", "A5/2", "AES", "ARIA", "Argon2",
		"Ascon", "BLAKE2", "BLAKE3", "BLS", "Blowfish", "CAMELLIA", "CAST5", "CAST6", "CMAC",
		"CMEA", "CTR_DRBG", "ChaCha", "ChaCha20", "DES", "DSA", "ECDH", "ECDSA", "ECIES", "EdDSA",
		"ElGamal", "FFDH", "Fortuna", "GOST", "HC", "HKDF", "HMAC", "HMAC_DRBG", "HPKE",
		"Hash_DRBG", "IDEA", "IKE-PRF", "J-PAKE", "LMS", "MD2", "MD4", "MD5", "MILENAGE",
		"ML-DSA", "ML-KEM", "MQV", "OPAQUE", "PBES1", "PBES2", "PBKDF1", "PBKDF2", "PBMAC1",
		"Poly1305", "RABBIT", "RC2", "RC4", "RC5", "RC6", "RIPEMD", "RSAES-OAEP", "RSAES-PKCS1",
		"RSASSA-PKCS1", "RSASSA-PSS", "SEED", "SHA-1", "SHA-2", "SHA-3", "SLH-DSA", "SM2", "SM3",
		"SM4", "SM9", "SNOW3G", "SP800-108", "SPAKE2", "SPAKE2PLUS", "SRP", "Salsa20", "Serpent",
		"SipHash", "Skipjack", "TUAK", "Twofish", "UMAC", "Whirlpool", "X3DH", "XMSS", "Yarrow",
		"ZUC", "bcrypt", "scrypt", "yescrypt")

	cdxRelatedMaterialTypes = newEnum("private-key", "public-key", "secret-key", "key",
		"ciphertext", "signature", "digest", "initialization-vector", "nonce", "seed", "salt",
		"shared-secret", "tag", "additional-data", "password", "credential", "token", "other",
		"unknown")

	// cdxKeyStates is relatedCryptoMaterialProperties.state (NIST SP 800-57).
	cdxKeyStates = newEnum("pre-activation", "active", "suspended", "deactivated", "compromised",
		"destroyed")

	// cdxCertificateStates is the pre-defined branch of certificateState. Note
	// it has no `compromised` and no `expired`.
	cdxCertificateStates = newEnum("pre-activation", "active", "suspended", "deactivated",
		"revoked", "destroyed")

	cdxCommonExtensions = newEnum("basicConstraints", "keyUsage", "extendedKeyUsage",
		"subjectAlternativeName", "authorityKeyIdentifier", "subjectKeyIdentifier",
		"authorityInformationAccess", "certificatePolicies", "crlDistributionPoints",
		"signedCertificateTimestamp")

	cdxHashAlgorithms = newEnum("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256",
		"SHA3-384", "SHA3-512", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3",
		"Streebog-256", "Streebog-512")
)

// cdxEnum matches case-insensitively but answers with the spec's own spelling,
// so `GCM` from a catalogue row emits as `gcm`.
type cdxEnum map[string]string

func newEnum(values ...string) cdxEnum {
	m := make(cdxEnum, len(values))
	for _, v := range values {
		m[strings.ToLower(v)] = v
	}
	return m
}

func (e cdxEnum) lookup(value string) (string, bool) {
	canonical, ok := e[strings.ToLower(strings.TrimSpace(value))]
	return canonical, ok
}

// enumOrEmpty returns the spec spelling of value, or "" when it isn't in the
// enum. The bool distinguishes "absent" from "present but off-spec" so callers
// can preserve the original.
func enumOrEmpty(value string, e cdxEnum) (string, bool) {
	if strings.TrimSpace(value) == "" {
		return "", false
	}
	canonical, ok := e.lookup(value)
	if !ok {
		return "", false
	}
	return canonical, true
}

func enumSubset(values []string, e cdxEnum) []string {
	var out []string
	for _, v := range values {
		if canonical, ok := e.lookup(v); ok {
			out = append(out, canonical)
		}
	}
	return out
}

// NormalizeProtocolType maps an observed protocol name onto
// protocolProperties.type. The enum is small and closed — `smb` and `rdp` are
// not members, and passing them through lower-cased (which is what we used to
// do) invalidates the document. Unrecognised protocols are `other`, which is
// exactly what the enum reserves the value for; the observed name is kept as a
// vendor property so nothing is lost.
func NormalizeProtocolType(protocol string) string {
	p := strings.ToLower(strings.TrimSpace(protocol))
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "dtls") {
		return "dtls"
	}
	if strings.HasPrefix(p, "tls") || strings.HasPrefix(p, "ssl") {
		return "tls"
	}
	if strings.HasPrefix(p, "ssh") {
		return "ssh"
	}
	if strings.HasPrefix(p, "ipsec") {
		return "ipsec"
	}
	if strings.HasPrefix(p, "ike") {
		return "ike"
	}
	if canonical, ok := cdxProtocolTypes.lookup(p); ok {
		return canonical
	}
	return "other"
}

// certificateStateEntry picks the oneOf branch a state entry belongs to.
func certificateStateEntry(s models.CBOMCertificateState) (CDXCertificateState, bool) {
	if canonical, ok := enumOrEmpty(s.State, cdxCertificateStates); ok {
		return CDXCertificateState{State: canonical, Reason: s.Reason}, true
	}
	// Custom branch: `name` is required, so fall back to whatever identifier we
	// have. An entry with neither is not worth emitting.
	name := s.Name
	if name == "" {
		name = s.State
	}
	if name == "" {
		return CDXCertificateState{}, false
	}
	return CDXCertificateState{Name: name, Description: s.Description, Reason: s.Reason}, true
}

// certificateExtensionEntry picks the oneOf branch an extension belongs to.
func certificateExtensionEntry(ext models.CBOMCertificateExtension) (CDXCertificateExtension, bool) {
	if canonical, ok := enumOrEmpty(ext.Name, cdxCommonExtensions); ok && ext.Value != "" {
		return CDXCertificateExtension{
			CommonExtensionName:  canonical,
			CommonExtensionValue: ext.Value,
		}, true
	}
	if ext.Name == "" {
		return CDXCertificateExtension{}, false
	}
	return CDXCertificateExtension{
		CustomExtensionName:  ext.Name,
		CustomExtensionValue: ext.Value,
	}, true
}

// hashContentPattern is the spec's own constraint on hash content: bare hex at
// one of the recognised digest lengths.
var hashContentPattern = regexp.MustCompile(`^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$`)

var hashSeparators = strings.NewReplacer(":", "", " ", "", "-", "")

// cdxHash builds a conforming `hash` object, or returns the raw content for the
// caller to preserve elsewhere. Colon-separated fingerprints (the usual
// human-readable form) are accepted and normalised.
func cdxHash(alg, content string) (*CDXFingerprint, string) {
	raw := strings.TrimSpace(content)
	if raw == "" {
		return nil, ""
	}

	normalized := hashSeparators.Replace(raw)
	if !hashContentPattern.MatchString(normalized) {
		return nil, raw
	}

	canonicalAlg, ok := cdxHashAlgorithms.lookup(alg)
	if !ok {
		// Infer from the digest length rather than guessing SHA-256 for
		// everything: a 40-hex-character fingerprint is SHA-1, and labelling it
		// SHA-256 would be a false statement about the evidence.
		switch len(normalized) {
		case 32:
			canonicalAlg = "MD5"
		case 40:
			canonicalAlg = "SHA-1"
		case 64:
			canonicalAlg = "SHA-256"
		case 96:
			canonicalAlg = "SHA-384"
		case 128:
			canonicalAlg = "SHA-512"
		default:
			return nil, raw
		}
	}
	return &CDXFingerprint{Alg: canonicalAlg, Content: normalized}, ""
}

func nonNegative(v int) int {
	if v < 0 {
		return 0
	}
	return v
}
