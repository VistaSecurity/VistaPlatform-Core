// Package handlers provides HTTP handlers for the report generator service.
// This file implements the CBOM (Cryptographic Bill of Materials) report handler.
package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/datasources"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/formatters"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// CBOMReportHandler assembles a CBOMData from the inventory service.
type CBOMReportHandler struct {
	inventoryDataSource *datasources.InventoryDataSource
}

// NewCBOMReportHandler creates a handler backed by the given inventory data source.
func NewCBOMReportHandler(inventoryDataSource *datasources.InventoryDataSource) *CBOMReportHandler {
	return &CBOMReportHandler{inventoryDataSource: inventoryDataSource}
}

type assetContext struct {
	AssetID     string
	AssetName   string
	AssetType   string
	Environment string
	IPAddress   string
	Hostname    string
	RiskLevel   string
	// Scope-predicate dimensions beyond environment/risk. They were previously
	// absent from this struct, which is why a Scope could name them and have
	// them silently ignored.
	AssetOwnership string
	AssetStatus    string
	BusinessUnit   string
	LocationRegion string
	Tags           map[string]string
	DiscoveredAt   time.Time
	LastVerified   time.Time
}

type cbomAlgorithmSource struct {
	Role    string
	Code    string
	KeySize int
	Curve   string
}

type componentAccumulator struct {
	components []models.CBOMComponent
	indexByID  map[string]int
}

// ParamAssetPredicate is the params-map key carrying the compiled Scope
// predicate. The value is an AssetPredicate.
const ParamAssetPredicate = "assetPredicate"

// GenerateCBOMData fetches the inventory datasets needed for CBOM generation and
// assembles them into a CBOMData ready for serialisation by the CycloneDX or SPDX generator.
//
// ctx bounds the inventory fetches. It used to be context.Background(), so the
// two-minute deadline the HTTP handler creates governed nothing: a wedged
// inventory-service held the request open until the client or a proxy gave up.
func (h *CBOMReportHandler) GenerateCBOMData(ctx context.Context, params map[string]interface{}, authToken, tenantID string) (*models.CBOMData, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	predicate := assetPredicateParam(params)
	includeAlgorithms := boolParam(params, "includeAlgorithms", true)
	includeCertificates := boolParam(params, "includeCertificates", true)
	includeProtocols := boolParam(params, "includeProtocols", true)
	includeKeys := boolParam(params, "includeKeys", true)
	includeLibraries := boolParam(params, "includeLibraries", true)

	type fetchResult struct {
		assets     []map[string]interface{}
		cryptos    []map[string]interface{}
		certs      []map[string]interface{}
		algorithms []map[string]interface{}
		errs       []string
	}

	result := fetchResult{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := h.inventoryDataSource.QueryAssets(ctx, authToken, tenantID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.errs = append(result.errs, fmt.Sprintf("assets: %v", err))
			return
		}
		result.assets = data
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := h.inventoryDataSource.QueryCryptoImplementations(ctx, authToken, tenantID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.errs = append(result.errs, fmt.Sprintf("crypto configurations: %v", err))
			return
		}
		result.cryptos = data
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := h.inventoryDataSource.QueryCertificates(ctx, authToken, tenantID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			result.errs = append(result.errs, fmt.Sprintf("certificates: %v", err))
			return
		}
		result.certs = data
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		data, err := h.inventoryDataSource.QueryAlgorithms(ctx, authToken, tenantID)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			// Algorithms are enrichment data — log but don't fail the CBOM.
			fmt.Printf("[CBOM] Warning: could not fetch algorithms table: %v\n", err)
			return
		}
		result.algorithms = data
	}()

	wg.Wait()

	if len(result.errs) > 0 {
		return nil, fmt.Errorf("failed to generate CBOM: %s", strings.Join(result.errs, "; "))
	}

	algorithmLookup := buildAlgorithmLookup(result.algorithms)

	components, tenantID := h.assembleComponents(
		result.assets,
		result.cryptos,
		result.certs,
		algorithmLookup,
		compilePredicate(predicate),
		includeAlgorithms,
		includeCertificates,
		includeProtocols,
		includeKeys,
		includeLibraries,
	)

	cbom := &models.CBOMData{
		SerialNumber: uuid.New().String(),
		BOMVersion:   1,
		GeneratedAt:  time.Now().UTC(),
		ReportTitle:  "Cryptographic Bill of Materials",
		TenantID:     tenantID,
		Parameters:   params,
		Summary:      buildCBOMSummary(components),
		Components:   components,
	}

	return cbom, nil
}

func (h *CBOMReportHandler) assembleComponents(
	assets, cryptos, certs []map[string]interface{},
	algorithmLookup map[string]map[string]interface{},
	predicate compiledPredicate,
	includeAlgorithms, includeCertificates, includeProtocols, includeKeys, includeLibraries bool,
) ([]models.CBOMComponent, string) {
	sortMapSliceByID(assets)
	sortMapSliceByID(cryptos)
	sortMapSliceByID(certs)

	assetsByID := indexByID(assets)
	certsByID := indexByID(certs)
	accumulator := newComponentAccumulator()
	tenantID := extractTenantID(cryptos, assets, certs)

	for _, implementation := range cryptos {
		implementationID := strVal(implementation["id"])
		if implementationID == "" {
			continue
		}

		assetID := strVal(implementation["asset_id"])
		context := buildAssetContext(assetsByID[assetID], implementation)
		if !predicate.matches(context) {
			continue
		}

		var dependencyIDs []string
		if includeKeys {
			keyComponents, keyDependencyIDs := buildKeyComponents(implementation, context)
			for _, component := range keyComponents {
				accumulator.Add(component)
			}
			dependencyIDs = append(dependencyIDs, keyDependencyIDs...)
		}
		if includeLibraries {
			libraryComponents, libraryDependencyIDs := buildLibraryComponents(implementation, context)
			for _, component := range libraryComponents {
				accumulator.Add(component)
			}
			dependencyIDs = append(dependencyIDs, libraryDependencyIDs...)
		}
		dependencyIDs = uniqueStrings(dependencyIDs)

		if includeProtocols {
			if component, ok := buildProtocolComponent(implementation, context, dependencyIDs); ok {
				accumulator.Add(component)
			}
		}

		certificateID := strVal(implementation["certificate_id"])
		certificate := certsByID[certificateID]
		if includeCertificates {
			if component, ok := buildCertificateComponent(implementation, assetsByID[assetID], certificate, context, dependencyIDs); ok {
				accumulator.Add(component)
			}
		}

		if includeAlgorithms {
			algorithmComponents := buildAlgorithmComponents(
				implementationID,
				implementation,
				assetsByID[assetID],
				certificate,
				context,
				dependencyIDs,
				algorithmLookup,
			)
			for _, component := range algorithmComponents {
				accumulator.Add(component)
			}
		}
	}

	if includeCertificates {
		for _, asset := range assets {
			context := buildAssetContext(asset, nil)
			if !predicate.matches(context) {
				continue
			}

			certificateID := strVal(asset["certificate_id"])
			if certificateID == "" || accumulator.Has(certificateComponentID(certificateID)) {
				continue
			}

			if component, ok := buildCertificateComponent(nil, asset, certsByID[certificateID], context, nil); ok {
				accumulator.Add(component)
			}
		}

		// Standalone certificates: uploaded or imported, not linked to any asset
		// or crypto configuration. They have no asset attributes at all, so there
		// is nothing to evaluate a predicate against.
		//
		// Under the "All" scope (empty predicate) they belong in the CBOM — a
		// tenant's uploaded CA certificates are part of its cryptographic estate.
		// Under any narrower scope they must not be: this loop used to run
		// unconditionally with an empty context and no filter, so a "Production"
		// artifact contained every environment's uploaded certificates and
		// overstated the boundary it claimed to attest to.
		//
		// The alternative — attributing them by guesswork — would be worse:
		// silently claiming an unattributed certificate is in production is the
		// failure being fixed, not a milder version of it. A tenant who wants
		// them scoped should link them to an asset.
		if predicate.isEmpty() {
			for _, cert := range certs {
				certificateID := strVal(cert["id"])
				if certificateID == "" || accumulator.Has(certificateComponentID(certificateID)) {
					continue
				}
				emptyContext := assetContext{}
				if component, ok := buildCertificateComponent(nil, nil, cert, emptyContext, nil); ok {
					accumulator.Add(component)
				}
			}
		}
	}

	resolveComponentRefs(accumulator.Components())

	return accumulator.Components(), tenantID
}

func newComponentAccumulator() *componentAccumulator {
	return &componentAccumulator{
		indexByID: make(map[string]int),
	}
}

func (a *componentAccumulator) Add(component models.CBOMComponent) {
	if component.ID == "" {
		return
	}

	if index, exists := a.indexByID[component.ID]; exists {
		mergeComponent(&a.components[index], component)
		return
	}

	a.indexByID[component.ID] = len(a.components)
	a.components = append(a.components, component)
}

func (a *componentAccumulator) Has(id string) bool {
	_, exists := a.indexByID[id]
	return exists
}

func (a *componentAccumulator) Components() []models.CBOMComponent {
	return a.components
}

func mergeComponent(dst *models.CBOMComponent, src models.CBOMComponent) {
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if dst.AssetID == "" {
		dst.AssetID = src.AssetID
	}
	if dst.AssetName == "" {
		dst.AssetName = src.AssetName
	}
	if dst.AssetType == "" {
		dst.AssetType = src.AssetType
	}
	if dst.Environment == "" {
		dst.Environment = src.Environment
	}
	if dst.IPAddress == "" {
		dst.IPAddress = src.IPAddress
	}
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	if dst.RiskLevel == "" {
		dst.RiskLevel = src.RiskLevel
	}
	if dst.DiscoveredAt.IsZero() {
		dst.DiscoveredAt = src.DiscoveredAt
	}
	if dst.LastVerified.IsZero() {
		dst.LastVerified = src.LastVerified
	}
	if dst.CertificateDetails == nil {
		dst.CertificateDetails = src.CertificateDetails
	}
	if dst.AlgorithmDetails == nil {
		dst.AlgorithmDetails = src.AlgorithmDetails
	}
	if dst.ProtocolDetails == nil {
		dst.ProtocolDetails = src.ProtocolDetails
	}
	if dst.KeyDetails == nil {
		dst.KeyDetails = src.KeyDetails
	}
	if dst.LibraryDetails == nil {
		dst.LibraryDetails = src.LibraryDetails
	}
	dst.DependsOn = uniqueStrings(append(dst.DependsOn, src.DependsOn...))
}

func buildAssetContext(asset, implementation map[string]interface{}) assetContext {
	context := assetContext{}
	context.AssetID = firstNonEmpty(
		strVal(fromMap(implementation, "asset_id")),
		strVal(fromMap(asset, "id")),
	)
	context.AssetName = firstNonEmpty(
		strVal(fromMap(implementation, "asset_hostname")),
		strVal(fromMap(asset, "hostname")),
		strVal(fromMap(asset, "name")),
		strVal(fromMap(implementation, "asset_ip_address")),
		strVal(fromMap(asset, "ip_address")),
		context.AssetID,
	)
	context.AssetType = firstNonEmpty(
		strVal(fromMap(implementation, "asset_type")),
		strVal(fromMap(asset, "asset_type")),
		strVal(fromMap(asset, "type")),
	)
	context.Environment = firstNonEmpty(
		strVal(fromMap(implementation, "asset_environment")),
		strVal(fromMap(asset, "environment")),
	)
	context.IPAddress = firstNonEmpty(
		strVal(fromMap(implementation, "asset_ip_address")),
		strVal(fromMap(asset, "ip_address")),
	)
	context.Hostname = firstNonEmpty(
		strVal(fromMap(implementation, "asset_hostname")),
		strVal(fromMap(asset, "hostname")),
	)
	context.RiskLevel = firstNonEmpty(
		strVal(fromMap(implementation, "risk_level")),
		strVal(fromMap(asset, "risk_level")),
	)
	// These four only ever come from the asset record — a crypto configuration
	// row carries no ownership, status, business unit or location of its own.
	context.AssetOwnership = strVal(fromMap(asset, "asset_ownership"))
	context.AssetStatus = strVal(fromMap(asset, "asset_status"))
	context.BusinessUnit = firstNonEmpty(
		strVal(fromMap(implementation, "asset_business_unit")),
		strVal(fromMap(asset, "business_unit")),
	)
	context.LocationRegion = tagLocationRegion(fromMap(asset, "tags"))
	context.Tags = flattenTags(fromMap(asset, "tags"))
	context.DiscoveredAt = firstNonZeroTime(
		parseTime(fromMap(implementation, "first_discovered_at")),
		parseTime(fromMap(asset, "created_at")),
		parseTime(fromMap(asset, "first_discovered_at")),
	)
	context.LastVerified = firstNonZeroTime(
		parseTime(fromMap(implementation, "last_verified_at")),
		parseTime(fromMap(asset, "updated_at")),
		parseTime(fromMap(asset, "last_seen_at")),
	)
	return context
}

// dedupeComponentRefs guarantees the one invariant the emitted document cannot
// survive without: a bom-ref names exactly one component.
//
// Every builder here derives its ref from the component id, which the
// accumulator keeps unique, so this should find nothing. It exists because the
// cost of being wrong about that is a document rejected by the validator an
// auditor runs — the schema's uniqueItems fires on both `components` and
// `dependencies`, and edges resolved by a shared ref are ambiguous even when
// the schema passes. A future builder that reintroduces a collision gets a
// suffixed ref rather than a broken artifact.
//
// Deterministic by construction: components arrive in a stable order (the
// inputs are sorted before assembly), so the same estate produces the same
// refs on every run. Renaming rather than dropping is deliberate — the
// duplicate is a real component, and deleting evidence to satisfy a validator
// would be the worse trade.
func dedupeComponentRefs(components []models.CBOMComponent) {
	used := make(map[string]bool, len(components))
	for i := range components {
		c := &components[i]
		if c.BOMRef == "" {
			continue
		}
		if !used[c.BOMRef] {
			used[c.BOMRef] = true
			continue
		}
		for n := 2; ; n++ {
			candidate := fmt.Sprintf("%s/dup-%d", c.BOMRef, n)
			if !used[candidate] {
				c.BOMRef = candidate
				used[candidate] = true
				break
			}
		}
	}
}

// resolveComponentRefs turns the cross-references our components carry into
// bom-refs that name components in the same document.
//
// Two things were dangling. `depends_on` was populated with internal component
// ids (`key:<uuid>`, `library:<uuid>`) while the components those ids describe
// publish bom-refs of the form `crypto/related-crypto-material/<uuid>` — so not
// one dependency edge in any artifact we ever produced resolved. And a key's
// `algorithm_ref` was whatever inventory stored, which is an algorithms-table
// UUID, not a reference to anything in the BOM.
//
// Anything that cannot be resolved is cleared here rather than emitted, because
// the formatter drops unresolvable edges anyway and leaving them on the model
// would just move the confusion.
func resolveComponentRefs(components []models.CBOMComponent) {
	// Refs are made unique before anything is indexed by them, so the maps below
	// (and every edge resolved through them) name one component each.
	dedupeComponentRefs(components)

	refByComponentID := make(map[string]string, len(components))
	knownRefs := make(map[string]bool, len(components))
	// Algorithm components are addressable by code as well, so a key that names
	// its algorithm by name or catalogue id can be linked to one.
	refByAlgorithmName := make(map[string]string, len(components))

	for i := range components {
		c := &components[i]
		if c.BOMRef == "" {
			continue
		}
		knownRefs[c.BOMRef] = true
		if c.ID != "" {
			refByComponentID[c.ID] = c.BOMRef
		}
		if c.Type == models.CBOMComponentTypeAlgorithm {
			if name := strings.ToUpper(strings.TrimSpace(c.Name)); name != "" {
				if _, exists := refByAlgorithmName[name]; !exists {
					refByAlgorithmName[name] = c.BOMRef
				}
			}
		}
	}

	resolve := func(value string) string {
		if value == "" {
			return ""
		}
		if knownRefs[value] {
			return value
		}
		if ref, ok := refByComponentID[value]; ok {
			return ref
		}
		if ref, ok := refByAlgorithmName[strings.ToUpper(strings.TrimSpace(value))]; ok {
			return ref
		}
		return ""
	}

	for i := range components {
		c := &components[i]

		resolved := make([]string, 0, len(c.DependsOn))
		for _, dep := range c.DependsOn {
			if ref := resolve(dep); ref != "" && ref != c.BOMRef {
				resolved = append(resolved, ref)
			}
		}
		c.DependsOn = uniqueStrings(resolved)

		provided := make([]string, 0, len(c.Provides))
		for _, p := range c.Provides {
			if ref := resolve(p); ref != "" && ref != c.BOMRef {
				provided = append(provided, ref)
			}
		}
		c.Provides = uniqueStrings(provided)

		if c.KeyDetails != nil {
			c.KeyDetails.AlgorithmRef = resolve(c.KeyDetails.AlgorithmRef)
			if c.KeyDetails.SecuredBy != nil {
				c.KeyDetails.SecuredBy.AlgorithmRef = resolve(c.KeyDetails.SecuredBy.AlgorithmRef)
			}
		}
		if c.CertificateDetails != nil {
			c.CertificateDetails.RelatedCryptoAssets = resolveRelatedAssets(c.CertificateDetails.RelatedCryptoAssets, resolve)
		}
		if c.KeyDetails != nil {
			c.KeyDetails.RelatedCryptoAssets = resolveRelatedAssets(c.KeyDetails.RelatedCryptoAssets, resolve)
		}
	}
}

func resolveRelatedAssets(refs []models.CBOMRelatedCryptoAssetRef, resolve func(string) string) []models.CBOMRelatedCryptoAssetRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]models.CBOMRelatedCryptoAssetRef, 0, len(refs))
	for _, r := range refs {
		if ref := resolve(r.Ref); ref != "" {
			out = append(out, models.CBOMRelatedCryptoAssetRef{Type: r.Type, Ref: ref})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// assetPredicateParam reads the compiled Scope predicate out of the params map.
// Absent means "no constraint" — the params map is also used by callers that
// pre-date scopes.
func assetPredicateParam(params map[string]interface{}) AssetPredicate {
	if raw, ok := params[ParamAssetPredicate]; ok {
		switch p := raw.(type) {
		case AssetPredicate:
			return p
		case *AssetPredicate:
			if p != nil {
				return *p
			}
		}
	}
	return AssetPredicate{}
}

func buildKeyComponents(implementation map[string]interface{}, context assetContext) ([]models.CBOMComponent, []string) {
	var components []models.CBOMComponent
	var dependencyIDs []string

	keys := mapSliceVal(implementation["keys"])
	sortMapSliceByID(keys)
	for _, key := range keys {
		keyID := strVal(key["id"])
		if keyID == "" {
			continue
		}

		componentID := keyComponentID(keyID)
		materialType := firstNonEmpty(strVal(key["material_type"]), "key")
		state := firstNonEmpty(strVal(key["state"]), strVal(key["status"]), "active")

		keyDetails := &models.CBOMKeyDetails{
			MaterialType:      materialType,
			ID:                keyID,
			State:             state,
			StateReason:       strVal(key["state_reason"]),
			KeyType:           strVal(key["key_type"]),
			KeyUsage:          stringSliceVal(key["key_usage"]),
			PublicFingerprint: strVal(key["public_fingerprint"]),
			JWKThumbprint:     strVal(key["jwk_thumbprint"]),
			SizeBits:          intVal(key["size_bits"]),
			Curve:             strVal(key["curve"]),
			Format:            strVal(key["format"]),
			AlgorithmRef:      strVal(key["algorithm_ref"]),
			Provenance:        strVal(key["provenance"]),
		}

		// Lifecycle timestamps as *time.Time
		if t := parseTime(key["created_at"]); !t.IsZero() {
			keyDetails.CreatedAt = &t
		}
		if t := parseTime(key["activation_date"]); !t.IsZero() {
			keyDetails.ActivationDate = &t
		}
		if t := parseTime(key["rotated_at"]); !t.IsZero() {
			keyDetails.RotatedAt = &t
		}
		if t := parseTime(key["deactivation_date"]); !t.IsZero() {
			keyDetails.DeactivationDate = &t
		}
		if t := parseTime(key["expires_at"]); !t.IsZero() {
			keyDetails.ExpiresAt = &t
		}
		if t := parseTime(key["destruction_date"]); !t.IsZero() {
			keyDetails.DestructionDate = &t
		}

		// SecuredBy mechanism
		if mechanism := strVal(key["secured_by"]); mechanism != "" {
			keyDetails.SecuredBy = &models.CBOMSecuredBy{
				Mechanism:    mechanism,
				AlgorithmRef: strVal(key["secured_by_algorithm_ref"]),
			}
		}

		component := models.CBOMComponent{
			ID:           componentID,
			BOMRef:       "crypto/related-crypto-material/" + keyID,
			Name:         buildKeyName(key),
			Type:         models.CBOMComponentTypeKey,
			AssetID:      context.AssetID,
			AssetName:    context.AssetName,
			AssetType:    context.AssetType,
			Environment:  context.Environment,
			IPAddress:    context.IPAddress,
			Hostname:     context.Hostname,
			RiskLevel:    context.RiskLevel,
			DiscoveredAt: firstNonZeroTime(parseTime(key["created_at"]), context.DiscoveredAt),
			LastVerified: context.LastVerified,
			KeyDetails:   keyDetails,
		}

		components = append(components, component)
		dependencyIDs = append(dependencyIDs, componentID)
	}

	return components, dependencyIDs
}

func buildLibraryComponents(implementation map[string]interface{}, context assetContext) ([]models.CBOMComponent, []string) {
	var components []models.CBOMComponent
	var dependencyIDs []string

	libraries := mapSliceVal(implementation["libraries"])
	sortMapSliceByID(libraries)
	for _, library := range libraries {
		libraryID := strVal(library["id"])
		if libraryID == "" {
			continue
		}

		vulnerabilities := mapSliceVal(library["known_vulnerabilities"])
		componentID := libraryComponentID(libraryID)

		// Build provides list from library_provided_algorithms
		providesAlgorithms := stringSliceVal(library["provides_algorithms"])

		component := models.CBOMComponent{
			ID:           componentID,
			BOMRef:       "crypto/library/" + libraryID,
			Name:         buildLibraryName(library),
			Type:         models.CBOMComponentTypeLibrary,
			AssetID:      context.AssetID,
			AssetName:    context.AssetName,
			AssetType:    context.AssetType,
			Environment:  context.Environment,
			IPAddress:    context.IPAddress,
			Hostname:     context.Hostname,
			RiskLevel:    context.RiskLevel,
			DiscoveredAt: firstNonZeroTime(parseTime(library["created_at"]), context.DiscoveredAt),
			LastVerified: firstNonZeroTime(parseTime(library["updated_at"]), context.LastVerified),
			Provides:     providesAlgorithms,
			LibraryDetails: &models.CBOMLibraryDetails{
				Name:                    strVal(library["name"]),
				Version:                 strVal(library["version"]),
				Vendor:                  strVal(library["vendor"]),
				CPE:                     strVal(library["cpe"]),
				PURL:                    strVal(library["purl"]),
				CertificationLevel:      stringSliceVal(library["certification_level"]),
				ProvidesAlgorithms:      providesAlgorithms,
				BuildMetadata:           mapVal(library["build_metadata"]),
				KnownVulnerabilities:    vulnerabilities,
				KnownVulnerabilityCount: len(vulnerabilities),
			},
		}

		components = append(components, component)
		dependencyIDs = append(dependencyIDs, componentID)
	}

	return components, dependencyIDs
}

func buildProtocolComponent(implementation map[string]interface{}, context assetContext, dependencyIDs []string) (models.CBOMComponent, bool) {
	implementationID := strVal(implementation["id"])
	protocol := strVal(implementation["protocol"])
	version := strVal(implementation["protocol_version"])
	if implementationID == "" || protocol == "" {
		return models.CBOMComponent{}, false
	}

	cipherSuites := stringSliceVal(fromMap(implementation, "cipher_suites"))
	if len(cipherSuites) == 0 {
		cipherSuites = filterEmpty([]string{strVal(implementation["cipher_suite"])})
	}

	// Map the observed protocol onto the CycloneDX protocolProperties.type
	// enumeration. This used to be a lower-case pass-through with a TLS/SSL
	// special case, which meant `smb` and `rdp` — both of which we discover —
	// went out as protocol types no version of the spec defines.
	protocolType := formatters.NormalizeProtocolType(protocol)

	component := models.CBOMComponent{
		ID:           protocolComponentID(implementationID),
		BOMRef:       "crypto/protocol/" + implementationID,
		Name:         strings.TrimSpace(fmt.Sprintf("%s %s", protocol, version)),
		Type:         models.CBOMComponentTypeProtocol,
		AssetID:      context.AssetID,
		AssetName:    context.AssetName,
		AssetType:    context.AssetType,
		Environment:  context.Environment,
		IPAddress:    context.IPAddress,
		Hostname:     context.Hostname,
		RiskLevel:    context.RiskLevel,
		DiscoveredAt: context.DiscoveredAt,
		LastVerified: context.LastVerified,
		DependsOn:    dependencyIDs,
		ProtocolDetails: &models.CBOMProtocolDetails{
			Type:                 protocolType,
			Version:              version,
			CipherSuiteNames:     cipherSuites,
			KeyExchangeAlgorithm: strVal(implementation["key_exchange_algorithm"]),
			PFSSupport:           boolVal(implementation["pfs_support"]),
			TLSCompression:       boolVal(implementation["tls_compression_enabled"]),
			ChainValid:           boolVal(implementation["certificate_chain_valid"]),
			DiscoveryMethod:      strVal(implementation["discovery_method"]),
			ConfidenceScore:      floatVal(implementation["confidence_score"]),
		},
	}

	if component.Name == "" {
		component.Name = protocol
	}
	return component, true
}

func buildCertificateComponent(
	implementation, asset, certificate map[string]interface{},
	context assetContext,
	dependencyIDs []string,
) (models.CBOMComponent, bool) {
	certificateID := firstNonEmpty(
		strVal(fromMap(implementation, "certificate_id")),
		strVal(fromMap(asset, "certificate_id")),
		strVal(fromMap(certificate, "id")),
	)
	if certificateID == "" {
		return models.CBOMComponent{}, false
	}

	details := buildCertDetails(certificate)
	if details == nil || (details.SubjectName == "" && details.CommonName == "") {
		details = buildCertDetailsFromAsset(asset)
	}
	if details == nil {
		return models.CBOMComponent{}, false
	}

	certCompID := certificateComponentID(certificateID)
	component := models.CBOMComponent{
		ID:                 certCompID,
		BOMRef:             "crypto/certificate/" + certificateID,
		Name:               firstNonEmpty(certCommonName(certificate), details.CommonName, details.SubjectName, certificateID),
		Type:               models.CBOMComponentTypeCertificate,
		AssetID:            context.AssetID,
		AssetName:          context.AssetName,
		AssetType:          context.AssetType,
		Environment:        context.Environment,
		IPAddress:          context.IPAddress,
		Hostname:           context.Hostname,
		RiskLevel:          context.RiskLevel,
		DiscoveredAt:       context.DiscoveredAt,
		LastVerified:       context.LastVerified,
		DependsOn:          dependencyIDs,
		CertificateDetails: details,
	}

	return component, true
}

func buildAlgorithmComponents(
	implementationID string,
	implementation, asset, certificate map[string]interface{},
	context assetContext,
	dependencyIDs []string,
	algorithmLookup map[string]map[string]interface{},
) []models.CBOMComponent {
	if implementationID == "" {
		return nil
	}

	var sources []cbomAlgorithmSource
	sources = appendIfCodePresent(sources, cbomAlgorithmSource{
		Role:    "key_exchange",
		Code:    strVal(implementation["key_exchange_algorithm"]),
		KeySize: intVal(implementation["key_size"]),
	})
	sources = appendIfCodePresent(sources, cbomAlgorithmSource{
		Role:    "signature",
		Code:    strVal(implementation["signature_algorithm"]),
		KeySize: intVal(implementation["key_size"]),
	})
	sources = appendIfCodePresent(sources, cbomAlgorithmSource{
		Role:    "symmetric",
		Code:    strVal(implementation["symmetric_encryption"]),
		KeySize: intVal(implementation["key_size"]),
	})
	sources = appendIfCodePresent(sources, cbomAlgorithmSource{
		Role: "hash",
		Code: strVal(implementation["hash_algorithm"]),
	})

	// When individual algorithm columns are unpopulated, fall back to parsing
	// the cipher_suite field. This handles implementations recorded by the sensor
	// where only the raw cipher suite name was captured (the common case).
	if len(sources) == 0 {
		cipherSuite := strVal(implementation["cipher_suite"])
		if cipherSuite == "" {
			// Try the first element of the cipher_suites array if present
			if cs := stringSliceVal(implementation["cipher_suites"]); len(cs) > 0 {
				cipherSuite = cs[0]
			}
		}
		keySize := intVal(implementation["key_size"])
		sources = append(sources, parseCipherSuiteAlgorithms(cipherSuite, keySize)...)
	}

	certKeySize := firstNonZeroInt(intVal(certificate["public_key_size"]), intVal(asset["certificate_key_size"]))
	certCurve := firstNonEmpty(strVal(certificate["curve"]), strVal(certificate["elliptic_curve"]))
	sources = appendIfCodePresent(sources, cbomAlgorithmSource{
		Role:    "certificate_key",
		Code:    firstNonEmpty(strVal(certificate["public_key_algorithm"]), strVal(certificate["key_algorithm"])),
		KeySize: certKeySize,
		Curve:   certCurve,
	})
	sources = appendIfCodePresent(sources, cbomAlgorithmSource{
		Role:    "certificate_signature",
		Code:    firstNonEmpty(strVal(certificate["signature_algorithm"]), strVal(asset["certificate_algorithm"])),
		KeySize: certKeySize,
		Curve:   certCurve,
	})

	var components []models.CBOMComponent
	seen := map[string]bool{}
	for _, source := range sources {
		componentID := algorithmComponentID(implementationID, source.Role, source.Code)
		if seen[componentID] {
			continue
		}
		seen[componentID] = true

		details := enrichAlgorithmDetails(source, algorithmLookup)
		component := models.CBOMComponent{
			ID:               componentID,
			BOMRef:           algorithmComponentRef(implementationID, source.Role, source.Code),
			Name:             source.Code,
			Type:             models.CBOMComponentTypeAlgorithm,
			AssetID:          context.AssetID,
			AssetName:        context.AssetName,
			AssetType:        context.AssetType,
			Environment:      context.Environment,
			IPAddress:        context.IPAddress,
			Hostname:         context.Hostname,
			RiskLevel:        context.RiskLevel,
			DiscoveredAt:     context.DiscoveredAt,
			LastVerified:     context.LastVerified,
			DependsOn:        dependencyIDs,
			AlgorithmDetails: details,
		}

		components = append(components, component)
	}

	return components
}

func buildCBOMSummary(components []models.CBOMComponent) models.CBOMSummary {
	summary := models.CBOMSummary{
		TotalComponents:     len(components),
		ByEnvironment:       map[string]int{},
		ByRiskLevel:         map[string]int{},
		ByAlgorithmCategory: map[string]int{},
		ByPrimitive:         map[string]int{},
		ByMaterialType:      map[string]int{},
	}

	for index := range components {
		component := &components[index]
		switch component.Type {
		case models.CBOMComponentTypeCertificate:
			summary.CertificateCount++
			if component.CertificateDetails != nil {
				if component.CertificateDetails.IsExpired() {
					summary.ExpiredCertificates++
				} else {
					days := component.CertificateDetails.DaysUntilExpiry()
					if days <= 30 {
						summary.ExpiringIn30Days++
					}
					if days <= 90 {
						summary.ExpiringIn90Days++
					}
				}
			}
		case models.CBOMComponentTypeAlgorithm:
			summary.AlgorithmCount++
			if component.AlgorithmDetails != nil {
				if component.AlgorithmDetails.IsWeak() {
					summary.WeakAlgorithms++
				}
				if component.AlgorithmDetails.IsDeprecated() {
					summary.DeprecatedAlgorithms++
				}
				if component.AlgorithmDetails.IsPQC {
					summary.PQCReadyCount++
				}
				if component.AlgorithmDetails.Category != "" {
					summary.ByAlgorithmCategory[component.AlgorithmDetails.Category]++
				}
				if component.AlgorithmDetails.Primitive != "" {
					summary.ByPrimitive[component.AlgorithmDetails.Primitive]++
				}
			}
		case models.CBOMComponentTypeProtocol:
			summary.ProtocolCount++
		case models.CBOMComponentTypeKey:
			summary.KeyCount++
			if component.KeyDetails != nil {
				if component.KeyDetails.MaterialType != "" {
					summary.ByMaterialType[component.KeyDetails.MaterialType]++
				}
				if component.KeyDetails.State == "compromised" {
					summary.CompromisedKeys++
				}
				if component.KeyDetails.ExpiresAt != nil && !component.KeyDetails.ExpiresAt.IsZero() && component.KeyDetails.ExpiresAt.Before(time.Now()) {
					summary.ExpiredKeys++
				}
			}
		case models.CBOMComponentTypeLibrary:
			summary.LibraryCount++
		}

		if component.Environment != "" {
			summary.ByEnvironment[component.Environment]++
		}
		if component.RiskLevel != "" {
			summary.ByRiskLevel[component.RiskLevel]++
		}
	}

	return summary
}

func buildCertDetails(cert map[string]interface{}) *models.CBOMCertificateDetails {
	if len(cert) == 0 {
		return nil
	}

	details := &models.CBOMCertificateDetails{
		SerialNumber:       strVal(cert["serial_number"]),
		SubjectName:        strVal(cert["subject_dn"]),
		IssuerName:         strVal(cert["issuer_dn"]),
		CommonName:         strVal(cert["common_name"]),
		FingerprintAlg:     "SHA-256",
		FingerprintContent: strVal(cert["fingerprint_sha256"]),
		FingerprintSHA1:    strVal(cert["fingerprint_sha1"]),
		KeyAlgorithm:       firstNonEmpty(strVal(cert["public_key_algorithm"]), strVal(cert["key_algorithm"])),
		SignatureAlgorithm: strVal(cert["signature_algorithm"]),
		SignatureAlgOID:    strVal(cert["signature_algorithm_oid"]),
		PublicKeyAlgOID:    strVal(cert["public_key_algorithm_oid"]),
		CertificateFormat:  firstNonEmpty(strVal(cert["certificate_format"]), "X.509"),
		DataSource:         strVal(cert["data_source"]),
		NotValidBefore:     parseTime(cert["not_before"]),
		NotValidAfter:      parseTime(cert["not_after"]),
	}

	// Build certificate lifecycle states from the certificate_state column
	certState := strVal(cert["certificate_state"])
	if certState == "" {
		certState = "active"
	}
	stateReason := strVal(cert["certificate_state_reason"])
	details.CertificateStates = []models.CBOMCertificateState{
		{State: certState, Reason: stateReason},
	}

	// Lifecycle timestamps
	if t := parseTime(cert["activation_date"]); !t.IsZero() {
		details.ActivationDate = &t
	}
	if t := parseTime(cert["deactivation_date"]); !t.IsZero() {
		details.DeactivationDate = &t
	}
	if t := parseTime(cert["revoked_at"]); !t.IsZero() {
		details.RevocationDate = &t
	}
	if t := parseTime(cert["destruction_date"]); !t.IsZero() {
		details.DestructionDate = &t
	}
	details.KeySize = firstNonZeroInt(intVal(cert["public_key_size"]), intVal(cert["key_size"]))
	details.IsSelfSigned = boolVal(cert["is_self_signed"])
	details.IsCA = boolVal(firstNonNil(cert["is_ca_certificate"], cert["is_ca"]))
	details.SANs = stringSliceVal(cert["subject_alternative_names"])
	return details
}

func buildCertDetailsFromAsset(asset map[string]interface{}) *models.CBOMCertificateDetails {
	if len(asset) == 0 {
		return nil
	}

	return &models.CBOMCertificateDetails{
		SubjectName:        strVal(asset["certificate_subject"]),
		IssuerName:         strVal(asset["certificate_issuer"]),
		CommonName:         strVal(asset["certificate_common_name"]),
		KeyAlgorithm:       strVal(asset["certificate_algorithm"]),
		SignatureAlgorithm: strVal(asset["certificate_algorithm"]),
		KeySize:            intVal(asset["certificate_key_size"]),
		NotValidAfter:      parseTime(asset["certificate_expires_at"]),
		CertificateFormat:  "X.509",
		CertificateStates:  []models.CBOMCertificateState{{State: "active"}},
	}
}

func certCommonName(cert map[string]interface{}) string {
	if cn := strVal(cert["common_name"]); cn != "" {
		return cn
	}
	if subject := strVal(cert["subject_dn"]); subject != "" {
		return subject
	}
	return ""
}

func inferAlgorithmCategory(role, code string) string {
	switch role {
	case "key_exchange":
		return "key_exchange"
	case "signature", "certificate_key", "certificate_signature":
		return "signature"
	case "symmetric":
		return "symmetric"
	case "hash":
		return "hash"
	}

	upper := strings.ToUpper(code)
	switch {
	case strings.Contains(upper, "RSA"):
		return "signature"
	case strings.Contains(upper, "ECDSA"), strings.Contains(upper, "ED25519"), strings.Contains(upper, "DILITHIUM"), strings.Contains(upper, "FALCON"):
		return "signature"
	case strings.Contains(upper, "SHA"), strings.Contains(upper, "MD5"):
		return "hash"
	case strings.Contains(upper, "AES"), strings.Contains(upper, "CHACHA"), strings.Contains(upper, "DES"):
		return "symmetric"
	case strings.Contains(upper, "DH"), strings.Contains(upper, "ECDH"), strings.Contains(upper, "KEM"), strings.Contains(upper, "KYBER"):
		return "key_exchange"
	default:
		return "other"
	}
}

func inferAlgorithmStrength(code string, keySize int) string {
	upper := strings.ToUpper(code)
	switch {
	case strings.Contains(upper, "MD5"), strings.Contains(upper, "SHA1"), strings.Contains(upper, "DES"), strings.Contains(upper, "RC4"), strings.Contains(upper, "3DES"):
		return "weak"
	case strings.Contains(upper, "RSA"):
		switch {
		case keySize > 0 && keySize < 2048:
			return "weak"
		case keySize >= 4096:
			return "strong"
		default:
			return "acceptable"
		}
	case strings.Contains(upper, "AES-256"), strings.Contains(upper, "AES256"), strings.Contains(upper, "SHA512"), strings.Contains(upper, "SHA384"), strings.Contains(upper, "SHA256"), strings.Contains(upper, "X25519"), strings.Contains(upper, "P-384"), strings.Contains(upper, "P-521"):
		return "strong"
	case strings.Contains(upper, "AES-128"), strings.Contains(upper, "AES128"), strings.Contains(upper, "CHACHA20"), strings.Contains(upper, "P-256"):
		return "acceptable"
	default:
		return "acceptable"
	}
}

func inferAlgorithmDeprecationStatus(code string, keySize int) string {
	upper := strings.ToUpper(code)
	switch {
	case strings.Contains(upper, "MD5"), strings.Contains(upper, "SHA1"), strings.Contains(upper, "RC4"), strings.Contains(upper, "DES"), strings.Contains(upper, "3DES"):
		return "deprecated"
	case strings.Contains(upper, "RSA") && keySize > 0 && keySize < 2048:
		return "deprecated"
	default:
		return "active"
	}
}

func inferAlgorithmRiskScore(code string, keySize int) int {
	if inferAlgorithmDeprecationStatus(code, keySize) == "deprecated" {
		return 85
	}
	if inferAlgorithmStrength(code, keySize) == "weak" {
		return 70
	}
	if isPQCAlgorithm(code) {
		return 10
	}
	return 25
}

func inferMigrationGuidance(code string, keySize int) string {
	if inferAlgorithmDeprecationStatus(code, keySize) != "deprecated" {
		return ""
	}

	upper := strings.ToUpper(code)
	switch {
	case strings.Contains(upper, "MD5"), strings.Contains(upper, "SHA1"):
		return "Replace with SHA-256 or stronger hashing."
	case strings.Contains(upper, "DES"), strings.Contains(upper, "RC4"), strings.Contains(upper, "3DES"):
		return "Replace with AES-GCM or ChaCha20-Poly1305."
	case strings.Contains(upper, "RSA"):
		return "Rotate to RSA-2048+ or an approved elliptic-curve algorithm."
	default:
		return "Replace with a supported modern algorithm."
	}
}

func isPQCAlgorithm(code string) bool {
	upper := strings.ToUpper(code)
	return strings.Contains(upper, "ML-KEM") ||
		strings.Contains(upper, "MLKEM") ||
		strings.Contains(upper, "KYBER") ||
		strings.Contains(upper, "ML-DSA") ||
		strings.Contains(upper, "MLDSA") ||
		strings.Contains(upper, "DILITHIUM") ||
		strings.Contains(upper, "FALCON") ||
		strings.Contains(upper, "FN-DSA") ||
		strings.Contains(upper, "FNDSA") ||
		strings.Contains(upper, "SPHINCS") ||
		strings.Contains(upper, "SLH-DSA") ||
		strings.Contains(upper, "SLHDSA") ||
		strings.Contains(upper, "HQC")
}

func inferPQCStatus(code string) string {
	if !isPQCAlgorithm(code) {
		return ""
	}
	return "emerging"
}

// buildAlgorithmLookup indexes canonical algorithm records by their code (upper-cased)
// for O(1) lookups during component assembly. The algorithms table is the authoritative
// source for strength, deprecation, PQC status, and migration guidance.
// It also adds lower-cased name, algorithm_name (when name is empty), and standard_name
// keys so the same lookup works for certificate fields and CBOM component codes.
func buildAlgorithmLookup(algorithms []map[string]interface{}) map[string]map[string]interface{} {
	lookup := make(map[string]map[string]interface{}, len(algorithms)*4)
	for _, alg := range algorithms {
		addLowerAlias := func(s string) {
			s = strings.TrimSpace(s)
			if s == "" {
				return
			}
			k := strings.ToLower(s)
			if _, exists := lookup[k]; !exists {
				lookup[k] = alg
			}
		}
		code := strings.ToUpper(strings.TrimSpace(strVal(alg["code"])))
		if code != "" {
			lookup[code] = alg
			addLowerAlias(code)
		}
		// Also index by name for fallback matching
		name := strings.ToUpper(strings.TrimSpace(strVal(alg["name"])))
		if name != "" && name != code {
			if _, exists := lookup[name]; !exists {
				lookup[name] = alg
			}
		}
		if n := strVal(alg["name"]); strings.TrimSpace(n) != "" {
			addLowerAlias(n)
		} else {
			addLowerAlias(strVal(alg["algorithm_name"]))
		}
		addLowerAlias(strVal(alg["standard_name"]))
	}
	return lookup
}

// lookupAlgorithm attempts to find a canonical algorithm record for the given code.
// It normalises the code and tries several variations to handle naming inconsistencies
// between observed cipher suite components and the algorithm catalog.
func lookupAlgorithm(code string, lookup map[string]map[string]interface{}) map[string]interface{} {
	if len(lookup) == 0 {
		return nil
	}
	upper := strings.ToUpper(strings.TrimSpace(code))
	if alg, ok := lookup[upper]; ok {
		return alg
	}
	// Try with hyphens removed (e.g., "AES-256-GCM" -> "AES256GCM")
	noHyphens := strings.ReplaceAll(upper, "-", "")
	if alg, ok := lookup[noHyphens]; ok {
		return alg
	}
	// Try with hyphens replaced by underscores
	underscored := strings.ReplaceAll(upper, "-", "_")
	if alg, ok := lookup[underscored]; ok {
		return alg
	}
	return nil
}

// enrichAlgorithmDetails builds CBOMAlgorithmDetails by first consulting the canonical
// algorithms table, falling back to heuristic inference for algorithms not in the catalog.
func enrichAlgorithmDetails(source cbomAlgorithmSource, algorithmLookup map[string]map[string]interface{}) *models.CBOMAlgorithmDetails {
	canonical := lookupAlgorithm(source.Code, algorithmLookup)

	category := inferAlgorithmCategory(source.Role, source.Code)

	details := &models.CBOMAlgorithmDetails{
		Code:    source.Code,
		Role:    source.Role,
		KeySize: source.KeySize,
		Curve:   source.Curve,
	}

	if canonical != nil {
		// Use authoritative data from the algorithms table
		details.Category = firstNonEmpty(strVal(canonical["category"]), category)
		details.Strength = firstNonEmpty(strVal(canonical["strength"]), inferAlgorithmStrength(source.Code, source.KeySize))
		details.DeprecationStatus = firstNonEmpty(strVal(canonical["deprecation_status"]), inferAlgorithmDeprecationStatus(source.Code, source.KeySize))
		details.IsPQC = boolVal(canonical["is_pqc"])
		details.PQCStandardizationStatus = firstNonEmpty(strVal(canonical["pqc_standardization_status"]), inferPQCStatus(source.Code))
		// Only the NIST PQC category column feeds this. `security_level` is
		// classical strength in bits and used to stand in for it, which put
		// values like 128 into a field the spec bounds at 0–6.
		details.NistQuantumSecurityLevel = intVal(canonical["nist_quantum_security_level"])
		details.RiskScore = firstNonZeroInt(intVal(canonical["risk_score"]), inferAlgorithmRiskScore(source.Code, source.KeySize))
		details.MigrationGuidance = firstNonEmpty(strVal(canonical["migration_guidance"]), inferMigrationGuidance(source.Code, source.KeySize))
		details.RecommendedAlternatives = stringSliceVal(canonical["recommended_alternatives"])

		// CycloneDX identity fields from enriched DB records
		details.AlgorithmFamily = strVal(canonical["algorithm_family"])
		details.Primitive = strVal(canonical["primitive"])
		details.Mode = firstNonEmpty(strVal(canonical["mode"]), details.Mode)
		details.OID = strVal(canonical["oid"])
		details.CryptoFunctions = stringSliceVal(canonical["crypto_functions"])
		details.ClassicalSecurityLevel = intVal(canonical["classical_security_level"])
		details.Padding = strVal(canonical["padding"])
		details.ParameterSetIdentifier = strVal(canonical["parameter_set_identifier"])
		if details.Curve == "" {
			details.Curve = strVal(canonical["curve"])
		}
	} else {
		// Fallback to heuristic inference for algorithms not in the catalog
		details.Category = category
		details.Strength = inferAlgorithmStrength(source.Code, source.KeySize)
		details.DeprecationStatus = inferAlgorithmDeprecationStatus(source.Code, source.KeySize)
		details.IsPQC = isPQCAlgorithm(source.Code)
		details.PQCStandardizationStatus = inferPQCStatus(source.Code)
		details.RiskScore = inferAlgorithmRiskScore(source.Code, source.KeySize)
		details.MigrationGuidance = inferMigrationGuidance(source.Code, source.KeySize)
	}

	return details
}

func buildKeyName(key map[string]interface{}) string {
	return firstNonEmpty(
		strVal(key["key_type"]),
		strVal(key["public_fingerprint"]),
		strVal(key["jwk_thumbprint"]),
		"Cryptographic Key",
	)
}

func buildLibraryName(library map[string]interface{}) string {
	return firstNonEmpty(
		strVal(library["name"]),
		strVal(library["cpe"]),
		"Crypto Library",
	)
}

func certificateComponentID(certificateID string) string {
	return "certificate:" + certificateID
}

func protocolComponentID(implementationID string) string {
	return "protocol:" + implementationID
}

func algorithmComponentID(implementationID, role, code string) string {
	return fmt.Sprintf("algorithm:%s:%s:%s", implementationID, role, sanitizeComponentIDPart(code))
}

// algorithmComponentRef is the published bom-ref for an algorithm component.
//
// It is derived from the same tuple as algorithmComponentID, and that is the
// whole point. A bom-ref identifies a component *within its document*: the
// CycloneDX schema puts uniqueItems on both `components` and `dependencies`,
// and dependency edges are resolved by ref. The ref used to be
// `crypto/algorithm/<code>` while components were de-duplicated on
// (implementation, role, code) — so an ordinary TLS configuration with an RSA
// key exchange and an RSA certificate key emitted two components, byte-equal
// after serialisation, under one ref. The artifact an auditor validates was
// rejected outright.
//
// Keying the ref off the component id makes the mapping injective: distinct
// components cannot collide, and the same component always publishes the same
// ref. It also disambiguates the milder case — identical crypto on two assets
// is two components, and a dependency edge now names exactly one of them.
func algorithmComponentRef(implementationID, role, code string) string {
	return fmt.Sprintf("crypto/algorithm/%s/%s/%s",
		sanitizeComponentIDPart(implementationID),
		sanitizeComponentIDPart(role),
		sanitizeComponentIDPart(code),
	)
}

func keyComponentID(keyID string) string {
	return "key:" + keyID
}

func libraryComponentID(libraryID string) string {
	return "library:" + libraryID
}

func sanitizeComponentIDPart(value string) string {
	if value == "" {
		return "unknown"
	}

	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", ",", "-", ".", "-", "(", "", ")", "", "[", "", "]", "", "{", "", "}", "", "+", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "unknown"
	}
	return value
}

// parseCipherSuiteAlgorithms extracts algorithm components from a TLS cipher
// suite name, in the algorithm-catalogue vocabulary.
//
// It is used as a fallback in the CBOM handler when the pre-parsed individual
// algorithm columns (key_exchange_algorithm, symmetric_encryption, ...) are
// absent — the common case for sensor-recorded implementations, where only the
// raw suite name was captured.
//
// This used to be a hand-transcribed copy of inventory-service's parser, and it
// drifted: it still emitted the mode-decorated names ("AES-256-GCM",
// "CHACHA20-POLY1305", "AES-128-CBC") that inventory's parser was fixed to stop
// emitting, and its key-exchange table differed. A CBOM artifact is audit-grade
// evidence, so naming a component differently from the inventory it was
// generated from — for the same observed suite — is the worst possible place
// for a fork. Both now call shared/cryptoparse.
func parseCipherSuiteAlgorithms(cipherSuite string, keySize int) []cbomAlgorithmSource {
	components, err := cryptoparse.ParseCipherSuite(cipherSuite)
	if err != nil || components == nil {
		return nil
	}

	var sources []cbomAlgorithmSource
	if components.KeyExchange != "" {
		sources = append(sources, cbomAlgorithmSource{
			Role: "key_exchange", Code: components.KeyExchange, KeySize: keySize,
		})
	}
	if components.Signature != "" {
		sources = append(sources, cbomAlgorithmSource{
			Role: "signature", Code: components.Signature,
		})
	}
	if components.Symmetric != "" {
		// The suite name pins the symmetric key length for the AES and ChaCha20
		// codes; keySize (the asset's key size) describes the key-exchange key
		// and must not be reused here.
		sources = append(sources, cbomAlgorithmSource{
			Role: "symmetric", Code: components.Symmetric,
			KeySize: cryptoparse.SymmetricKeyBits(components.Symmetric),
		})
	}
	if components.Hash != "" {
		sources = append(sources, cbomAlgorithmSource{
			Role: "hash", Code: components.Hash,
		})
	}
	return sources
}

func appendIfCodePresent(sources []cbomAlgorithmSource, source cbomAlgorithmSource) []cbomAlgorithmSource {
	if strings.TrimSpace(source.Code) == "" {
		return sources
	}
	return append(sources, source)
}

func sortMapSliceByID(items []map[string]interface{}) {
	sort.Slice(items, func(i, j int) bool {
		return strVal(items[i]["id"]) < strVal(items[j]["id"])
	})
}

func indexByID(items []map[string]interface{}) map[string]map[string]interface{} {
	index := make(map[string]map[string]interface{}, len(items))
	for _, item := range items {
		if id := strVal(item["id"]); id != "" {
			index[id] = item
		}
	}
	return index
}

func extractTenantID(itemGroups ...[]map[string]interface{}) string {
	for _, items := range itemGroups {
		for _, item := range items {
			if tenantID := strVal(item["tenant_id"]); tenantID != "" {
				return tenantID
			}
		}
	}
	return ""
}

func fromMap(m map[string]interface{}, key string) interface{} {
	if len(m) == 0 {
		return nil
	}
	return m[key]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNonNil(values ...interface{}) interface{} {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func firstNonZeroInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}

func strVal(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func intVal(v interface{}) int {
	switch value := v.(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	case float32:
		return int(value)
	default:
		return 0
	}
}

func floatVal(v interface{}) float64 {
	switch value := v.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	default:
		return 0
	}
}

func boolVal(v interface{}) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(value, "true")
	default:
		return false
	}
}

func parseTime(v interface{}) time.Time {
	if v == nil {
		return time.Time{}
	}

	switch value := v.(type) {
	case string:
		if value == "" {
			return time.Time{}
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05Z07:00", "2006-01-02"} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed
			}
		}
	case time.Time:
		return value
	}

	return time.Time{}
}

func boolParam(params map[string]interface{}, key string, defaultVal bool) bool {
	value, exists := params[key]
	if !exists || value == nil {
		return defaultVal
	}
	boolValue, ok := value.(bool)
	if !ok {
		return defaultVal
	}
	return boolValue
}

func stringSliceVal(v interface{}) []string {
	switch value := v.(type) {
	case []string:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if strings.TrimSpace(item) != "" {
				out = append(out, item)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if stringValue := strVal(item); strings.TrimSpace(stringValue) != "" {
				out = append(out, stringValue)
			}
		}
		return out
	default:
		return nil
	}
}

func mapSliceVal(v interface{}) []map[string]interface{} {
	switch value := v.(type) {
	case []map[string]interface{}:
		return value
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(value))
		for _, item := range value {
			if mapped, ok := item.(map[string]interface{}); ok {
				out = append(out, mapped)
			}
		}
		return out
	default:
		return nil
	}
}

func mapVal(v interface{}) map[string]interface{} {
	if mapped, ok := v.(map[string]interface{}); ok {
		return mapped
	}
	return nil
}

func filterEmpty(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}
