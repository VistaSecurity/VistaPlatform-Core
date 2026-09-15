package xbom

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/formatters"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
)

// Property namespace for everything this platform states about a component
// that CycloneDX has no field for. The `vista:` prefix follows the CycloneDX
// convention of namespacing custom property names so a consumer merging BOMs
// from several tools can tell whose statement is whose.
const (
	propPrefix     = "vista:"
	propAssetUID   = propPrefix + "asset:uid"
	propAssetClass = propPrefix + "asset:class"
	propAssetPath  = propPrefix + "asset:class_path"
	propAssetStat  = propPrefix + "asset:status"
	propAssetOwnsp = propPrefix + "asset:ownership"
	propAssetEnv   = propPrefix + "asset:environment"
	propAssetBU    = propPrefix + "asset:business_unit"
	propAssetOwner = propPrefix + "asset:owner_email"
	propAssetSite  = propPrefix + "asset:site"
	propAssetRegn  = propPrefix + "asset:region"
	propAssetZone  = propPrefix + "asset:zone"
	propAssetRisk  = propPrefix + "asset:risk_score"
	propAssetFirst = propPrefix + "asset:first_seen_at"
	propAssetLast  = propPrefix + "asset:last_seen_at"
	propIDPrefix   = propPrefix + "identifier:"
	propFactPrefix = propPrefix + "fact:"
	propTagPrefix  = propPrefix + "tag:"
	propEdgeType   = propPrefix + "relationship:"
	propEndpAsset  = propPrefix + "endpoint:asset_uid"
	propEndpTrans  = propPrefix + "endpoint:transport"
	propEndpProto  = propPrefix + "endpoint:protocol"
	propEndpPort   = propPrefix + "endpoint:port"
	propEndpStatus = propPrefix + "endpoint:status"
	propSWPath     = propPrefix + "software:install_path"
	propVulnFind   = propPrefix + "finding:id"
	propVulnKind   = propPrefix + "finding:kind"
	propVulnSev    = propPrefix + "finding:severity"
	propVulnScore  = propPrefix + "finding:score"
	propVulnFirst  = propPrefix + "finding:first_seen"
	propVulnLast   = propPrefix + "finding:last_seen"
)

// bom-ref prefixes. A ref is derived from a DATABASE ID, never from a position
// or a name, so the same asset carries the same ref in every artifact ever
// generated. That is what makes a comparison across two artifacts align rows
// rather than report the whole inventory as removed-then-added.
const (
	refAsset    = "asset/"
	refEndpoint = "endpoint/"
	refSoftware = "software/"
	refVuln     = "vuln/"
)

// DocumentInput is the non-inventory half of an assembly: the identity and
// timestamp stamped on the document.
//
// Both are parameters rather than being taken from uuid.New()/time.Now() inside
// the assembler so a test can pin them. They are the only two non-deterministic
// inputs to the canonical bytes, and a golden test that could not fix them
// could not assert byte-stability at all.
type DocumentInput struct {
	SerialNumber uuid.UUID
	GeneratedAt  time.Time
	ScopeName    string
	ToolVersion  string
}

// BuildDocument assembles the CycloneDX document for one kind.
//
// Kinds share the walk and differ in what they emit:
//
//	sbom      — one `library` component per distinct software PRODUCT, with the
//	            assets it was found on as evidence.occurrences. No dependency
//	            graph: an install record says a product is present on a host,
//	            not that anything depends on it, and an invented edge in a
//	            signed document is worse than an absent one.
//	hbom      — one `device` component per hardware-class asset, carrying its
//	            hw.* facts and its identifiers.
//	inventory — every asset as a component typed by its class, endpoints as
//	            services, asset_relationships as the dependency graph, facts and
//	            identifiers as properties, and vulnerability-producer findings
//	            as `vulnerabilities`.
func BuildDocument(kind string, snap *Snapshot, in DocumentInput) (*formatters.CDXDocument, error) {
	if snap == nil {
		return nil, fmt.Errorf("xbom: snapshot cannot be nil")
	}
	doc := &formatters.CDXDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  formatters.SpecVersion,
		Version:      1,
		SerialNumber: "urn:uuid:" + in.SerialNumber.String(),
		Metadata: &formatters.CDXMetadata{
			Timestamp: utcRFC3339(in.GeneratedAt),
			Tools: &formatters.CDXTools{
				Components: []formatters.CDXToolComponent{{
					Type:    "application",
					Name:    "Vista Platform xBOM Generator",
					Version: firstNonEmpty(in.ToolVersion, "1.0.0"),
					Group:   "io.vistasecurity",
				}},
			},
			Component: &formatters.CDXComponent{
				Type:        "application",
				BOMRef:      "xbom-" + in.SerialNumber.String(),
				Name:        documentTitle(kind, in.ScopeName),
				Version:     "1.0",
				Description: documentDescription(kind),
			},
			Lifecycles: []formatters.CDXLifecycle{{Phase: "operations"}},
		},
		// Never nil: `components` has no omitempty, and a nil slice marshals as
		// `null`, which the 1.7 schema rejects for an array.
		Components: []formatters.CDXComponent{},
	}

	switch kind {
	case "sbom":
		doc.Components = softwareComponents(snap)
	case "hbom":
		doc.Components = hardwareComponents(snap)
	case "inventory":
		components, services := inventoryEntries(snap)
		doc.Components = components
		doc.Services = services
		doc.Dependencies = dependencyGraph(snap, components, services)
		doc.Vulnerabilities = vulnerabilities(snap)
	default:
		return nil, fmt.Errorf("xbom: no assembler for kind %q", kind)
	}
	return doc, nil
}

// EntryCount is how many top-level entries the document lists — components plus
// services.
//
// Services are counted because for an inventory snapshot they are not a
// sub-detail: a listening endpoint is one of the things the artifact inventories,
// and a count that ignored them would under-report exactly the rows an ops user
// generated the artifact to see.
func EntryCount(doc *formatters.CDXDocument) int {
	if doc == nil {
		return 0
	}
	return len(doc.Components) + len(doc.Services)
}

// ---------------------------------------------------------------------------
// sbom
// ---------------------------------------------------------------------------

// softwareComponents collapses installs to one component per PRODUCT and lists
// the assets each was found on as evidence.occurrences.
//
// Per product, not per install: a fleet of 500 hosts running the same OpenSSL
// is one thing to patch, and 500 identical components would make the SBOM
// unreadable and its diff meaningless. The occurrence list is what preserves
// "where", which is the information per-install rows carried.
func softwareComponents(snap *Snapshot) []formatters.CDXComponent {
	assetByID := indexAssets(snap.Assets)

	type product struct {
		install     SoftwareInstall
		occurrences []CDXOccurrenceSeed
	}
	byProduct := map[uuid.UUID]*product{}
	order := make([]uuid.UUID, 0, len(snap.Software))

	for _, si := range snap.Software {
		p, seen := byProduct[si.ProductID]
		if !seen {
			p = &product{install: si}
			byProduct[si.ProductID] = p
			order = append(order, si.ProductID)
		}
		p.occurrences = append(p.occurrences, CDXOccurrenceSeed{
			AssetID:     si.AssetID,
			AssetName:   assetDisplay(assetByID, si.AssetID),
			InstallPath: si.InstallPath,
		})
	}

	// The source query already orders by product id, so `order` is sorted; sort
	// again rather than depend on that from here. A second sort is free next to
	// the SQL and it means the determinism of these bytes does not rest on a
	// clause in another file.
	sort.Slice(order, func(i, j int) bool { return order[i].String() < order[j].String() })

	out := make([]formatters.CDXComponent, 0, len(order))
	for _, productID := range order {
		p := byProduct[productID]
		si := p.install
		comp := formatters.CDXComponent{
			// `library` is the CycloneDX type the SBOM ecosystem uses for an
			// installed package — it is what syft, trivy and the rest emit for
			// OS and language packages alike. `application` would be a claim
			// about what the software IS that an install record cannot support.
			Type:    "library",
			BOMRef:  refSoftware + productID.String(),
			Name:    si.Name,
			Version: si.Version,
			Group:   si.Vendor,
			Purl:    si.PURL,
			CPE:     si.CPE,
		}
		if si.LicenseID != "" {
			comp.Licenses = []formatters.CDXLicenseEntry{{
				License: formatters.CDXLicenseName{Name: si.LicenseID},
			}}
		}
		comp.Evidence = occurrenceEvidence(p.occurrences)
		out = append(out, comp)
	}
	return out
}

// CDXOccurrenceSeed is one (asset, path) an installed product was found at.
type CDXOccurrenceSeed struct {
	AssetID     uuid.UUID
	AssetName   string
	InstallPath string
}

func occurrenceEvidence(seeds []CDXOccurrenceSeed) *formatters.CDXEvidence {
	if len(seeds) == 0 {
		return nil
	}
	sorted := append([]CDXOccurrenceSeed(nil), seeds...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].AssetID != sorted[j].AssetID {
			return sorted[i].AssetID.String() < sorted[j].AssetID.String()
		}
		return sorted[i].InstallPath < sorted[j].InstallPath
	})

	occurrences := make([]formatters.CDXOccurrence, 0, len(sorted))
	for _, s := range sorted {
		// `location` is required by the schema and must say something true. An
		// install path when we have one; otherwise the asset's bom-ref, which
		// is where the component was found in the only sense we measured.
		location := s.InstallPath
		if location == "" {
			location = refAsset + s.AssetID.String()
		}
		occurrences = append(occurrences, formatters.CDXOccurrence{
			Location:          location,
			AdditionalContext: s.AssetName,
		})
	}
	return &formatters.CDXEvidence{Occurrences: occurrences}
}

// ---------------------------------------------------------------------------
// hbom
// ---------------------------------------------------------------------------

// hardwareComponents emits one `device` component per hardware-class asset.
//
// Membership is decided by the class registry's own CycloneDXType — the same
// field the inventory kind types every component from — so "what counts as
// hardware" has one definition and the HBOM cannot drift from the taxonomy.
func hardwareComponents(snap *Snapshot) []formatters.CDXComponent {
	identifiersByAsset := groupIdentifiers(snap.Identifiers)
	factsByAsset := groupFacts(snap.Facts)

	out := make([]formatters.CDXComponent, 0, len(snap.Assets))
	for _, a := range snap.Assets {
		// RESOLVED and `device` — not "resolved to device, or unresolved". An
		// asset whose class the registry cannot answer for is not PROVABLY
		// hardware, and an HBOM is the one document whose entire content is the
		// claim "these are your hardware assets". Under-listing is a gap a
		// reader can see; over-listing is a false statement they cannot.
		if t, ok := resolveCycloneDXType(a); !ok || t != "device" {
			continue
		}
		comp := formatters.CDXComponent{
			Type:   "device",
			BOMRef: refAsset + a.ID.String(),
			Name:   a.Name(),
			Group:  factValue(factsByAsset[a.ID], "hw.vendor"),
			// `version` on a device component is its firmware: on an appliance
			// or an OT device the firmware IS the software, and it is what a
			// vendor advisory names.
			Version: factValue(factsByAsset[a.ID], "hw.firmware_version"),
		}
		props := baseAssetProperties(a)
		// hw.* only. An HBOM that carried os.* and sw.* facts would be an
		// inventory snapshot under a narrower name.
		props = append(props, factProperties(factsByAsset[a.ID], "hw.")...)
		props = append(props, identifierProperties(identifiersByAsset[a.ID])...)
		comp.Properties = sortProperties(props)
		out = append(out, comp)
	}
	return out
}

// ---------------------------------------------------------------------------
// inventory
// ---------------------------------------------------------------------------

// inventoryEntries emits every in-scope asset, split between `components` and
// `services` by its class's CycloneDX type, plus one service per endpoint.
//
// The split is the class registry's: `CycloneDXTypes` documents that "service"
// is not a component type and a class carrying it goes into the services array.
// So a business service is a CycloneDX service and a server is a component,
// and the taxonomy decides rather than this file.
func inventoryEntries(snap *Snapshot) ([]formatters.CDXComponent, []formatters.CDXService) {
	identifiersByAsset := groupIdentifiers(snap.Identifiers)
	factsByAsset := groupFacts(snap.Facts)
	softwareByAsset := groupSoftware(snap.Software)

	components := make([]formatters.CDXComponent, 0, len(snap.Assets))
	services := make([]formatters.CDXService, 0, len(snap.Endpoints))

	for _, a := range snap.Assets {
		cdxType := cycloneDXTypeFor(a)
		props := baseAssetProperties(a)
		props = append(props, factProperties(factsByAsset[a.ID], "")...)
		props = append(props, identifierProperties(identifiersByAsset[a.ID])...)
		props = append(props, tagProperties(a.Tags)...)
		props = sortProperties(props)

		if cdxType == "service" {
			services = append(services, formatters.CDXService{
				BOMRef:      refAsset + a.ID.String(),
				Name:        a.Name(),
				Description: classLabel(a.ClassKey),
				Properties:  props,
			})
			continue
		}

		comp := formatters.CDXComponent{
			Type:   cdxType,
			BOMRef: refAsset + a.ID.String(),
			Name:   a.Name(),
			// An asset has no version of its own; the OS version is the closest
			// honest answer and only for classes whose CycloneDX type says the
			// component IS the operating system. Everywhere else it stays
			// absent rather than borrowing a fact that describes something the
			// component contains.
			Description: classLabel(a.ClassKey),
			Properties:  props,
		}
		if cdxType == "operating-system" {
			comp.Version = factValue(factsByAsset[a.ID], "os.version")
		}
		// The software an asset carries is named here as a purl list in
		// properties rather than as nested components: a full SBOM is its own
		// kind, and inlining every package would make an inventory snapshot of
		// 500 hosts unopenable.
		comp.Properties = sortProperties(append(comp.Properties, softwareProperties(softwareByAsset[a.ID])...))
		components = append(components, comp)
	}

	for _, e := range snap.Endpoints {
		services = append(services, endpointService(e))
	}

	sort.SliceStable(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })
	sort.SliceStable(services, func(i, j int) bool { return services[i].BOMRef < services[j].BOMRef })
	return components, services
}

// endpointService renders one reachable face as a CycloneDX service.
func endpointService(e Endpoint) formatters.CDXService {
	name := e.ServiceName
	if name == "" {
		// No identified service. The name is required, so say what we DO know —
		// the face itself — rather than guessing a service from the port. A
		// port number is a convention, not a measurement, and "443 means HTTPS"
		// is exactly the guess the discovery pipeline refuses to make.
		name = e.Host()
		if e.HasPort {
			name = fmt.Sprintf("%s:%d", name, e.Port)
		}
	}
	svc := formatters.CDXService{
		BOMRef:  refEndpoint + e.ID.String(),
		Name:    name,
		Version: e.ServiceVersion,
	}
	if endpoint := endpointIRI(e); endpoint != "" {
		svc.Endpoints = []string{endpoint}
	}
	props := []formatters.CDXProperty{{Name: propEndpAsset, Value: e.AssetID.String()}}
	props = appendIfSet(props, propEndpTrans, e.Transport)
	props = appendIfSet(props, propEndpProto, e.Protocol)
	if e.HasPort {
		props = append(props, formatters.CDXProperty{Name: propEndpPort, Value: strconv.Itoa(e.Port)})
	}
	props = appendIfSet(props, propEndpStatus, e.Status)
	svc.Properties = sortProperties(props)
	return svc
}

// endpointIRI renders an endpoint as the IRI reference CycloneDX asks for.
//
// `service.endpoints` declares `format: iri-reference`, and a bare `10.0.0.5:443`
// is not one — it parses as a scheme named "10.0.0.5". The transport is used as
// the scheme, which is true (it is the transport) and keeps the string parseable.
// An endpoint with no port has nothing to address, so it yields nothing rather
// than a scheme pointing at a host on no port.
func endpointIRI(e Endpoint) string {
	host := e.Host()
	if host == "" || !e.HasPort {
		return ""
	}
	scheme := e.Transport
	if scheme == "" || scheme == "none" {
		scheme = "tcp"
	}
	// An IPv6 literal has to be bracketed or the colons read as part of the
	// authority's port.
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, e.Port)
}

// dependencyGraph turns asset_relationships into the CycloneDX dependency
// graph, dropping any edge whose ends are not both entries in this document.
//
// The drop is the same rule the CBOM formatter applies to its own refs: a
// `dependsOn` naming something the reader cannot resolve asserts a relationship
// to a component that is not there, which is worse than asserting none.
func dependencyGraph(snap *Snapshot, components []formatters.CDXComponent, services []formatters.CDXService) []formatters.CDXDependency {
	known := make(map[string]struct{}, len(components)+len(services))
	for _, c := range components {
		known[c.BOMRef] = struct{}{}
	}
	for _, s := range services {
		known[s.BOMRef] = struct{}{}
	}

	dependsOn := map[string]map[string]struct{}{}
	for _, r := range snap.Relationships {
		from := refAsset + r.FromAssetID.String()
		to := refAsset + r.ToAssetID.String()
		if _, ok := known[from]; !ok {
			continue
		}
		if _, ok := known[to]; !ok {
			continue
		}
		if dependsOn[from] == nil {
			dependsOn[from] = map[string]struct{}{}
		}
		dependsOn[from][to] = struct{}{}
	}

	refs := make([]string, 0, len(dependsOn))
	for ref := range dependsOn {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	out := make([]formatters.CDXDependency, 0, len(refs))
	for _, ref := range refs {
		targets := make([]string, 0, len(dependsOn[ref]))
		for t := range dependsOn[ref] {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		out = append(out, formatters.CDXDependency{Ref: ref, DependsOn: targets})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// vulnerabilities renders the vulnerability producer's findings.
//
// Every other producer stays out. The `vulnerabilities` array has a meaning to
// every tool that reads CycloneDX — these are CVEs — and a compliance control
// failure or a missing asset owner placed there would be read as one.
func vulnerabilities(snap *Snapshot) []formatters.CDXVulnerability {
	if len(snap.Vulns) == 0 {
		return nil
	}
	out := make([]formatters.CDXVulnerability, 0, len(snap.Vulns))
	for _, v := range snap.Vulns {
		entry := formatters.CDXVulnerability{
			BOMRef:      refVuln + v.ID.String(),
			ID:          v.CVEID,
			Description: firstNonEmpty(v.Description, v.Summary),
			Detail:      v.Summary,
			Published:   timePtrRFC3339(v.PublishedAt),
			Updated:     timePtrRFC3339(v.ModifiedAt),
		}
		if v.CVEID != "" {
			// The source is named only when there is an id for it to be the
			// source of. NVD is where the mirror job takes CVE records from
			// (BUILD_PLAN 3.4); a finding with no CVE has no such provenance
			// and gets none invented.
			entry.Source = &formatters.CDXVulnerabilitySource{
				Name: "NVD",
				URL:  "https://nvd.nist.gov/vuln/detail/" + v.CVEID,
			}
		}
		if rating := cvssRating(v); rating != nil {
			entry.Ratings = []formatters.CDXVulnerabilityRating{*rating}
		}
		// The subject. An `asset` subject affects that asset's component
		// directly. A `software_install` subject affects the install's asset —
		// the finding's own id is the install's, which is not a bom-ref in this
		// document, so the honest target is the asset it sits on.
		if ref := affectedRef(v); ref != "" {
			entry.Affects = []formatters.CDXVulnerabilityAffect{{Ref: ref}}
		}
		props := []formatters.CDXProperty{
			{Name: propVulnFind, Value: v.ID.String()},
			{Name: propVulnKind, Value: v.Kind},
			{Name: propVulnSev, Value: v.Severity},
			{Name: propVulnScore, Value: strconv.Itoa(v.Score)},
		}
		props = appendIfSet(props, propVulnFirst, utcRFC3339(v.FirstSeen))
		props = appendIfSet(props, propVulnLast, utcRFC3339(v.LastSeen))
		entry.Properties = sortProperties(props)
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].BOMRef < out[j].BOMRef })
	return out
}

// affectedRef names what a vulnerability finding is about, as a bom-ref.
func affectedRef(v VulnerabilityFinding) string {
	switch v.SubjectType {
	case "asset":
		return refAsset + v.SubjectID.String()
	default:
		// A software_install subject: the install id is not a ref in this
		// document. Returning nothing is correct — `affects` is optional, and
		// an entry pointing at a ref the reader cannot resolve is the dangling
		// edge this codebase filters everywhere else.
		return ""
	}
}

// cvssRating renders the catalogue's CVSS entry, or nothing.
//
// Nothing, not zero. A CVE the mirror has not yet seen has no score, and a 0.0
// in a ratings array reads as "scored, and harmless" — the same three-valued
// collapse that produced a year of wrong answers elsewhere in this codebase.
func cvssRating(v VulnerabilityFinding) *formatters.CDXVulnerabilityRating {
	if v.CVSSScore == nil {
		return nil
	}
	rating := formatters.CDXVulnerabilityRating{
		Source:   &formatters.CDXVulnerabilitySource{Name: "NVD"},
		Score:    v.CVSSScore,
		Severity: cvssSeverityLabel(v.CVSSeverity),
		Vector:   v.CVSSVector,
		Method:   cvssMethod(v.CVSSVersion),
	}
	return &rating
}

// cvssSeverityLabel maps the catalogue's severity onto the CycloneDX `severity`
// enumeration (critical/high/medium/low/info/none/unknown).
//
// Anything outside the enumeration becomes `unknown`, never passes through:
// `severity` is a closed enum in the schema, so one unrecognised value from a
// future feed would fail validation for the WHOLE document — every asset, every
// vulnerability — over one row. `unknown` is also the truthful answer, which is
// why it exists in the enumeration.
func cvssSeverityLabel(s string) string {
	switch strings.ToLower(s) {
	case "":
		return ""
	case "critical", "high", "medium", "low", "info", "none":
		return strings.ToLower(s)
	default:
		return "unknown"
	}
}

// cvssMethod maps a CVSS version string onto the CycloneDX `scoreMethod`
// enumeration. An unrecognised version yields nothing: `method` is optional and
// a value outside the enumeration fails schema validation for the whole
// document.
func cvssMethod(version string) string {
	switch {
	case strings.HasPrefix(version, "4"):
		return "CVSSv4"
	case strings.HasPrefix(version, "3.1"):
		return "CVSSv31"
	case strings.HasPrefix(version, "3"):
		return "CVSSv3"
	case strings.HasPrefix(version, "2"):
		return "CVSSv2"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// resolveCycloneDXType resolves an asset's class to its CycloneDX component
// type, and reports whether the class registry actually answered.
//
// Two layers, in this order:
//
//  1. The GENERATED registry (standards/asset-classes.yaml, via assetclass).
//     Authoritative for the fixed top of the taxonomy, and it cannot be edited
//     per tenant.
//  2. The asset's own `asset_classes.cyclonedx_type`, carried on the row. A
//     tenant may add leaf subclasses at RUNTIME (ADR-0002 D2) — a NetBox device
//     role becomes one — and `assetclass.Get` deliberately does not know them,
//     so layer 1 misses every one.
//
// The second result is the load-bearing half, and it used to be absent: an
// unresolved class fell through to `device` unconditionally, so a tenant
// subclass of `business_service` or `application` was emitted as a CycloneDX
// `device` AND admitted to the HBOM as hardware — a claim about a customer's
// estate, in a document they hand an auditor, that nothing in the taxonomy
// supports. The comment here asserted an ancestry walk through class_path that
// the code never performed, which is why it went unnoticed.
//
// class_path is NOT walked, deliberately. `classPathForKey` stores a tenant
// subclass's path as the bare KEY when the class row cannot be read, so the
// ancestry such a walk would need is exactly what is missing in the only case
// it would help. Reading the registry's own answer is both simpler and right.
func resolveCycloneDXType(a Asset) (string, bool) {
	if c, ok := assetclass.Get(a.ClassKey); ok && c.CycloneDXType != "" {
		return c.CycloneDXType, true
	}
	if a.CycloneDXType != "" {
		return a.CycloneDXType, true
	}
	return "", false
}

// cycloneDXTypeFor is resolveCycloneDXType with the inventory kind's fallback
// applied: SOMETHING has to be emitted for every in-scope asset, and CycloneDX
// 1.7 has no "unknown" component type to say so with.
//
// `device` is that something, and the class key travels verbatim in
// `vista:asset:class` on the same component, so a reader is never left guessing
// what the platform actually thinks the asset is. The HBOM does NOT take this
// fallback — see hardwareComponents.
func cycloneDXTypeFor(a Asset) string {
	if t, ok := resolveCycloneDXType(a); ok {
		return t
	}
	return "device"
}

func classLabel(classKey string) string {
	if c, ok := assetclass.Get(classKey); ok {
		return c.Label
	}
	return classKey
}

func baseAssetProperties(a Asset) []formatters.CDXProperty {
	props := []formatters.CDXProperty{
		{Name: propAssetUID, Value: a.ID.String()},
		{Name: propAssetClass, Value: a.ClassKey},
		{Name: propAssetPath, Value: a.ClassPath},
		{Name: propAssetStat, Value: a.AssetStatus},
		{Name: propAssetOwnsp, Value: a.AssetOwnership},
		{Name: propAssetRisk, Value: strconv.Itoa(a.RiskScore)},
	}
	props = appendIfSet(props, propAssetEnv, a.Environment)
	props = appendIfSet(props, propAssetBU, a.BusinessUnit)
	props = appendIfSet(props, propAssetOwner, a.OwnerEmail)
	props = appendIfSet(props, propAssetSite, a.Site)
	props = appendIfSet(props, propAssetRegn, a.Region)
	props = appendIfSet(props, propAssetZone, a.Zone)
	props = appendIfSet(props, propAssetFirst, utcRFC3339(a.FirstSeenAt))
	props = appendIfSet(props, propAssetLast, utcRFC3339(a.LastSeenAt))
	return props
}

// factProperties renders an asset's facts, optionally filtered to one namespace.
//
// The property name carries the fact key verbatim, and the source_ref is
// appended when a key has more than one source — `asset_facts` is unique per
// (asset, key, source_ref) precisely so two sources may disagree, and flattening
// that disagreement to one value here would publish a reconciliation this
// package did not perform.
func factProperties(facts []Fact, namespace string) []formatters.CDXProperty {
	bySourceCount := map[string]int{}
	for _, f := range facts {
		bySourceCount[f.Key]++
	}
	out := make([]formatters.CDXProperty, 0, len(facts))
	for _, f := range facts {
		if namespace != "" && !strings.HasPrefix(f.Key, namespace) {
			continue
		}
		if f.Value == "" {
			continue
		}
		name := propFactPrefix + f.Key
		if bySourceCount[f.Key] > 1 && f.SourceRef != "" {
			name = name + "@" + f.SourceRef
		}
		out = append(out, formatters.CDXProperty{Name: name, Value: f.Value})
	}
	return out
}

// factValue returns the value of one fact key, or empty.
//
// When a key has several sources it returns the FIRST in the snapshot's order
// (asset, key, source_ref), which is stable but arbitrary — this is a
// convenience for a component's `group`/`version`, not a reconciliation. The
// full disagreement is in the properties.
func factValue(facts []Fact, key string) string {
	for _, f := range facts {
		if f.Key == key {
			return f.Value
		}
	}
	return ""
}

func identifierProperties(ids []Identifier) []formatters.CDXProperty {
	out := make([]formatters.CDXProperty, 0, len(ids))
	for _, i := range ids {
		name := propIDPrefix + i.Kind
		if i.Scope != "" {
			name = name + "@" + i.Scope
		}
		out = append(out, formatters.CDXProperty{Name: name, Value: i.Value})
	}
	return out
}

func tagProperties(tags map[string]string) []formatters.CDXProperty {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]formatters.CDXProperty, 0, len(keys))
	for _, k := range keys {
		out = append(out, formatters.CDXProperty{Name: propTagPrefix + k, Value: tags[k]})
	}
	return out
}

// softwareProperties names the products installed on an asset by purl (falling
// back to name@version), one property per product.
func softwareProperties(installs []SoftwareInstall) []formatters.CDXProperty {
	seen := map[string]struct{}{}
	values := make([]string, 0, len(installs))
	for _, si := range installs {
		value := si.PURL
		if value == "" {
			value = si.Name
			if si.Version != "" {
				value += "@" + si.Version
			}
		}
		if value == "" {
			continue
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	sort.Strings(values)
	out := make([]formatters.CDXProperty, 0, len(values))
	for _, v := range values {
		out = append(out, formatters.CDXProperty{Name: propPrefix + "software:installed", Value: v})
	}
	return out
}

// sortProperties gives the property list a total order.
//
// Name alone is not a total order — CycloneDX allows a repeated property name
// (that is how `vista:software:installed` lists several packages), so ties break
// on value. Without the tie-break, two assemblies of the same data could emit
// the repeated properties in either order and hash differently.
func sortProperties(props []formatters.CDXProperty) []formatters.CDXProperty {
	if len(props) == 0 {
		return nil
	}
	sort.SliceStable(props, func(i, j int) bool {
		if props[i].Name != props[j].Name {
			return props[i].Name < props[j].Name
		}
		return props[i].Value < props[j].Value
	})
	return props
}

// propertyValue returns the value of one property by exact name, or empty.
func propertyValue(props []formatters.CDXProperty, name string) string {
	for _, p := range props {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// factProperty reads one fact key back out of a component's properties,
// tolerating the per-source suffix.
//
// It exists because factProperties renames a key that has MORE THAN ONE source
// to `vista:fact:<key>@<source_ref>`, which makes the plain name unreachable —
// and that is not hypothetical: the OCSF projection looked up
// `vista:fact:os.name` and found nothing for exactly the assets that had two
// sources for it, so a server with a CMDB record AND an agent report came out
// with no operating system at all while a server with only one came out fine.
// The disagreement the suffix preserves was silently deleting the answer.
//
// Where sources disagree this returns the FIRST by source reference, because
// the properties are sorted by (name, value) and `@` sorts before nothing. That
// is a deterministic pick, not a reconciliation: the full disagreement stays in
// the CycloneDX document, and only a projection into a format with one scalar
// field — OCSF's `device.os.name` — has to choose.
func factProperty(props []formatters.CDXProperty, key string) string {
	exact := propFactPrefix + key
	if v := propertyValue(props, exact); v != "" {
		return v
	}
	prefix := exact + "@"
	for _, p := range props {
		if strings.HasPrefix(p.Name, prefix) {
			return p.Value
		}
	}
	return ""
}

func appendIfSet(props []formatters.CDXProperty, name, value string) []formatters.CDXProperty {
	if value == "" {
		return props
	}
	return append(props, formatters.CDXProperty{Name: name, Value: value})
}

func indexAssets(assets []Asset) map[uuid.UUID]Asset {
	out := make(map[uuid.UUID]Asset, len(assets))
	for _, a := range assets {
		out[a.ID] = a
	}
	return out
}

func assetDisplay(byID map[uuid.UUID]Asset, id uuid.UUID) string {
	if a, ok := byID[id]; ok {
		return a.Name()
	}
	return id.String()
}

func groupIdentifiers(ids []Identifier) map[uuid.UUID][]Identifier {
	out := map[uuid.UUID][]Identifier{}
	for _, i := range ids {
		out[i.AssetID] = append(out[i.AssetID], i)
	}
	return out
}

func groupFacts(facts []Fact) map[uuid.UUID][]Fact {
	out := map[uuid.UUID][]Fact{}
	for _, f := range facts {
		out[f.AssetID] = append(out[f.AssetID], f)
	}
	return out
}

func groupSoftware(installs []SoftwareInstall) map[uuid.UUID][]SoftwareInstall {
	out := map[uuid.UUID][]SoftwareInstall{}
	for _, si := range installs {
		out[si.AssetID] = append(out[si.AssetID], si)
	}
	return out
}

func documentTitle(kind, scopeName string) string {
	title := map[string]string{
		"sbom":      "Software Bill of Materials",
		"hbom":      "Hardware Bill of Materials",
		"inventory": "Inventory Bill of Materials",
	}[kind]
	if title == "" {
		title = "Bill of Materials"
	}
	if scopeName != "" {
		return title + " — " + scopeName
	}
	return title
}

func documentDescription(kind string) string {
	switch kind {
	case "sbom":
		return "Every distinct software product installed on the assets in scope, with the assets each was found on."
	case "hbom":
		return "Every hardware asset in scope, with its hardware identity facts and identifiers."
	case "inventory":
		return "Every asset in scope, typed by its class, with its endpoints, relationships, facts and open vulnerabilities."
	default:
		return ""
	}
}

func timePtrRFC3339(t *time.Time) string {
	if t == nil {
		return ""
	}
	return utcRFC3339(*t)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
