// Package xbom assembles the non-crypto bills of materials — sbom, hbom and
// inventory — onto the existing CBOM artifact pipeline (ADR-0005 D6).
//
// The premise is that a CBOM is not a format of its own: it is the
// CRYPTOGRAPHIC SUBSET of an inventory snapshot, and CycloneDX 1.7 already
// models the rest of the union — `device`, `operating-system`, `platform`,
// `application`, `library`, `data` and `container` component types, `services`
// for network faces, `dependencies` for edges, `vulnerabilities` for CVEs. So
// the four kinds share one format, one content hash, one signature and one
// comparison rather than each inventing a serialisation. A rejected alternative
// was a bespoke inventory document (OCSF-as-artifact, or our own JSON); see the
// ADR. OCSF is here too, but as an EXPORT of the artifact, not as the artifact.
//
// What this package reads and what it does not:
//
//   - It does NOT decide which assets are in scope. The asset id set arrives
//     already resolved, by inventory-service, from the scope's query — exactly
//     the boundary the CBOM kind uses. cbom-service holding a second opinion
//     about what a scope means is the bug the query-language pipeline removed,
//     and re-introducing it HERE, where the answer is signed and dated, would
//     be the worst place to have it.
//   - It DOES read the inventory tables directly, by asset id. That is a join,
//     not a boundary: fetching six related tables for N assets over HTTP would
//     be N+1 round trips per artifact, and the per-asset endpoints that exist
//     are shaped for one asset at a time. `ee/cbomattest` already reads
//     `findings` the same way, under the same tenant-scoped transaction.
package xbom

import (
	"time"

	"github.com/google/uuid"
)

// Asset is the subset of an `assets` row an xBOM needs. Deliberately a narrow
// projection rather than the whole row: everything here is emitted into a
// document a customer hands to a third party, and a column arriving in the
// artifact because it happened to be SELECTed is how an inventory export comes
// to carry things nobody meant to publish.
type Asset struct {
	ID        uuid.UUID
	ClassKey  string
	ClassPath string
	// CycloneDXType is the class registry's own CycloneDX component type for
	// this asset's class, read from `asset_classes`.
	//
	// It travels on the row because `assetclass.Get` — the generated registry —
	// deliberately does NOT know tenant subclasses: those are runtime rows
	// (ADR-0002 D2), and a NetBox device role or a hand-added leaf produces
	// one. Without this column the lookup missed every one of them and fell
	// back to `device`, which typed a tenant subclass of `business_service` as
	// hardware and put it in the HBOM. Empty when the class has no registry row
	// at all — see resolveCycloneDXType for what that then means.
	CycloneDXType  string
	DisplayName    string
	Hostname       string
	PrimaryAddress string
	Environment    string
	BusinessUnit   string
	OwnerEmail     string
	Site           string
	Region         string
	Zone           string
	AssetStatus    string
	AssetOwnership string
	RiskScore      int
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	// Tags is the flattened `tags` jsonb, string values only. A nested object
	// under a tag key is skipped rather than stringified — "map[…]" in an
	// evidence document is noise, not information.
	Tags map[string]string
}

// Name is the asset's display name, falling back through the identifiers a
// human would actually recognise it by, and finally to the id.
//
// It never returns empty: `name` is REQUIRED on a CycloneDX component, so an
// asset with no display name, hostname or address would otherwise produce a
// document that fails schema validation.
func (a Asset) Name() string {
	for _, candidate := range []string{a.DisplayName, a.Hostname, a.PrimaryAddress} {
		if candidate != "" {
			return candidate
		}
	}
	return a.ID.String()
}

// Identifier is one `asset_identifiers` row: how the asset is known.
type Identifier struct {
	AssetID uuid.UUID
	Kind    string
	Value   string
	Scope   string
}

// Endpoint is one `asset_endpoints` row: a reachable (address, port, transport)
// face of an asset.
type Endpoint struct {
	ID             uuid.UUID
	AssetID        uuid.UUID
	Address        string
	FQDN           string
	Port           int
	HasPort        bool
	Transport      string
	Protocol       string
	ServiceName    string
	ServiceVersion string
	Status         string
}

// Host is the address half of the endpoint — FQDN preferred, then address.
// Empty is impossible in the database (`asset_endpoints_addressable_check`),
// but the caller is not entitled to assume the constraint is there.
func (e Endpoint) Host() string {
	if e.FQDN != "" {
		return e.FQDN
	}
	return e.Address
}

// Fact is one `asset_facts` row: a statement with provenance.
type Fact struct {
	AssetID uuid.UUID
	Key     string
	// Value is the rendered scalar form of the jsonb value. A string comes out
	// unquoted; a number, bool or null comes out as its JSON text; an object or
	// array comes out as compact JSON. Facts go into CycloneDX `properties`,
	// whose value is a string, so something has to do this — doing it once here
	// keeps `"22.04"` from arriving as `"\"22.04\""`.
	Value      string
	SourceKind string
	SourceRef  string
	ObservedAt time.Time
}

// SoftwareInstall is a `software_installs` row joined to its product.
type SoftwareInstall struct {
	AssetID     uuid.UUID
	ProductID   uuid.UUID
	InstallPath string
	Name        string
	Vendor      string
	Version     string
	CPE         string
	PURL        string
	LicenseID   string
}

// Relationship is one `asset_relationships` row: a typed edge between two
// assets.
type Relationship struct {
	FromAssetID uuid.UUID
	ToAssetID   uuid.UUID
	Type        string
	Status      string
}

// VulnerabilityFinding is a `findings` row from the `vulnerability` producer,
// left-joined to the mirrored catalogue entry for the CVE it names.
//
// ONLY this producer's findings reach a bill of materials' `vulnerabilities`
// array. A compliance control failure, a missing owner, an end-of-life OS —
// each is a finding, none is a CVE, and a downstream vulnerability scanner
// reading this array has no way to tell a hygiene gap from a remote code
// execution once they are in the same list under the same key.
type VulnerabilityFinding struct {
	ID          uuid.UUID
	Kind        string
	SubjectType string
	SubjectID   uuid.UUID
	SubjectLbl  string
	Severity    string
	Score       int
	Summary     string
	FirstSeen   time.Time
	LastSeen    time.Time
	// CVEID is read from `evidence.cve_id` (a string) or the first entry of
	// `evidence.cve_ids` (an array). Empty when the finding names no CVE, which
	// is a legitimate state: the finding still travels, without a `cve` object,
	// rather than being dropped or given an invented id.
	CVEID string

	// The catalogue half. All optional — a CVE the mirror has not seen yet
	// yields a finding with an id and no score, and that is reported as "not
	// scored", never as a zero.
	CVSSVersion string
	CVSSScore   *float64
	CVSSVector  string
	CVSSeverity string
	Description string
	PublishedAt *time.Time
	ModifiedAt  *time.Time
}

// Snapshot is everything the assembler read for one artifact, already sorted.
//
// Sorted is the contract, not an implementation detail. The canonical bytes are
// the content hash; component order decides the bytes; so every slice here is
// ordered by a stable key at the SQL level and the assembler never re-orders by
// anything a map iteration touches. Two assemblies of an unchanged inventory
// must hash identically or "the artifact changed" stops meaning anything.
type Snapshot struct {
	Assets        []Asset
	Identifiers   []Identifier
	Endpoints     []Endpoint
	Facts         []Fact
	Software      []SoftwareInstall
	Relationships []Relationship
	Vulns         []VulnerabilityFinding
}
