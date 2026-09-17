package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/lib/pq"
	"time"

	"github.com/google/uuid"
)

// Asset is one configuration item: a thing, not a listening port (ADR-0002 D1,
// DATA_MODEL §2).
//
// What it no longer carries, and where those went:
//
//	port, service_*      → Endpoints. An asset may have zero (an at-rest bucket,
//	                       a declared service) or many.
//	asset_type           → ClassKey / ClassPath. The four-value enum is dropped.
//	operating_system     → Attributes["operating_system"], a class attribute.
//	fqdns, mac_addresses,
//	serial_number,
//	cloud_*              → Identifiers, which is also what the identification
//	                       engine matches on.
//	risk_level (stored)  → derived from RiskScore through models.RiskBands. The
//	                       column never had a writer, so every consumer of it
//	                       read "Informational" forever.
type Asset struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	// Class and its provenance. ClassSourceKind says HOW the class was decided
	// (measured/declared/imported/inferred); ClassSourceRef says WHO decided it.
	// ClassConfidence is nil for a fallback class — nothing classified it, and
	// that is not the same as classifying it with low confidence.
	ClassKey        string   `json:"class_key" db:"class_key"`
	ClassPath       string   `json:"class_path" db:"class_path"`
	ClassSourceKind string   `json:"class_source_kind" db:"class_source_kind"`
	ClassSourceRef  *string  `json:"class_source_ref,omitempty" db:"class_source_ref"`
	ClassConfidence *float64 `json:"class_confidence,omitempty" db:"class_confidence"`

	DisplayName *string `json:"display_name,omitempty" db:"display_name"`
	Hostname    *string `json:"hostname" db:"hostname"`
	// PrimaryAddress is a convenience for lists. The authoritative addresses are
	// the endpoints; this is the one to show when there is room for one.
	PrimaryAddress *string                `json:"primary_address,omitempty" db:"primary_address"`
	Attributes     map[string]interface{} `json:"attributes" db:"attributes"`

	Environment  *string `json:"environment" db:"environment"`
	BusinessUnit *string `json:"business_unit" db:"business_unit"`
	OwnerEmail   *string `json:"owner_email" db:"owner_email"`
	// SupportGroup is the team on the hook for it — ADR-0001 D3 Q5, the one
	// context field the CMDB buyer asked for that the old model had no home for.
	SupportGroup       *string                `json:"support_group,omitempty" db:"support_group"`
	Description        *string                `json:"description" db:"description"`
	Site               *string                `json:"site,omitempty" db:"site"`
	Region             *string                `json:"region,omitempty" db:"region"`
	Zone               *string                `json:"zone,omitempty" db:"zone"`
	LocationID         *uuid.UUID             `json:"location_id,omitempty" db:"location_id"`
	NetworkSegmentID   *uuid.UUID             `json:"network_segment_id,omitempty" db:"network_segment_id"`
	NetworkSegmentName *string                `json:"network_segment_name,omitempty" db:"network_segment_name"`
	DiscoveryMethod    *string                `json:"discovery_method,omitempty" db:"discovery_method"`
	ConfidenceScore    *int                   `json:"confidence_score,omitempty" db:"confidence_score"`
	Tags               map[string]interface{} `json:"tags" db:"tags"`
	Metadata           map[string]interface{} `json:"metadata" db:"metadata"`
	AssetOwnership     string                 `json:"asset_ownership" db:"asset_ownership"`
	AssetStatus        string                 `json:"asset_status" db:"asset_status"`
	StaleStatus        *string                `json:"stale_status,omitempty" db:"stale_status"`
	// MergedInto is the asset this one was merged into — the tombstone pointer.
	//
	// Accepting a merge ARCHIVES the observation rather than deleting it, so its
	// id keeps resolving: `GET /assets/{merged-away-id}` answers 200 with
	// `asset_status: archived` and this field naming the survivor, instead of a
	// 404 that tells a stale bookmark nothing. It is a first-class field rather
	// than a key inside `metadata` because a client has to be able to FOLLOW it,
	// and a pointer nobody can find in a schema is a pointer nobody follows.
	//
	// nil on every asset that was not merged away, which is almost all of them.
	MergedInto        *uuid.UUID `json:"merged_into,omitempty" db:"merged_into"`
	FirstDiscoveredAt time.Time  `json:"first_discovered_at" db:"first_discovered_at"`
	LastSeenAt        time.Time  `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt         *time.Time `json:"deleted_at" db:"deleted_at"`

	// RiskScore is recomputed as the MAX over the asset's scored crypto
	// configurations (ADR-0005 D4), never the GREATEST(old, new) the old model
	// wrote — that could only ever go up. RiskAssessedBy names the producers
	// that have looked: score 0 with an EMPTY array is NOT ASSESSED, score 0
	// with {crypto} is assessed clean, and collapsing the two is the
	// three-valued mistake this platform has made sixty times.
	RiskScore      int      `json:"risk_score" db:"risk_score"`
	RiskAssessedBy []string `json:"risk_assessed_by" db:"risk_assessed_by"`
	RiskLevel      string   `json:"risk_level"`

	// Identifiers and Endpoints are the asset's children. They are loaded by the
	// paths that need them rather than by every list query.
	Identifiers []Identifier `json:"identifiers,omitempty"`
	Endpoints   []Endpoint   `json:"endpoints,omitempty"`
	// PrimaryEndpoint is the one a list row shows: the most recently seen active
	// one. Nil is a real answer — an at-rest cloud resource has no endpoint at
	// all, which is what retires the old "AT-REST" port sentinel.
	PrimaryEndpoint *Endpoint `json:"primary_endpoint,omitempty"`

	CryptoImplementations []CryptoImplementation `json:"crypto_implementations,omitempty"`
	HighestRisk           *int                   `json:"highest_risk,omitempty"`
	CertificateCount      *int                   `json:"certificate_count,omitempty"`
	// CryptoImplementationCount is the number of live crypto configurations on
	// the asset. Populated by the LIST query so the Inventory row can show an
	// "N cfg" count without a per-row round trip.
	CryptoImplementationCount *int `json:"crypto_implementation_count,omitempty"`
	// ProtocolSummary is a per-protocol rollup of the asset's crypto
	// configurations (one entry per distinct protocol). It exists so the
	// Infrastructure lens row can render protocol badges from the LIST payload
	// instead of firing one child query per visible row.
	ProtocolSummary []AssetProtocolSummary `json:"protocol_summary,omitempty"`
}

// AssetProtocolSummary rolls up one protocol observed on an asset.
//
// MaxRiskScore follows the same convention as every other score in the
// platform: 0 means NOT ASSESSED (nothing resolved against the algorithms
// catalogue), NOT "safe". Consumers must not band 0 as a low-risk claim.
type AssetProtocolSummary struct {
	Protocol     string `json:"protocol"`
	Count        int    `json:"count"`
	MaxRiskScore int    `json:"max_risk_score"`
}

// Identifier is one identifier observed for an asset (DATA_MODEL §2).
//
// The kinds are the nine of ADR-0002 D3 and are validated in Go against the
// class registry, not by a database CHECK — the registry owns the vocabulary
// and the per-class precedence, and a second copy in SQL would drift from it.
type Identifier struct {
	ID      uuid.UUID `json:"id" db:"id"`
	AssetID uuid.UUID `json:"asset_id" db:"asset_id"`
	Kind    string    `json:"kind" db:"kind"`
	Value   string    `json:"value" db:"value"`
	// Scope is the segment for hostname and ip_address and the sync profile for
	// cmdb_sys_id. Nil for the six globally unique kinds; a scope on one of
	// those splits the uniqueness key and is rejected upstream.
	Scope       *string   `json:"scope,omitempty" db:"scope"`
	SourceKind  string    `json:"source_kind" db:"source_kind"`
	SourceRef   *string   `json:"source_ref,omitempty" db:"source_ref"`
	Confidence  float64   `json:"confidence" db:"confidence"`
	FirstSeenAt time.Time `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at" db:"last_seen_at"`
}

// Endpoint is one network face of an asset: an (address|fqdn, port, transport)
// it was observed exposing (DATA_MODEL §2, ADR-0002 D1).
//
// Port is nil for an at-rest or declared endpoint. The "AT-REST" port sentinel
// the port-as-asset model needed is retired: an at-rest cloud resource has no
// endpoint row at all.
type Endpoint struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	AssetID  uuid.UUID `json:"asset_id" db:"asset_id"`

	Address   *string `json:"address,omitempty" db:"address"`
	FQDN      *string `json:"fqdn,omitempty" db:"fqdn"`
	Port      *int    `json:"port,omitempty" db:"port"`
	Transport string  `json:"transport" db:"transport"`
	Protocol  *string `json:"protocol,omitempty" db:"protocol"`

	ServiceName                 *string `json:"service_name,omitempty" db:"service_name"`
	ServiceVersion              *string `json:"service_version,omitempty" db:"service_version"`
	ServiceConfidence           *string `json:"service_confidence,omitempty" db:"service_confidence"`
	ServiceIdentificationMethod *string `json:"service_identification_method,omitempty" db:"service_identification_method"`

	// BoundLocal says whether the socket is reachable only from the host
	// itself. THREE-VALUED, which is why it is a pointer AND why `omitempty` is
	// correct here: nil means nobody established it — every endpoint a network
	// scan found, because a scan cannot know, it only sees what answers — and
	// the field is then absent from the JSON rather than false. An explicit
	// false is a measurement that the service IS exposed to the network, and it
	// serialises, because `omitempty` on a pointer tests the pointer.
	//
	// Only a host's own view of its sockets writes either boolean (the agent's
	// host inventory, workstream 2.11b).
	BoundLocal *bool `json:"bound_local,omitempty" db:"bound_local"`

	SourceKind     string     `json:"source_kind" db:"source_kind"`
	SourceRef      *string    `json:"source_ref,omitempty" db:"source_ref"`
	Status         string     `json:"status" db:"status"`
	FirstSeenAt    time.Time  `json:"first_seen_at" db:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at" db:"last_seen_at"`
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty" db:"last_scanned_at"`
	LastScanStatus *string    `json:"last_scan_status,omitempty" db:"last_scan_status"`
}

// CryptoImplementation represents a cryptographic implementation found on an asset
type CryptoImplementation struct {
	ID       uuid.UUID `json:"id" db:"id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`
	AssetID  uuid.UUID `json:"asset_id" db:"asset_id"`
	// EndpointID is the endpoint this configuration was measured on
	// (DATA_MODEL §2). Nil for a configuration with no socket behind it — an
	// at-rest cloud resource — and AssetID stays as the roll-up target either
	// way.
	EndpointID           *uuid.UUID `json:"endpoint_id,omitempty" db:"endpoint_id"`
	Protocol             string     `json:"protocol" db:"protocol"`
	ProtocolVersion      *string    `json:"protocol_version" db:"protocol_version"`
	CipherSuite          *string    `json:"cipher_suite" db:"cipher_suite"`
	KeyExchangeAlgorithm *string    `json:"key_exchange_algorithm" db:"key_exchange_algorithm"`
	SignatureAlgorithm   *string    `json:"signature_algorithm" db:"signature_algorithm"`
	SymmetricEncryption  *string    `json:"symmetric_encryption" db:"symmetric_encryption"`
	HashAlgorithm        *string    `json:"hash_algorithm" db:"hash_algorithm"`
	KeySize              *int       `json:"key_size" db:"key_size"`
	CertificateID        *uuid.UUID `json:"certificate_id" db:"certificate_id"`
	DiscoveryMethod      string     `json:"discovery_method" db:"discovery_method"`
	// DiscoveryMethods is the row's full provenance: every method that has
	// contributed an observation to it, DiscoveryMethod first. A row a passive
	// sensor wrote and an active probe then completed carries both (subset
	// absorption, crypto_dedup.go). Never nil on the wire — readers normalise
	// it to an empty array — so a consumer can iterate it without a guard.
	DiscoveryMethods pq.StringArray `json:"discovery_methods" db:"discovery_methods"`
	ConfidenceScore  *float64       `json:"confidence_score" db:"confidence_score"`
	SourceSensorID   *uuid.UUID     `json:"source_sensor_id" db:"source_sensor_id"`
	RawData          JSONB          `json:"raw_data" db:"raw_data"`
	RiskScore        *int           `json:"risk_score" db:"risk_score"`
	// RiskScoreAssessed distinguishes an explicit numeric zero from the legacy
	// storage default. It is derived on reads from an existing positive stored
	// score or a stored zero corroborated by a worst numeric catalogue score of zero.
	RiskScoreAssessed bool       `json:"risk_score_assessed" db:"risk_score_assessed"`
	ComplianceStatus  JSONB      `json:"compliance_status" db:"compliance_status"`
	FirstDiscoveredAt time.Time  `json:"first_discovered_at" db:"first_discovered_at"`
	LastVerifiedAt    time.Time  `json:"last_verified_at" db:"last_verified_at"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt         *time.Time `json:"deleted_at" db:"deleted_at"`
	RiskLevel         string     `json:"risk_level" db:"risk_level"`
	RiskFactors       []string   `json:"risk_factors,omitempty"`
	// The six `device_*` fields are GONE. They were never set by any query in
	// this service, so they serialised as absent on every crypto configuration
	// the API has ever returned — six documented fields that could only ever be
	// missing. `devices` is retired: a device is an asset with an
	// `asset_management` row, and its vendor, model and firmware are class
	// ATTRIBUTES of that asset (ADR-0002 D2). A consumer that wants them reads
	// the asset.
	//
	// Asset information
	AssetHostname  *string `json:"asset_hostname,omitempty"`
	AssetIPAddress *string `json:"asset_ip_address,omitempty"`
	// AssetClassKey is the owning asset's class (ADR-0002 D2), not the retired
	// four-value asset_type enum. Renamed rather than left in place because the
	// VALUE changed meaning: an asset the old model called "appliance" is now
	// `hardware`, `switch` or `firewall`, and a consumer still reading
	// `asset_type` would have gone on matching four strings that no longer
	// appear.
	AssetClassKey     *string         `json:"asset_class_key,omitempty"`
	AssetEnvironment  *string         `json:"asset_environment,omitempty"`
	AssetBusinessUnit *string         `json:"asset_business_unit,omitempty"`
	Keys              []Key           `json:"keys,omitempty"`
	Libraries         []CryptoLibrary `json:"libraries,omitempty"`
}

// RiskSummary provides an overview of asset risks
type RiskSummary struct {
	TotalAssets int `json:"total_assets" db:"total_assets"`
	HighRisk    int `json:"high_risk" db:"high_risk"`
	MediumRisk  int `json:"medium_risk" db:"medium_risk"`
	LowRisk     int `json:"low_risk" db:"low_risk"`
	// Informational is score 0 WITH a producer in risk_assessed_by: somebody
	// looked and found nothing wrong.
	Informational int `json:"informational" db:"informational"`
	// UnknownRisk is score 0 with an EMPTY risk_assessed_by: NOT ASSESSED.
	//
	// The two used to be one number. `unknown_risk` counted every asset in the
	// Informational band with no coverage guard at all, so an asset nobody had
	// ever scored and an asset scored clean were the same bucket — the
	// three-valued-logic flattening this platform has made sixty times, in the
	// summary the dashboard hero reads. The risk FACET has always split them,
	// which is why the tile and the rail disagreed.
	UnknownRisk      int `json:"unknown_risk" db:"unknown_risk"`
	TotalCrypto      int `json:"total_crypto" db:"total_crypto"`
	CriticalFindings int `json:"critical_findings" db:"critical_findings"`
}

// PostureTrendPoint is one day on the dashboard posture trend line (ADR-0007).
// RiskIndex is the same metric the hero gauge shows (% of assets at high risk),
// computed identically here so the trend's right edge matches the gauge.
// Seeded=true marks a synthesized pre-history day: a new tenant has no
// snapshots yet, so days before its first real snapshot are drawn flat at the
// current live posture. Seeded=false is a real snapshot, a carried-forward real
// value, or today's live value.
type PostureTrendPoint struct {
	Date      string `json:"date"`       // YYYY-MM-DD (UTC)
	RiskIndex int    `json:"risk_index"` // 0–100, round(high_risk / total_assets * 100)
	Seeded    bool   `json:"seeded"`
}

// PQCReadinessSummary summarises tenant PQC adoption across crypto implementations.
// Readiness is measured as the fraction of crypto configurations whose key exchange
// or signature algorithm is flagged is_pqc=true in the algorithms catalog.
type PQCReadinessSummary struct {
	TotalImplementations int     `json:"total_implementations"`
	PQCImplementations   int     `json:"pqc_implementations"`
	ReadinessPercent     float64 `json:"readiness_percent"`
}

// AssetStats provides statistics for assets with trend data
type AssetStats struct {
	Current       int     `json:"current"`
	Previous      int     `json:"previous"`
	Change        int     `json:"change"`
	ChangePercent float64 `json:"change_percent"`
	Period        string  `json:"period"`
}

// AssetFilters defines parameters for filtering asset searches
// Note: Uses both 'form' tags (for Gin query binding) and 'json' tags (for JSON responses)
type AssetFilters struct {
	// Query is a query-language predicate over the `asset` target
	// (QUERY_LANGUAGE.md). It is the form the facet rail writes, a saved view
	// stores and the MCP tools take. Everything else in this struct is the
	// pre-query-language vocabulary, kept working for one release by being
	// translated into a query string server-side and AND-ed with this one.
	Query            string   `json:"query" form:"query"`
	Search           string   `json:"search" form:"search"`
	AssetType        []string `json:"asset_type" form:"asset_type"`
	Environment      []string `json:"environment" form:"environment"`
	RiskLevel        []string `json:"risk_level" form:"risk_level"`
	Protocol         []string `json:"protocol" form:"protocol"`
	BusinessUnit     []string `json:"business_unit" form:"business_unit"`
	OperatingSystem  []string `json:"operating_system" form:"operating_system"`
	OwnerEmail       []string `json:"owner_email" form:"owner_email"`
	LocationRegion   []string `json:"location_region" form:"location_region"`
	LocationSite     []string `json:"location_site" form:"location_site"`
	LocationBuilding []string `json:"location_building" form:"location_building"`
	LocationZone     []string `json:"location_zone" form:"location_zone"`
	LocationID       []string `json:"location_id" form:"location_id"`
	NetworkSegmentID []string `json:"network_segment_id" form:"network_segment_id"`
	AssetOwnership   []string `json:"asset_ownership" form:"asset_ownership"`
	AssetStatus      []string `json:"asset_status" form:"asset_status"`
	// UnscannedOnly keeps only assets that have never been actively scanned
	// (last_scanned_at IS NULL) — the "unscanned" coverage cut for Active Scan ().
	UnscannedOnly *bool `json:"unscanned_only" form:"unscanned_only"`
	// LastSeenBefore (RFC3339) keeps only assets whose last_seen_at is strictly
	// older than the cutoff; assets with NULL last_seen_at never match. Composes
	// with asset_status by AND — the time arm of the Stale lens's server-side cut.
	LastSeenBefore string `json:"last_seen_before" form:"last_seen_before"`
	// DiscoverySource filters by metadata->>'discovery_source' (e.g. "sensor_discoveries",
	// "cloud_discovery", "device_interrogation", "discovery_jobs"). Used by the Operations
	// → Approvals filter buttons.
	DiscoverySource []string `json:"discovery_source" form:"discovery_source"`
	// Certificate-based filters
	HasCertificates    *bool   `json:"has_certificates" form:"has_certificates"`
	CertExpiringWithin *int    `json:"cert_expiring_within" form:"cert_expiring_within"`
	CertKeySizeMin     *int    `json:"cert_key_size_min" form:"cert_key_size_min"`
	CertAlgorithm      *string `json:"cert_algorithm" form:"cert_algorithm"`
	// Crypto configuration filters
	ProtocolVersion          []string `json:"protocol_version" form:"protocol_version"`
	HashAlgorithm            []string `json:"hash_algorithm" form:"hash_algorithm"`
	KeySizeMin               *int     `json:"key_size_min" form:"key_size_min"`
	UsesDeprecatedAlgorithms *bool    `json:"uses_deprecated_algorithms" form:"uses_deprecated_algorithms"`
	Page                     int      `json:"page" form:"page"`
	PageSize                 int      `json:"page_size" form:"page_size"`
	SortBy                   string   `json:"sort_by" form:"sort_by"`
	SortOrder                string   `json:"sort_order" form:"sort_order"`
}

// AssetInput is what a caller supplies to create or update an asset: a class,
// identifiers, and context. There is no port — a port is an endpoint, and an
// endpoint is observed or declared separately (ADR-0002 D1).
//
// It is also the shape the bulk import and the CMDB pull build, so the columns
// those carry (serial, MAC, FQDN, cloud resource id) arrive as Identifiers and
// go through the identification engine like every other intake.
type AssetInput struct {
	// ClassKey is required on create and is validated against the class
	// registry. The old `asset_type` had four values, no validation in Go, and
	// an import wizard offering ten of which nine were invalid in the database.
	ClassKey string `json:"class_key"`
	// Identifiers are what the asset is known by. Declared identifiers (a
	// serial typed into the UI, a sys_id from a CMDB) are as much identity as
	// measured ones; what differs is their source, which the engine reconciles
	// on.
	Identifiers []AssetIdentifierInput `json:"identifiers,omitempty"`
	// Endpoints are optional: a manually created asset usually has none, and an
	// import may carry one.
	Endpoints []AssetEndpointInput `json:"endpoints,omitempty"`

	// DisplayName is what a person calls this thing. For most classes it is
	// cosmetic (the engine derives one from the identifiers). For the SERVICE
	// branch it is IDENTITY and required: a service identifies by
	// (tenant, class, name) and has nothing else to be known by
	// (ADR-0002 D3 erratum).
	DisplayName *string `json:"display_name"`

	Hostname  *string `json:"hostname"`
	IPAddress *string `json:"ip_address"`
	// Attributes are the class-specific typed attributes (operating_system,
	// vendor, model, firmware_version …), validated against the class's schema.
	Attributes   map[string]interface{} `json:"attributes"`
	Environment  *string                `json:"environment"`
	BusinessUnit *string                `json:"business_unit"`
	OwnerEmail   *string                `json:"owner_email"`
	SupportGroup *string                `json:"support_group"`
	Description  *string                `json:"description"`
	// Site and Region are the physical placement of the asset, as the source
	// that supplied it names it — a NetBox site and its region, a CMDB
	// location. They are free text rather than a FK to `locations` because a
	// connector cannot be trusted to have created a location row, and an
	// import that silently invented one would grow a location tree nobody
	// asked for. A nil pointer is "not stated" and leaves the column alone,
	// like every other context field.
	Site   *string `json:"site"`
	Region *string `json:"region"`

	Tags           map[string]interface{} `json:"tags"`
	Metadata       map[string]interface{} `json:"metadata"`
	AssetOwnership *string                `json:"asset_ownership"`
	// AssetStatus is REFUSED on both paths and exists only so a client that
	// sends it is told so.
	//
	// Creation ignores it: a new asset's approval status is evaluated
	// server-side from the tenant's network segments
	// (AssetService.evaluateAssetApproval), so no request body can promote an
	// asset past the approval queue. Update REJECTS it with a 400 naming the
	// endpoints that do the work — approving is a cascade (edge promotion,
	// deferred-finding materialisation) and denying carries a suppression, so
	// writing the column alone produces a monitored asset with none of it done.
	AssetStatus *string `json:"asset_status"`
}

// IdentifierUpdateReport says what an update did to an asset's identifiers.
//
// It is returned rather than implied because part of the answer is "no". A
// collector-minted identifier — an agent's installation id, a cloud resource
// id, anything a sensor measured — is a fact about the world, and an edit form
// is not where facts get deleted. Reporting those as removed would be a lie the
// UI repeats; leaving them out of the response entirely would be the same lie
// by omission, since the row the user deleted would reappear on the next read
// with nothing to say why.
type IdentifierUpdateReport struct {
	Attached []IdentifierChange `json:"attached"`
	Removed  []IdentifierChange `json:"removed"`
	Kept     []IdentifierChange `json:"kept"`
}

// IdentifierChange is one identifier an update attached, retired, or refused to
// retire. Reason is set only on `kept`, where it is the whole point.
type IdentifierChange struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Scope      string `json:"scope,omitempty"`
	SourceKind string `json:"source_kind,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// AssetIdentifierInput is one declared identifier on an AssetInput.
type AssetIdentifierInput struct {
	Kind  string  `json:"kind"`
	Value string  `json:"value"`
	Scope *string `json:"scope,omitempty"`
}

// AssetEndpointInput is one declared endpoint on an AssetInput.
type AssetEndpointInput struct {
	Address   *string `json:"address,omitempty"`
	FQDN      *string `json:"fqdn,omitempty"`
	Port      *int    `json:"port,omitempty"`
	Transport string  `json:"transport,omitempty"`
	Protocol  *string `json:"protocol,omitempty"`
}

// AssetFacetBucket represents a bucket for asset facets.
//
// Key is what a query term matches on — for the class facet that is the
// class_path, which is what `class:` compares against. Label is what the rail
// shows a person; it is empty when the key IS the label, so a rail can render
// `label || key` and a facet that gains a label later does not need a client
// change.
type AssetFacetBucket struct {
	Key   string `json:"value"`
	Label string `json:"label,omitempty"`
	Count int    `json:"count"`
}

// JSONB represents a PostgreSQL JSONB type
type JSONB map[string]interface{}

// Scan implements the sql.Scanner interface for JSONB
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = make(map[string]interface{})
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	result := make(map[string]interface{})
	if err := json.Unmarshal(bytes, &result); err != nil {
		return err
	}

	*j = result
	return nil
}

// Value implements the driver.Valuer interface for JSONB
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// CalculateAssetRiskScore calculates the risk score for an asset based on its crypto configurations
func (a *Asset) CalculateAssetRiskScore() {
	if len(a.CryptoImplementations) == 0 {
		a.RiskScore = 0
		a.RiskLevel = "Informational"
		return
	}

	maxRisk := 0
	for _, impl := range a.CryptoImplementations {
		if impl.RiskScore != nil && *impl.RiskScore > maxRisk {
			maxRisk = *impl.RiskScore
		}
	}

	a.RiskScore = maxRisk
	a.RiskLevel = GetRiskLevel(maxRisk)
}

// GetRiskLevel lives in risk_bands.go, alongside the SQL forms of the same
// ladder, so the Go and SQL bands cannot drift apart.

// RelationshipHints provides helpful information about asset relationships
type RelationshipHints struct {
	CertificateCount int    `json:"certificate_count"`
	Message          string `json:"message,omitempty"`
}

// AssetCertificateLink is a single asset-to-certificate edge, sourced from the
// crypto_implementations join table. It's the canonical answer to "which cert
// is on which asset, via which crypto configuration." Visualizers that need
// exact per-asset cert linkage fetch a list of these scoped to the asset or
// cert IDs they're currently rendering.
type AssetCertificateLink struct {
	AssetID                uuid.UUID `json:"asset_id" db:"asset_id"`
	CertificateID          uuid.UUID `json:"certificate_id" db:"certificate_id"`
	CryptoImplementationID uuid.UUID `json:"crypto_implementation_id" db:"crypto_implementation_id"`
	Protocol               string    `json:"protocol" db:"protocol"`
	RiskScore              *int      `json:"risk_score,omitempty" db:"risk_score"`
}

// AssetsResponse represents the response structure for asset queries
type AssetsResponse struct {
	Assets     []Asset            `json:"assets"`
	Pagination PaginationInfo     `json:"pagination"`
	Hints      *RelationshipHints `json:"hints,omitempty"`
}

// PaginationInfo provides pagination metadata
type PaginationInfo struct {
	Page       int  `json:"page"`
	PageSize   int  `json:"page_size"`
	Total      int  `json:"total"`
	TotalPages int  `json:"total_pages"`
	HasNext    bool `json:"has_next"`
	HasPrev    bool `json:"has_prev"`
}

// AssetHistory represents a history entry for an asset
type AssetHistory struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	AssetID     uuid.UUID              `json:"asset_id" db:"asset_id"`
	TenantID    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	ActorUserID *uuid.UUID             `json:"actor_user_id,omitempty" db:"actor_user_id"`
	Source      string                 `json:"source" db:"source"`
	Action      string                 `json:"action" db:"action"`
	ChangesJSON map[string]interface{} `json:"changes" db:"changes_json"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
}

// AssetClassChange is one row of `asset_class_history`: the class an asset
// moved FROM, the class it moved TO, and how.
//
// `FromClassKey` is nil only on the row the asset's creation wrote — there was
// no previous class. Every other row carries both ends, so a reader never has
// to look at the neighbouring row to know what changed; a row that needed its
// predecessor would be wrong the moment a page boundary fell between them.
type AssetClassChange struct {
	ID       uuid.UUID `json:"id" db:"id"`
	AssetID  uuid.UUID `json:"asset_id" db:"asset_id"`
	TenantID uuid.UUID `json:"tenant_id" db:"tenant_id"`

	FromClassKey   *string `json:"from_class_key,omitempty" db:"from_class_key"`
	FromClassLabel string  `json:"from_class_label,omitempty"`
	ToClassKey     string  `json:"to_class_key" db:"to_class_key"`
	ToClassLabel   string  `json:"to_class_label,omitempty"`

	// Source is the MECHANISM: proposal, manual, import, classifier.
	Source string `json:"source" db:"source"`
	// ActorUserID is the person, absent when a machine did it. Absent means
	// "no person", not "person unknown".
	ActorUserID *uuid.UUID `json:"actor_user_id,omitempty" db:"actor_user_id"`
	// Evidence is the argument as identifiers — rule ids, a model id and its
	// probability, the proposal id. Never a hostname, an address or a secret.
	Evidence  map[string]interface{} `json:"evidence" db:"evidence"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
}

// Certificate represents a certificate in the inventory
type Certificate struct {
	ID                      uuid.UUID  `json:"id" db:"id"`
	TenantID                uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	SerialNumber            *string    `json:"serial_number,omitempty" db:"serial_number"`
	SubjectDN               string     `json:"subject_dn" db:"subject_dn"`
	IssuerDN                string     `json:"issuer_dn" db:"issuer_dn"`
	CommonName              *string    `json:"common_name,omitempty" db:"common_name"`
	SubjectAlternativeNames []string   `json:"subject_alternative_names,omitempty" db:"subject_alternative_names"`
	SignatureAlgorithm      *string    `json:"signature_algorithm,omitempty" db:"signature_algorithm"`
	PublicKeyAlgorithm      *string    `json:"public_key_algorithm,omitempty" db:"public_key_algorithm"`
	PublicKeySize           *int       `json:"public_key_size,omitempty" db:"public_key_size"`
	NotBefore               *time.Time `json:"not_before,omitempty" db:"not_before"`
	NotAfter                *time.Time `json:"not_after,omitempty" db:"not_after"`
	FingerprintSHA1         *string    `json:"fingerprint_sha1,omitempty" db:"fingerprint_sha1"`
	FingerprintSHA256       string     `json:"fingerprint_sha256" db:"fingerprint_sha256"`
	CertificatePEM          *string    `json:"certificate_pem,omitempty" db:"certificate_pem"`
	IsSelfSigned            bool       `json:"is_self_signed" db:"is_self_signed"`
	IsCACertificate         bool       `json:"is_ca_certificate" db:"is_ca_certificate"`
	KeyUsage                []string   `json:"key_usage,omitempty" db:"key_usage"`
	ExtendedKeyUsage        []string   `json:"extended_key_usage,omitempty" db:"extended_key_usage"`
	// Certificate chain and lifecycle fields
	IssuerCertificateID       *uuid.UUID `json:"issuer_certificate_id,omitempty" db:"issuer_certificate_id"`
	SupersededByCertificateID *uuid.UUID `json:"superseded_by_certificate_id,omitempty" db:"superseded_by_certificate_id"`
	CertificateState          string     `json:"certificate_state" db:"certificate_state"`
	CertificateStateReason    *string    `json:"certificate_state_reason,omitempty" db:"certificate_state_reason"`
	RevokedAt                 *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevocationDiscoveredAt    *time.Time `json:"revocation_discovered_at,omitempty" db:"revocation_discovered_at"`
	// CycloneDX CBOM certificate properties
	CertificateFormat     string     `json:"certificate_format" db:"certificate_format"`
	ActivationDate        *time.Time `json:"activation_date,omitempty" db:"activation_date"`
	DeactivationDate      *time.Time `json:"deactivation_date,omitempty" db:"deactivation_date"`
	DestructionDate       *time.Time `json:"destruction_date,omitempty" db:"destruction_date"`
	SignatureAlgorithmOID *string    `json:"signature_algorithm_oid,omitempty" db:"signature_algorithm_oid"`
	PublicKeyAlgorithmOID *string    `json:"public_key_algorithm_oid,omitempty" db:"public_key_algorithm_oid"`
	DataCompleteness      string     `json:"data_completeness" db:"data_completeness"`
	DataSource            *string    `json:"data_source,omitempty" db:"data_source"`
	LastDataUpdate        *time.Time `json:"last_data_update,omitempty" db:"last_data_update"`
	// Certificate quality flags
	HasSCT *bool `json:"has_sct,omitempty" db:"has_sct"`
	// SCTSource is which RFC 6962 delivery route carried the SCT (embedded |
	// tls_extension | ocsp | none). Absent means the route wasn't observable
	// (e.g. a passive-capture-only observation) — never a false "none".
	SCTSource     *string   `json:"sct_source,omitempty" db:"sct_source"`
	KnownBadCA    *string   `json:"known_bad_ca,omitempty" db:"known_bad_ca"`
	IsEV          *bool     `json:"is_ev,omitempty" db:"is_ev"`
	OCSPStatus    *string   `json:"ocsp_status,omitempty" db:"ocsp_status"`
	OCSPDetail    *string   `json:"ocsp_detail,omitempty" db:"ocsp_detail"`
	CertOwnership *string   `json:"cert_ownership,omitempty" db:"cert_ownership"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
	RelatedAssets []Asset   `json:"related_assets,omitempty"`
	// DeploymentCount is the number of distinct assets currently using
	// this certificate via crypto_implementations. Populated by list queries
	// via a correlated subquery so the frontend row can show a host count
	// without expanding the row.
	DeploymentCount *int `json:"deployment_count,omitempty"`
	// Ownership is the EFFECTIVE ownership bucket used by the `?ownership=`
	// list filter — the linked asset's asset_ownership when the cert is
	// deployed, else the declared CertOwnership (manual uploads), else
	// "unknown". Unlike CertOwnership (which is null unless explicitly
	// declared at upload time), this is always populated so the list view and
	// the filter agree on which of internal/third_party/unknown a cert falls
	// into (#H-6: filter buckets summed to less than the unfiltered total
	// because the list payload only ever showed the raw, mostly-null
	// cert_ownership column). Populated by list queries only.
	Ownership string `json:"ownership,omitempty" db:"-"`
}

// CertificateData represents certificate data for ingestion
type CertificateData struct {
	SubjectDN               string
	IssuerDN                string
	SerialNumber            string
	CommonName              string
	SubjectAlternativeNames []string
	NotBefore               time.Time
	NotAfter                time.Time
	FingerprintSHA256       string
	FingerprintSHA1         string
	CertificatePEM          string
	PublicKeyAlgorithm      string
	PublicKeySize           int
	SignatureAlgorithm      string
	IsSelfSigned            bool
	IsCACertificate         bool
	KeyUsage                []string
	ExtendedKeyUsage        []string
	IssuerCertificateID     *uuid.UUID
	DataSource              string                 // e.g., "discovery", "cloud_api", "manual"
	CertOwnership           string                 // "internal" | "third_party" | "" (unset; derived from asset link for discovered certs)
	ACMMetadata             map[string]interface{} // AWS ACM-specific metadata (ARN, renewal status, etc.)

	// Certificate quality flags (computed during active TLS probing/enrichment)
	HasSCT     *bool  // Certificate Transparency: SCT present (any RFC 6962 route)
	SCTSource  string // Which route carried it: embedded | tls_extension | ocsp | none
	KnownBadCA string // Known-bad CA name (e.g., Superfish, eDellRoot)
	IsEV       bool   // Extended Validation certificate
	OCSPStatus string // OCSP revocation status: good, revoked, unknown
	OCSPDetail string // OCSP response detail
}

// CertificateHistory represents a certificate lifecycle event
type CertificateHistory struct {
	ID                    uuid.UUID              `json:"id" db:"id"`
	CertificateID         uuid.UUID              `json:"certificate_id" db:"certificate_id"`
	TenantID              uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	EventType             string                 `json:"event_type" db:"event_type"`
	EventData             map[string]interface{} `json:"event_data" db:"event_data"`
	PreviousCertificateID *uuid.UUID             `json:"previous_certificate_id,omitempty" db:"previous_certificate_id"`
	DiscoveredAt          *time.Time             `json:"discovered_at,omitempty" db:"discovered_at"`
	CreatedAt             time.Time              `json:"created_at" db:"created_at"`
	CreatedBy             *uuid.UUID             `json:"created_by,omitempty" db:"created_by"`
}

// UnifiedInventoryFilters defines parameters for filtering unified inventory searches
type UnifiedInventoryFilters struct {
	// Entity type filter
	EntityType string `json:"entity_type" form:"entity_type"` // "assets", "certificates", "both", "crypto_implementations"

	// View mode
	ViewMode string `json:"view_mode" form:"view_mode"` // "unified", "grouped", "flat"

	// Common filters
	Search      string   `json:"search" form:"search"`
	RiskLevel   []string `json:"risk_level" form:"risk_level"`
	Environment []string `json:"environment" form:"environment"`

	// Asset filters (inherit from AssetFilters)
	AssetType       []string `json:"asset_type" form:"asset_type"`
	BusinessUnit    []string `json:"business_unit" form:"business_unit"`
	OperatingSystem []string `json:"operating_system" form:"operating_system"`
	OwnerEmail      []string `json:"owner_email" form:"owner_email"`
	AssetOwnership  []string `json:"asset_ownership" form:"asset_ownership"`
	AssetStatus     []string `json:"asset_status" form:"asset_status"`

	// Certificate filters
	CertExpiringDays   *int    `json:"cert_expiring_days" form:"cert_expiring_days"`     // Days until expiration
	CertKeySizeMin     *int    `json:"cert_key_size_min" form:"cert_key_size_min"`       // Minimum key size
	CertAlgorithm      *string `json:"cert_algorithm" form:"cert_algorithm"`             // Public key algorithm
	CertIssuer         *string `json:"cert_issuer" form:"cert_issuer"`                   // Issuer DN filter
	CertExpiringWithin *int    `json:"cert_expiring_within" form:"cert_expiring_within"` // Expiring within X days

	// Crypto configuration filters
	ProtocolVersion      []string `json:"protocol_version" form:"protocol_version"`           // e.g., ["TLSv1.0", "TLSv1.1"]
	HashAlgorithm        []string `json:"hash_algorithm" form:"hash_algorithm"`               // e.g., ["SHA1", "MD5"]
	KeySizeMin           *int     `json:"key_size_min" form:"key_size_min"`                   // Minimum key size
	DeprecatedAlgorithms *bool    `json:"deprecated_algorithms" form:"deprecated_algorithms"` // Filter for deprecated algorithms

	// Cross-entity filters
	HasCertificates          *bool `json:"has_certificates" form:"has_certificates"`                     // Assets with certificates
	UsesDeprecatedAlgorithms *bool `json:"uses_deprecated_algorithms" form:"uses_deprecated_algorithms"` // Assets using deprecated algorithms

	// Pagination and sorting
	Page      int    `json:"page" form:"page"`
	PageSize  int    `json:"page_size" form:"page_size"`
	SortBy    string `json:"sort_by" form:"sort_by"`
	SortOrder string `json:"sort_order" form:"sort_order"`
}

// UnifiedEntity represents a unified entity (asset, certificate, or crypto configuration)
type UnifiedEntity struct {
	EntityType                   string                 `json:"entity_type"` // "asset", "certificate", "crypto_implementation"
	ID                           uuid.UUID              `json:"id"`
	Asset                        *Asset                 `json:"asset,omitempty"`
	Certificate                  *Certificate           `json:"certificate,omitempty"`
	CryptoImplementation         *CryptoImplementation  `json:"crypto_implementation,omitempty"`
	RelatedAssets                []Asset                `json:"related_assets,omitempty"`
	RelatedCertificates          []Certificate          `json:"related_certificates,omitempty"`
	RelatedCryptoImplementations []CryptoImplementation `json:"related_crypto_implementations,omitempty"`
	RiskScore                    int                    `json:"risk_score"`
	RiskLevel                    string                 `json:"risk_level"`
	CertificateCount             *int                   `json:"certificate_count,omitempty"` // For assets
	AssetCount                   *int                   `json:"asset_count,omitempty"`       // For certificates
	CryptoImplementationCount    *int                   `json:"crypto_implementation_count,omitempty"`
	DaysUntilExpiration          *int                   `json:"days_until_expiration,omitempty"` // For certificates
}

// UnifiedInventorySummary provides summary statistics for unified inventory
type UnifiedInventorySummary struct {
	TotalAssets                int `json:"total_assets"`
	TotalCertificates          int `json:"total_certificates"`
	TotalCryptoImplementations int `json:"total_crypto_implementations"`
	ExpiringCertificates       int `json:"expiring_certificates"`    // Expiring within 30 days
	DeprecatedAlgorithms       int `json:"deprecated_algorithms"`    // Count of deprecated algorithm usage
	AssetsWithCertificates     int `json:"assets_with_certificates"` // Assets that have certificates
	HighRiskEntities           int `json:"high_risk_entities"`       // Entities with high/critical risk
}

// CertificateFilters defines parameters for filtering certificate searches
type CertificateFilters struct {
	CertificateID *uuid.UUID `json:"certificate_id" form:"cert_id"`
	ExpiringDays  *int       `json:"expiring_days" form:"expiring_days"`
	KeySizeMin    *int       `json:"key_size_min" form:"key_size_min"`
	Algorithm     *string    `json:"algorithm" form:"algorithm"`
	Issuer        *string    `json:"issuer" form:"issuer"`
	SelfSigned    *bool      `json:"self_signed" form:"self_signed"`
	// Ownership filters to certs whose owning asset has this asset_ownership
	// (internal | third_party | unknown), via crypto_implementations → assets.
	// Drives the "vendor certificates" view of the cert lens.
	Ownership *string `json:"ownership" form:"ownership"`
	Search    *string `json:"search" form:"search"`
	Page      int     `json:"page" form:"page"`
	PageSize  int     `json:"page_size" form:"page_size"`
	SortBy    string  `json:"sort_by" form:"sort_by"`
	SortOrder string  `json:"sort_order" form:"sort_order"`
}

// CryptoImplementationFilters defines parameters for filtering crypto configuration searches
type CryptoImplementationFilters struct {
	// Protocol filters
	Protocol        []string `json:"protocol" form:"protocol"`                 // Filter by protocol (TLS, SSH, IPSec, etc.)
	ProtocolVersion []string `json:"protocol_version" form:"protocol_version"` // Filter by protocol version

	// Cipher and algorithm filters
	CipherSuite   []string `json:"cipher_suite" form:"cipher_suite"`     // Filter by cipher suite
	HashAlgorithm []string `json:"hash_algorithm" form:"hash_algorithm"` // Filter by hash algorithm
	KeySizeMin    *int     `json:"key_size_min" form:"key_size_min"`     // Minimum key size

	// Relationship filters
	CertificateID *uuid.UUID `json:"certificate_id" form:"certificate_id"` // Filter by certificate
	AssetID       *uuid.UUID `json:"asset_id" form:"asset_id"`             // Filter by asset

	// Risk and discovery filters
	RiskLevel       []string `json:"risk_level" form:"risk_level"`             // Filter by risk level (low, medium, high, critical)
	DiscoveryMethod []string `json:"discovery_method" form:"discovery_method"` // Filter by discovery method (passive, active, manual, integration)

	// Deprecated algorithms filter
	UsesDeprecatedAlgorithms *bool `json:"uses_deprecated_algorithms" form:"uses_deprecated_algorithms"` // Filter deprecated algorithms

	// Search
	Search string `json:"search" form:"search"` // Text search across protocol, cipher suite, etc.

	// Pagination and sorting
	Page      int    `json:"page" form:"page"`
	PageSize  int    `json:"page_size" form:"page_size"`
	SortBy    string `json:"sort_by" form:"sort_by"`
	SortOrder string `json:"sort_order" form:"sort_order"`
}
