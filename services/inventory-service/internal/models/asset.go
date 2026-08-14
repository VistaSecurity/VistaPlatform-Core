package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Asset represents a discovered asset in the inventory
type Asset struct {
	ID                          uuid.UUID              `json:"id" db:"id"`
	TenantID                    uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Hostname                    *string                `json:"hostname" db:"hostname"`
	IPAddress                   *string                `json:"ip_address" db:"ip_address"`
	Port                        *int                   `json:"port" db:"port"`
	AssetType                   string                 `json:"asset_type" db:"asset_type"`
	OperatingSystem             *string                `json:"operating_system" db:"operating_system"`
	Environment                 *string                `json:"environment" db:"environment"`
	BusinessUnit                *string                `json:"business_unit" db:"business_unit"`
	OwnerEmail                  *string                `json:"owner_email" db:"owner_email"`
	Description                 *string                `json:"description" db:"description"`
	FQDNs                       []string               `json:"fqdns,omitempty" db:"fqdns"`
	MacAddresses                []string               `json:"mac_addresses,omitempty" db:"mac_addresses"`
	SerialNumber                *string                `json:"serial_number,omitempty" db:"serial_number"`
	CloudProvider               *string                `json:"cloud_provider,omitempty" db:"cloud_provider"`
	CloudAccountID              *string                `json:"cloud_account_id,omitempty" db:"cloud_account_id"`
	CloudInstanceID             *string                `json:"cloud_instance_id,omitempty" db:"cloud_instance_id"`
	Site                        *string                `json:"site,omitempty" db:"site"`
	Region                      *string                `json:"region,omitempty" db:"region"`
	Zone                        *string                `json:"zone,omitempty" db:"zone"`
	LocationID                  *uuid.UUID             `json:"location_id,omitempty" db:"location_id"`
	NetworkSegmentID            *uuid.UUID             `json:"network_segment_id,omitempty" db:"network_segment_id"`
	NetworkSegmentName          *string                `json:"network_segment_name,omitempty" db:"network_segment_name"`
	ServiceName                 *string                `json:"service_name,omitempty" db:"service_name"`
	ServiceVersion              *string                `json:"service_version,omitempty" db:"service_version"`
	ServiceConfidence           *string                `json:"service_confidence,omitempty" db:"service_confidence"`
	ServiceIdentificationMethod *string                `json:"service_identification_method,omitempty" db:"service_identification_method"`
	DiscoveryMethod             *string                `json:"discovery_method,omitempty" db:"discovery_method"`
	ConfidenceScore             *int                   `json:"confidence_score,omitempty" db:"confidence_score"`
	Tags                        map[string]interface{} `json:"tags" db:"tags"`
	Metadata                    map[string]interface{} `json:"metadata" db:"metadata"`
	AssetOwnership              string                 `json:"asset_ownership" db:"asset_ownership"`
	AssetStatus                 string                 `json:"asset_status" db:"asset_status"`
	StaleStatus                 *string                `json:"stale_status,omitempty" db:"stale_status"`
	FirstDiscoveredAt           time.Time              `json:"first_discovered_at" db:"first_discovered_at"`
	LastSeenAt                  time.Time              `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt                   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt                   time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt                   *time.Time             `json:"deleted_at" db:"deleted_at"`
	RiskScore                   int                    `json:"risk_score" db:"risk_score"`
	RiskLevel                   string                 `json:"risk_level" db:"risk_level"`
	CryptoImplementations       []CryptoImplementation `json:"crypto_implementations,omitempty"`
	HighestRisk                 *int                   `json:"highest_risk,omitempty"`
	CertificateCount            *int                   `json:"certificate_count,omitempty"`
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

// CryptoImplementation represents a cryptographic implementation found on an asset
type CryptoImplementation struct {
	ID                   uuid.UUID  `json:"id" db:"id"`
	TenantID             uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	AssetID              uuid.UUID  `json:"asset_id" db:"asset_id"`
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
	ConfidenceScore      *float64   `json:"confidence_score" db:"confidence_score"`
	SourceSensorID       *uuid.UUID `json:"source_sensor_id" db:"source_sensor_id"`
	RawData              JSONB      `json:"raw_data" db:"raw_data"`
	RiskScore            *int       `json:"risk_score" db:"risk_score"`
	ComplianceStatus     JSONB      `json:"compliance_status" db:"compliance_status"`
	FirstDiscoveredAt    time.Time  `json:"first_discovered_at" db:"first_discovered_at"`
	LastVerifiedAt       time.Time  `json:"last_verified_at" db:"last_verified_at"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt            *time.Time `json:"deleted_at" db:"deleted_at"`
	RiskLevel            string     `json:"risk_level" db:"risk_level"`
	RiskFactors          []string   `json:"risk_factors,omitempty"`
	// Device information (if asset is linked to a device)
	DeviceID        *uuid.UUID `json:"device_id,omitempty"`
	DeviceType      *string    `json:"device_type,omitempty"`
	DeviceVendor    *string    `json:"device_vendor,omitempty"`
	DeviceModel     *string    `json:"device_model,omitempty"`
	DeviceHostname  *string    `json:"device_hostname,omitempty"`
	DeviceIPAddress *string    `json:"device_ip_address,omitempty"`
	// Asset information
	AssetHostname     *string         `json:"asset_hostname,omitempty"`
	AssetIPAddress    *string         `json:"asset_ip_address,omitempty"`
	AssetType         *string         `json:"asset_type,omitempty"`
	AssetEnvironment  *string         `json:"asset_environment,omitempty"`
	AssetBusinessUnit *string         `json:"asset_business_unit,omitempty"`
	Keys              []Key           `json:"keys,omitempty"`
	Libraries         []CryptoLibrary `json:"libraries,omitempty"`
}

// RiskSummary provides an overview of asset risks
type RiskSummary struct {
	TotalAssets      int `json:"total_assets" db:"total_assets"`
	HighRisk         int `json:"high_risk" db:"high_risk"`
	MediumRisk       int `json:"medium_risk" db:"medium_risk"`
	LowRisk          int `json:"low_risk" db:"low_risk"`
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

// AssetInput defines the input structure for creating or updating an asset
type AssetInput struct {
	Hostname        *string                `json:"hostname"`
	IPAddress       *string                `json:"ip_address"`
	Port            *int                   `json:"port"`
	AssetType       string                 `json:"asset_type" binding:"required"`
	OperatingSystem *string                `json:"operating_system"`
	Environment     *string                `json:"environment"`
	BusinessUnit    *string                `json:"business_unit"`
	OwnerEmail      *string                `json:"owner_email"`
	Description     *string                `json:"description"`
	Tags            map[string]interface{} `json:"tags"`
	Metadata        map[string]interface{} `json:"metadata"`
	AssetOwnership  *string                `json:"asset_ownership"`
	// AssetStatus applies to UPDATES only. Asset CREATION ignores it: a new
	// asset's approval status is evaluated server-side from the tenant's network
	// segments (AssetService.evaluateAssetApproval), so no request body can
	// promote an asset to `monitoring` past the approval queue.
	AssetStatus *string `json:"asset_status"`
}

// AssetFacetBucket represents a bucket for asset facets
type AssetFacetBucket struct {
	Key   string `json:"value"`
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
	HasSCT        *bool     `json:"has_sct,omitempty" db:"has_sct"`
	KnownBadCA    *string   `json:"known_bad_ca,omitempty" db:"known_bad_ca"`
	IsEV          *bool     `json:"is_ev,omitempty" db:"is_ev"`
	OCSPStatus    *string   `json:"ocsp_status,omitempty" db:"ocsp_status"`
	OCSPDetail    *string   `json:"ocsp_detail,omitempty" db:"ocsp_detail"`
	CertOwnership *string   `json:"cert_ownership,omitempty" db:"cert_ownership"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
	RelatedAssets []Asset   `json:"related_assets,omitempty"`
	// DeploymentCount is the number of distinct network_assets currently using
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
	HasSCT     *bool  // Certificate Transparency: embedded SCTs present
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
	// (internal | third_party | unknown), via crypto_implementations → network_assets.
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
