package models

import (
	"github.com/google/uuid"
	"time"
)

// Asset represents an infrastructure asset
type Asset struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	TenantID          uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Hostname          *string                `json:"hostname" db:"hostname"`
	IPAddress         *string                `json:"ip_address" db:"ip_address"`
	Port              *int                   `json:"port" db:"port"`
	AssetType         string                 `json:"asset_type" db:"asset_type"`
	OperatingSystem   *string                `json:"operating_system" db:"operating_system"`
	Environment       *string                `json:"environment" db:"environment"`
	BusinessUnit      *string                `json:"business_unit" db:"business_unit"`
	OwnerEmail        *string                `json:"owner_email" db:"owner_email"`
	Description       *string                `json:"description" db:"description"`
	Tags              map[string]interface{} `json:"tags" db:"tags"`
	Metadata          map[string]interface{} `json:"metadata" db:"metadata"`
	FirstDiscoveredAt time.Time              `json:"first_discovered_at" db:"first_discovered_at"`
	LastSeenAt        time.Time              `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt         *time.Time             `json:"deleted_at" db:"deleted_at"`
	RiskScore         int                    `json:"risk_score" db:"risk_score"`
	RiskLevel         string                 `json:"risk_level" db:"risk_level"`
	HighestRisk       *int                   `json:"highest_risk" db:"highest_risk"`
}

// CryptoImplementation represents a crypto implementation
type CryptoImplementation struct {
	ID                   uuid.UUID              `json:"id" db:"id"`
	TenantID             uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	AssetID              uuid.UUID              `json:"asset_id" db:"asset_id"`
	Protocol             string                 `json:"protocol" db:"protocol"`
	ProtocolVersion      *string                `json:"protocol_version" db:"protocol_version"`
	CipherSuite          *string                `json:"cipher_suite" db:"cipher_suite"`
	KeyExchangeAlgorithm *string                `json:"key_exchange_algorithm" db:"key_exchange_algorithm"`
	SignatureAlgorithm   *string                `json:"signature_algorithm" db:"signature_algorithm"`
	SymmetricEncryption  *string                `json:"symmetric_encryption" db:"symmetric_encryption"`
	HashAlgorithm        *string                `json:"hash_algorithm" db:"hash_algorithm"`
	KeySize              *int                   `json:"key_size" db:"key_size"`
	CertificateID        *string                `json:"certificate_id" db:"certificate_id"`
	DiscoveryMethod      string                 `json:"discovery_method" db:"discovery_method"`
	ConfidenceScore      float64                `json:"confidence_score" db:"confidence_score"`
	SourceSensorID       *string                `json:"source_sensor_id" db:"source_sensor_id"`
	RawData              map[string]interface{} `json:"raw_data" db:"raw_data"`
	RiskScore            int                    `json:"risk_score" db:"risk_score"`
	ComplianceStatus     map[string]interface{} `json:"compliance_status" db:"compliance_status"`
	FirstDiscoveredAt    time.Time              `json:"first_discovered_at" db:"first_discovered_at"`
	LastVerifiedAt       time.Time              `json:"last_verified_at" db:"last_verified_at"`
	CreatedAt            time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt            *time.Time             `json:"deleted_at" db:"deleted_at"`
	RiskLevel            string                 `json:"risk_level" db:"risk_level"`
	RiskFactors          []string               `json:"risk_factors" db:"risk_factors"`
}

// RiskSummary represents a risk summary
type RiskSummary struct {
	TotalAssets      int `json:"total_assets"`
	HighRisk         int `json:"high_risk"`
	MediumRisk       int `json:"medium_risk"`
	LowRisk          int `json:"low_risk"`
	UnknownRisk      int `json:"unknown_risk"`
	TotalCrypto      int `json:"total_crypto"`
	CriticalFindings int `json:"critical_findings"`
}

// AssetFilters represents filters for asset queries
type AssetFilters struct {
	Search           *string  `json:"search"`
	AssetType        []string `json:"asset_type"`
	Environment      []string `json:"environment"`
	RiskLevel        []string `json:"risk_level"`
	Protocol         []string `json:"protocol"`
	BusinessUnit     []string `json:"business_unit"`
	OperatingSystem  []string `json:"operating_system"`
	OwnerEmail       []string `json:"owner_email"`
	LocationRegion   []string `json:"location_region"`
	LocationSite     []string `json:"location_site"`
	LocationBuilding []string `json:"location_building"`
	LocationZone     []string `json:"location_zone"`
	Page             *int     `json:"page"`
	PageSize         *int     `json:"page_size"`
	SortBy           *string  `json:"sort_by"`
	SortOrder        *string  `json:"sort_order"`
}

// AssetsResponse represents a paginated response of assets
type AssetsResponse struct {
	Assets     []Asset `json:"assets"`
	Pagination struct {
		Page       int  `json:"page"`
		PageSize   int  `json:"page_size"`
		Total      int  `json:"total"`
		TotalPages int  `json:"total_pages"`
		HasNext    bool `json:"has_next"`
		HasPrev    bool `json:"has_prev"`
	} `json:"pagination"`
}
