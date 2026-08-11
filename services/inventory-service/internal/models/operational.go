package models

import (
	"time"

	"github.com/google/uuid"
)

// LocationFindingSummaryRow is one row from mv_location_finding_summary (per location per environment).
type LocationFindingSummaryRow struct {
	LocationID        uuid.UUID `json:"location_id" db:"location_id"`
	TenantID          uuid.UUID `json:"tenant_id" db:"tenant_id"`
	LocationName      string    `json:"location_name" db:"location_name"`
	LocationType      string    `json:"location_type" db:"location_type"`
	FullPath          *string   `json:"full_path,omitempty" db:"full_path"`
	Environment       string    `json:"environment" db:"environment"`
	AssetCount        int64     `json:"asset_count" db:"asset_count"`
	CryptoConfigCount int64     `json:"crypto_config_count" db:"crypto_config_count"`
	CertificateCount  int64     `json:"certificate_count" db:"certificate_count"`
	CriticalFindings  int64     `json:"critical_findings" db:"critical_findings"`
	HighFindings      int64     `json:"high_findings" db:"high_findings"`
	MediumFindings    int64     `json:"medium_findings" db:"medium_findings"`
	LowFindings       int64     `json:"low_findings" db:"low_findings"`
	ExpiringCerts30D  int64     `json:"expiring_certs_30d" db:"expiring_certs_30d"`
	ExpiredCerts      int64     `json:"expired_certs" db:"expired_certs"`
}

// RemediationQueueRow is one row from mv_remediation_queue.
type RemediationQueueRow struct {
	TenantID               uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	FindingType            string     `json:"finding_type" db:"finding_type"`
	Severity               string     `json:"severity" db:"severity"`
	AssetID                uuid.UUID  `json:"asset_id" db:"asset_id"`
	AssetHostname          *string    `json:"asset_hostname,omitempty" db:"asset_hostname"`
	AssetIP                *string    `json:"asset_ip,omitempty" db:"asset_ip"`
	AssetPort              *int       `json:"asset_port,omitempty" db:"asset_port"`
	LocationName           *string    `json:"location_name,omitempty" db:"location_name"`
	LocationFullPath       *string    `json:"location_full_path,omitempty" db:"location_full_path"`
	Environment            *string    `json:"environment,omitempty" db:"environment"`
	ServiceName            *string    `json:"service_name,omitempty" db:"service_name"`
	CertificateID          *uuid.UUID `json:"certificate_id,omitempty" db:"certificate_id"`
	CryptoImplementationID *uuid.UUID `json:"crypto_implementation_id,omitempty" db:"crypto_implementation_id"`
	DetailText             string     `json:"detail_text" db:"detail_text"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
}

// EnvironmentSummary is environment-level stats for a location (from mv or derived).
type EnvironmentSummary struct {
	Environment       string `json:"environment"`
	AssetCount        int64  `json:"asset_count"`
	CryptoConfigCount int64  `json:"crypto_config_count"`
	CertificateCount  int64  `json:"certificate_count"`
	CriticalFindings  int64  `json:"critical_findings"`
	HighFindings      int64  `json:"high_findings"`
	MediumFindings    int64  `json:"medium_findings"`
	LowFindings       int64  `json:"low_findings"`
	ExpiringCerts30D  int64  `json:"expiring_certs_30d"`
	ExpiredCerts      int64  `json:"expired_certs"`
}

// RemediationTemplate describes a template for generating remediation text.
type RemediationTemplate struct {
	FindingType  string   `json:"finding_type"`
	Severity     string   `json:"severity"`
	Template     string   `json:"template"`
	Placeholders []string `json:"placeholders"`
}

// RemediationQueueFilters are query parameters for the remediation queue.
type RemediationQueueFilters struct {
	Severity    *string    `form:"severity"`
	FindingType *string    `form:"finding_type"`
	LocationID  *uuid.UUID `form:"location_id"`
	Environment *string    `form:"environment"`
	Page        int        `form:"page"`
	PageSize    int        `form:"page_size"`
}
