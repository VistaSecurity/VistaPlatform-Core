package models

import (
	"time"

	"github.com/google/uuid"
)

// Location represents a hierarchical location (datacenter, cloud region, etc.) for operational context.
type Location struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	TenantID      uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Name          string     `json:"name" db:"name"`
	ParentID      *uuid.UUID `json:"parent_id,omitempty" db:"parent_id"`
	LocationType  string     `json:"location_type" db:"location_type"`
	Description   *string    `json:"description,omitempty" db:"description"`
	Address       *string    `json:"address,omitempty" db:"address"`
	City          *string    `json:"city,omitempty" db:"city"`
	StateProvince *string    `json:"state_province,omitempty" db:"state_province"`
	Country       *string    `json:"country,omitempty" db:"country"`
	Latitude      *float64   `json:"latitude,omitempty" db:"latitude"`
	Longitude     *float64   `json:"longitude,omitempty" db:"longitude"`
	Timezone      *string    `json:"timezone,omitempty" db:"timezone"`
	CloudProvider *string    `json:"cloud_provider,omitempty" db:"cloud_provider"`
	CloudRegion   *string    `json:"cloud_region,omitempty" db:"cloud_region"`
	Metadata      JSONB      `json:"metadata,omitempty" db:"metadata"`
	FullPath      string     `json:"full_path" db:"full_path"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
	// Joined/optional for responses
	Children   []Location `json:"children,omitempty"`
	AssetCount *int       `json:"asset_count,omitempty"`
}

// LocationInput is the payload for creating or updating a location.
type LocationInput struct {
	Name          string                 `json:"name" binding:"required"`
	ParentID      *uuid.UUID             `json:"parent_id"`
	LocationType  string                 `json:"location_type" binding:"required"`
	Description   *string                `json:"description"`
	Address       *string                `json:"address"`
	City          *string                `json:"city"`
	StateProvince *string                `json:"state_province"`
	Country       *string                `json:"country"`
	Latitude      *float64               `json:"latitude"`
	Longitude     *float64               `json:"longitude"`
	Timezone      *string                `json:"timezone"`
	CloudProvider *string                `json:"cloud_provider"`
	CloudRegion   *string                `json:"cloud_region"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// LocationFilters are query parameters for listing locations.
type LocationFilters struct {
	ParentID     *uuid.UUID `json:"parent_id" form:"parent_id"`
	LocationType string     `json:"location_type" form:"location_type"`
	Tree         bool       `json:"tree" form:"tree"` // if true, return hierarchical tree
	Page         int        `json:"page" form:"page"`
	PageSize     int        `json:"page_size" form:"page_size"`
}

// LocationSummary includes finding counts for operational views.
type LocationSummary struct {
	Location
	AssetCount        int `json:"asset_count"`
	CryptoConfigCount int `json:"crypto_config_count"`
	CertificateCount  int `json:"certificate_count"`
	CriticalFindings  int `json:"critical_findings"`
	HighFindings      int `json:"high_findings"`
	MediumFindings    int `json:"medium_findings"`
	ExpiringCerts30D  int `json:"expiring_certs_30d"`
	ExpiredCerts      int `json:"expired_certs"`
}
