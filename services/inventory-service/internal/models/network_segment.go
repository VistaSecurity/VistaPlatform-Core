package models

import (
	"time"

	"github.com/google/uuid"
)

// NetworkSegment represents a network segment (CIDR, IP range, or domain). Environment is
// required; location is OPTIONAL — a segment is a logical object that may span many sites or
// none, so location is an enrichment default that propagates to matched assets only when set.
type NetworkSegment struct {
	ID                     uuid.UUID  `json:"id" db:"id"`
	TenantID               uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Name                   string     `json:"name" db:"name"`
	SegmentType            string     `json:"segment_type" db:"segment_type"` // cidr, ip_range, domain, cloud_vpc
	Value                  string     `json:"value" db:"value"`
	NetworkType            string     `json:"network_type" db:"network_type"` // private, public, vpn, cloud
	Environment            string     `json:"environment" db:"environment"`   // production, staging, development, test
	LocationID             *uuid.UUID `json:"location_id" db:"location_id"`   // optional; null when the segment isn't pinned to a site
	BusinessUnit           *string    `json:"business_unit,omitempty" db:"business_unit"`
	OwnerEmail             *string    `json:"owner_email,omitempty" db:"owner_email"`
	Description            *string    `json:"description,omitempty" db:"description"`
	IsActive               bool       `json:"is_active" db:"is_active"`
	AutoApproveDiscoveries bool       `json:"auto_approve_discoveries" db:"auto_approve_discoveries"`
	Tags                   JSONB      `json:"tags" db:"tags"`
	Metadata               JSONB      `json:"metadata" db:"metadata"`
	CreatedAt              time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at" db:"updated_at"`
	// Joined for responses (from locations join)
	LocationName     *string `json:"location_name,omitempty" db:"location_name"`
	LocationFullPath *string `json:"location_full_path,omitempty" db:"location_full_path"`
}

// NetworkSegmentInput is the payload for creating or updating a network segment.
type NetworkSegmentInput struct {
	Name                   string                 `json:"name" binding:"required"`
	SegmentType            string                 `json:"segment_type" binding:"required"` // cidr, ip_range, domain, cloud_vpc
	Value                  string                 `json:"value" binding:"required"`
	NetworkType            string                 `json:"network_type" binding:"required"` // private, public, vpn, cloud
	Environment            string                 `json:"environment" binding:"required"`  // production, staging, development, test
	LocationID             *uuid.UUID             `json:"location_id"`                     // optional — omit/null for WAN/VPN/multi-region segments
	BusinessUnit           *string                `json:"business_unit"`
	OwnerEmail             *string                `json:"owner_email"`
	Description            *string                `json:"description"`
	IsActive               *bool                  `json:"is_active"`
	AutoApproveDiscoveries *bool                  `json:"auto_approve_discoveries"` // nil on update = keep current; nil on create = false. A plain bool here let any client that omitted the field silently wipe it.
	Tags                   map[string]interface{} `json:"tags"`
	Metadata               map[string]interface{} `json:"metadata"`
}

// NetworkSegmentFilters are query parameters for listing network segments.
type NetworkSegmentFilters struct {
	IsActive    *bool      `json:"is_active" form:"is_active"`
	Environment string     `json:"environment" form:"environment"`
	LocationID  *uuid.UUID `json:"location_id" form:"location_id"`
	Page        int        `json:"page" form:"page"`
	PageSize    int        `json:"page_size" form:"page_size"`
}

// ClassifyAssetRequest is the body for POST network-segments/classify-asset.
type ClassifyAssetRequest struct {
	IPAddress *string `json:"ip_address"`
	Hostname  *string `json:"hostname"`
}
