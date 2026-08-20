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
	// AutoApproveSources names which discovery sources this segment's
	// auto-approval covers. Persisted inside Metadata (see
	// AutoApproveSourcesKey) rather than in its own column, and hydrated on
	// read — see AutoApproveSourcesFromMetadata for why "absent" means
	// sensor-only.
	AutoApproveSources []string  `json:"auto_approve_sources" db:"-"`
	Tags               JSONB     `json:"tags" db:"tags"`
	Metadata           JSONB     `json:"metadata" db:"metadata"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
	// Joined for responses (from locations join)
	LocationName     *string `json:"location_name,omitempty" db:"location_name"`
	LocationFullPath *string `json:"location_full_path,omitempty" db:"location_full_path"`
}

// NetworkSegmentInput is the payload for creating or updating a network segment.
type NetworkSegmentInput struct {
	Name                   string     `json:"name" binding:"required"`
	SegmentType            string     `json:"segment_type" binding:"required"` // cidr, ip_range, domain, cloud_vpc
	Value                  string     `json:"value" binding:"required"`
	NetworkType            string     `json:"network_type" binding:"required"` // private, public, vpn, cloud
	Environment            string     `json:"environment" binding:"required"`  // production, staging, development, test
	LocationID             *uuid.UUID `json:"location_id"`                     // optional — omit/null for WAN/VPN/multi-region segments
	BusinessUnit           *string    `json:"business_unit"`
	OwnerEmail             *string    `json:"owner_email"`
	Description            *string    `json:"description"`
	IsActive               *bool      `json:"is_active"`
	AutoApproveDiscoveries *bool      `json:"auto_approve_discoveries"` // nil on update = keep current; nil on create = false. A plain bool here let any client that omitted the field silently wipe it.
	// AutoApproveSources is which discovery sources auto-approval covers for
	// this segment: any of "sensor", "cloud". nil (omitted) keeps the persisted
	// value on update and defaults to sensor-only on create — the same
	// omitted-means-keep discipline as AutoApproveDiscoveries, for the same
	// reason: a client that does not know about the field must not silently
	// widen or narrow a tenant's approval policy.
	AutoApproveSources []string               `json:"auto_approve_sources"`
	Tags               map[string]interface{} `json:"tags"`
	Metadata           map[string]interface{} `json:"metadata"`
}

// Discovery sources a segment's auto-approval can cover.
//
// These are the API/UI vocabulary. shared/approval's rule conditions use an
// older wire vocabulary ("sensor_discoveries" / "cloud_discovery" / "all");
// ManageAutoApprovalRules translates between the two in exactly one place.
const (
	AutoApproveSourceSensor = "sensor"
	AutoApproveSourceCloud  = "cloud"
)

// AutoApproveSourcesKey is the network_segments.metadata key the per-source
// setting is stored under.
const AutoApproveSourcesKey = "auto_approve_sources"

// NormalizeAutoApproveSources filters a caller-supplied list down to the known
// sources, de-duplicated and in a stable order.
//
// An empty or entirely-unrecognized list normalizes to sensor-only rather than
// to "no sources": a segment with auto-approve ON and no source at all is a
// setting that silently does nothing, which is the class of bug this field
// exists to end. A tenant who wants nothing auto-approved turns auto-approve
// off.
func NormalizeAutoApproveSources(in []string) []string {
	var sensor, cloud bool
	for _, v := range in {
		switch v {
		case AutoApproveSourceSensor:
			sensor = true
		case AutoApproveSourceCloud:
			cloud = true
		}
	}
	if !sensor && !cloud {
		sensor = true
	}
	out := make([]string, 0, 2)
	if sensor {
		out = append(out, AutoApproveSourceSensor)
	}
	if cloud {
		out = append(out, AutoApproveSourceCloud)
	}
	return out
}

// AutoApproveSourcesFromMetadata reads the per-source setting off a segment's
// metadata.
//
// A segment with no stored value — every segment created before the setting
// existed — reads back as sensor-only. That default is the whole migration
// story: a tenant who switched auto-approve on when it covered sensor
// discoveries and nothing else must not find cloud assets auto-approving after
// an upgrade they did not ask for. Cloud coverage is opt-in, per segment.
func AutoApproveSourcesFromMetadata(meta JSONB) []string {
	raw, ok := meta[AutoApproveSourcesKey]
	if !ok {
		return []string{AutoApproveSourceSensor}
	}
	// []interface{} is what a JSONB round-trip yields; []string is what an
	// in-process caller that just stamped the value holds.
	var vals []string
	switch list := raw.(type) {
	case []interface{}:
		for _, v := range list {
			if s, ok := v.(string); ok {
				vals = append(vals, s)
			}
		}
	case []string:
		vals = list
	default:
		return []string{AutoApproveSourceSensor}
	}
	return NormalizeAutoApproveSources(vals)
}

// AutoApproveSourcesInclude reports whether a stored source list covers src.
func AutoApproveSourcesInclude(sources []string, src string) bool {
	for _, s := range sources {
		if s == src {
			return true
		}
	}
	return false
}

// HydrateAutoApproveSources fills AutoApproveSources from Metadata. Called
// wherever a segment is read back for a caller or for rule generation, so the
// field is never empty in a response.
func (s *NetworkSegment) HydrateAutoApproveSources() {
	if s == nil {
		return
	}
	s.AutoApproveSources = AutoApproveSourcesFromMetadata(s.Metadata)
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
//
// The cloud_* fields describe a resource discovered through a cloud provider
// API, which frequently has no routable address of its own (a KMS key, a
// bucket, a managed database). For those the IP is a placeholder and cannot
// answer "whose network is this on"; the cloud account/region/VPC can, and it
// is the same key inventory-service already uses to attribute the imported
// asset to a segment (FindOrCreateCloudSegment).
type ClassifyAssetRequest struct {
	IPAddress     *string `json:"ip_address"`
	Hostname      *string `json:"hostname"`
	CloudProvider string  `json:"cloud_provider"`
	CloudRegion   string  `json:"cloud_region"`
	VPCID         string  `json:"vpc_id"`
	Environment   string  `json:"environment"`
}
