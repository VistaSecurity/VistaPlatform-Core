package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Regions, site groups, sites and locations (DCIM row 2.1, ADR-0010 D4,
// DATA_MODEL section 1). A region is geography, a site group a functional
// grouping, a site one place, and a location a position inside one site
// (floor, room, row, cage).

// SiteRef is the compact site that rides on an asset (`site: {id, name, slug}`).
// It scans from the jsonb the asset readers select (assetSiteSQL).
type SiteRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Slug string    `json:"slug"`
}

// Scan implements sql.Scanner over the jsonb (or its text form).
func (r *SiteRef) Scan(src interface{}) error { return scanJSONRef(src, r) }

// Value implements driver.Valuer.
func (r SiteRef) Value() (driver.Value, error) { return json.Marshal(r) }

// LocationRef is the compact location that rides on an asset
// (`location: {id, name, path}`); path is "Site / Floor / Room".
type LocationRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Path string    `json:"path"`
}

// Scan implements sql.Scanner over the jsonb (or its text form).
func (r *LocationRef) Scan(src interface{}) error { return scanJSONRef(src, r) }

// Value implements driver.Valuer.
func (r LocationRef) Value() (driver.Value, error) { return json.Marshal(r) }

func scanJSONRef(src interface{}, dst any) error {
	switch v := src.(type) {
	case nil:
		return nil
	case []byte:
		return json.Unmarshal(v, dst)
	case string:
		return json.Unmarshal([]byte(v), dst)
	}
	return errors.New("unsupported ref source")
}

// RackPlacementRef is the compact rack placement that rides on an asset
// (`rack: {id, name, position, face}`, DCIM row 2.3). Position and Face are nil
// for a device in the rack without a position.
type RackPlacementRef struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Position *float64  `json:"position"`
	Face     *string   `json:"face"`
}

// Scan implements sql.Scanner over the jsonb (or its text form).
func (r *RackPlacementRef) Scan(src interface{}) error { return scanJSONRef(src, r) }

// Value implements driver.Valuer.
func (r RackPlacementRef) Value() (driver.Value, error) { return json.Marshal(r) }

// Region is a row of regions (NetBox dcim/region). SiteCount counts the sites
// directly in it.
type Region struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     uuid.UUID              `json:"tenant_id"`
	Name         string                 `json:"name"`
	Slug         string                 `json:"slug"`
	ParentID     *uuid.UUID             `json:"parent_id"`
	Description  *string                `json:"description"`
	Comments     *string                `json:"comments"`
	SourceKind   string                 `json:"source_kind"`
	SourceRef    *string                `json:"source_ref"`
	CustomFields map[string]interface{} `json:"custom_fields"`
	CreatedBy    *uuid.UUID             `json:"created_by"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	SiteCount    int                    `json:"site_count"`
}

// SiteGroup is a row of site_groups (NetBox dcim/site-group); same shape as
// Region.
type SiteGroup Region

// Site is a row of sites (NetBox dcim/site).
type Site struct {
	ID                uuid.UUID              `json:"id"`
	TenantID          uuid.UUID              `json:"tenant_id"`
	Name              string                 `json:"name"`
	Slug              string                 `json:"slug"`
	OperationalStatus string                 `json:"operational_status"`
	RegionID          *uuid.UUID             `json:"region_id"`
	GroupID           *uuid.UUID             `json:"group_id"`
	Facility          *string                `json:"facility"`
	TimeZone          *string                `json:"time_zone"`
	PhysicalAddress   *string                `json:"physical_address"`
	ShippingAddress   *string                `json:"shipping_address"`
	Latitude          *float64               `json:"latitude"`
	Longitude         *float64               `json:"longitude"`
	BusinessUnitID    *uuid.UUID             `json:"business_unit_id"`
	ASNs              []int64                `json:"asns"`
	ExternalIDs       map[string]interface{} `json:"external_ids"`
	Description       *string                `json:"description"`
	Comments          *string                `json:"comments"`
	SourceKind        string                 `json:"source_kind"`
	SourceRef         *string                `json:"source_ref"`
	CustomFields      map[string]interface{} `json:"custom_fields"`
	CreatedBy         *uuid.UUID             `json:"created_by"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	// Joined names, for lists and the site page.
	RegionName       *string `json:"region_name"`
	GroupName        *string `json:"group_name"`
	BusinessUnitName *string `json:"business_unit_name"`
	// AssetCount counts live assets in the site (every read).
	AssetCount int `json:"asset_count"`
	// Counts is set by the single-site read only.
	Counts *SiteCounts `json:"counts,omitempty"`
}

// SiteCounts are what the site page's Overview shows. Racks is 0 until racks
// exist (row 2.3) — a real zero, there are none to count.
type SiteCounts struct {
	Assets    int `json:"assets"`
	Locations int `json:"locations"`
	Racks     int `json:"racks"`
	Prefixes  int `json:"prefixes"`
	VLANs     int `json:"vlans"`
}

// Location is a row of locations (NetBox dcim/location): a position inside one
// site.
type Location struct {
	ID                uuid.UUID              `json:"id"`
	TenantID          uuid.UUID              `json:"tenant_id"`
	SiteID            uuid.UUID              `json:"site_id"`
	ParentID          *uuid.UUID             `json:"parent_id"`
	Name              string                 `json:"name"`
	Slug              string                 `json:"slug"`
	OperationalStatus string                 `json:"operational_status"`
	Facility          *string                `json:"facility"`
	BusinessUnitID    *uuid.UUID             `json:"business_unit_id"`
	Description       *string                `json:"description"`
	Comments          *string                `json:"comments"`
	SourceKind        string                 `json:"source_kind"`
	SourceRef         *string                `json:"source_ref"`
	CustomFields      map[string]interface{} `json:"custom_fields"`
	CreatedBy         *uuid.UUID             `json:"created_by"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	// Path is "Site / Floor / Room" (public.location_path).
	Path       string `json:"path"`
	AssetCount int    `json:"asset_count"`
	// The floor plan (DCIM gap 9): width (x) by depth (y) in FloorPlanUnit
	// ("m" or "ft"); all three nil when the location has none.
	FloorPlanWidth *float64 `json:"floor_plan_width"`
	FloorPlanDepth *float64 `json:"floor_plan_depth"`
	FloorPlanUnit  *string  `json:"floor_plan_unit"`
}

// presence records which JSON keys a patch carried, so `"x": null` (clear) and
// an absent key (keep) differ.
type presence map[string]bool

func presenceOf(b []byte) (presence, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, err
	}
	p := presence{}
	for k := range probe {
		p[k] = true
	}
	return p, nil
}

// RegionInput is the create/update payload for a region or a site group.
// Update is a patch: absent fields are kept; Has reports presence.
type RegionInput struct {
	Name        *string    `json:"name"`
	Slug        *string    `json:"slug"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Description *string    `json:"description"`
	Comments    *string    `json:"comments"`
	Set         presence   `json:"-"`
}

// Has reports whether the payload carried key.
func (in RegionInput) Has(key string) bool { return in.Set[key] }

// UnmarshalJSON records which keys were present.
func (in *RegionInput) UnmarshalJSON(b []byte) error {
	type plain RegionInput
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	set, err := presenceOf(b)
	if err != nil {
		return err
	}
	p.Set = set
	*in = RegionInput(p)
	return nil
}

// SiteInput is the create/update payload for a site (a patch on update).
type SiteInput struct {
	Name              *string                `json:"name"`
	Slug              *string                `json:"slug"`
	OperationalStatus *string                `json:"operational_status"`
	RegionID          *uuid.UUID             `json:"region_id"`
	GroupID           *uuid.UUID             `json:"group_id"`
	Facility          *string                `json:"facility"`
	TimeZone          *string                `json:"time_zone"`
	PhysicalAddress   *string                `json:"physical_address"`
	ShippingAddress   *string                `json:"shipping_address"`
	Latitude          *float64               `json:"latitude"`
	Longitude         *float64               `json:"longitude"`
	BusinessUnitID    *uuid.UUID             `json:"business_unit_id"`
	ASNs              []int64                `json:"asns"`
	ExternalIDs       map[string]interface{} `json:"external_ids"`
	Description       *string                `json:"description"`
	Comments          *string                `json:"comments"`
	Set               presence               `json:"-"`
}

// Has reports whether the payload carried key.
func (in SiteInput) Has(key string) bool { return in.Set[key] }

// UnmarshalJSON records which keys were present.
func (in *SiteInput) UnmarshalJSON(b []byte) error {
	type plain SiteInput
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	set, err := presenceOf(b)
	if err != nil {
		return err
	}
	p.Set = set
	*in = SiteInput(p)
	return nil
}

// LocationInput is the create/update payload for a location (a patch on
// update). site_id is required on create.
type LocationInput struct {
	SiteID            *uuid.UUID `json:"site_id"`
	ParentID          *uuid.UUID `json:"parent_id"`
	Name              *string    `json:"name"`
	Slug              *string    `json:"slug"`
	OperationalStatus *string    `json:"operational_status"`
	Facility          *string    `json:"facility"`
	BusinessUnitID    *uuid.UUID `json:"business_unit_id"`
	Description       *string    `json:"description"`
	Comments          *string    `json:"comments"`
	// The floor plan (DCIM gap 9): set all three, or null all three to
	// remove the plan.
	FloorPlanWidth *float64 `json:"floor_plan_width"`
	FloorPlanDepth *float64 `json:"floor_plan_depth"`
	FloorPlanUnit  *string  `json:"floor_plan_unit"`
	Set            presence `json:"-"`
}

// Has reports whether the payload carried key.
func (in LocationInput) Has(key string) bool { return in.Set[key] }

// UnmarshalJSON records which keys were present.
func (in *LocationInput) UnmarshalJSON(b []byte) error {
	type plain LocationInput
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	set, err := presenceOf(b)
	if err != nil {
		return err
	}
	p.Set = set
	*in = LocationInput(p)
	return nil
}

// SiteFilters are the list filters for sites.
type SiteFilters struct {
	RegionID *uuid.UUID
	GroupID  *uuid.UUID
	Q        string
}
