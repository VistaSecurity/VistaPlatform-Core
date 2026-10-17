package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BusinessUnitRef is the compact form of a Business Unit that rides on an asset
// (`business_unit: {id, name, slug}`). It scans from the jsonb the asset readers
// select (assetBusinessUnitSQL), so a reader that already scans a nullable text
// column only changes the SQL fragment, not its scan shape.
type BusinessUnitRef struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Slug string    `json:"slug"`
}

// Scan implements sql.Scanner over the jsonb (or its text form).
func (r *BusinessUnitRef) Scan(src interface{}) error {
	switch v := src.(type) {
	case nil:
		return nil
	case []byte:
		return json.Unmarshal(v, r)
	case string:
		return json.Unmarshal([]byte(v), r)
	}
	return fmt.Errorf("business unit ref: cannot scan %T", src)
}

// Value implements driver.Valuer so a ref can be bound back as jsonb.
func (r BusinessUnitRef) Value() (driver.Value, error) { return json.Marshal(r) }

// BusinessUnit is a row of business_units (NetBox Tenant, ADR-0010 D2).
type BusinessUnit struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	TenantID     uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	Name         string                 `json:"name" db:"name"`
	Slug         string                 `json:"slug" db:"slug"`
	ParentID     *uuid.UUID             `json:"parent_id" db:"parent_id"`
	Description  *string                `json:"description" db:"description"`
	Comments     *string                `json:"comments" db:"comments"`
	ExternalIDs  map[string]interface{} `json:"external_ids" db:"-"`
	SourceKind   string                 `json:"source_kind" db:"source_kind"`
	SourceRef    *string                `json:"source_ref" db:"source_ref"`
	CustomFields map[string]interface{} `json:"custom_fields" db:"-"`
	CreatedBy    *uuid.UUID             `json:"created_by" db:"created_by"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" db:"updated_at"`
	// AssetCount is the number of live assets assigned to the unit (list and
	// detail reads only).
	AssetCount int `json:"asset_count" db:"asset_count"`
}

// BusinessUnitInput is the create/update payload. Update is a patch: absent
// fields are kept; `parent_id: null` is distinguished from absent by ParentSet.
type BusinessUnitInput struct {
	Name        *string                `json:"name"`
	Slug        *string                `json:"slug"`
	ParentID    *uuid.UUID             `json:"parent_id"`
	ParentSet   bool                   `json:"-"`
	Description *string                `json:"description"`
	Comments    *string                `json:"comments"`
	ExternalIDs map[string]interface{} `json:"external_ids"`
	// CustomFields (DCIM row 5.1): on create, the values; on update, the
	// fields to change (the others are kept, as NetBox's PATCH).
	CustomFields map[string]interface{} `json:"custom_fields"`
}

// UnmarshalJSON records whether parent_id was present, so a PATCH can clear it.
func (in *BusinessUnitInput) UnmarshalJSON(b []byte) error {
	type plain BusinessUnitInput
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	_, p.ParentSet = probe["parent_id"]
	*in = BusinessUnitInput(p)
	return nil
}
