package services

// Config contexts as an engine spec (DCIM BUILD_PLAN row 5.3; DATA_MODEL §8).
// Column names are the API property names and the OpenAPI schema properties.

import (
	"context"
	"database/sql"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// RouteConfigContexts is the route segment under /dcim.
const RouteConfigContexts = "config-contexts"

// configDimension is one assignment array of a config context: the column, the
// table its ids point at (for write-time validation) and how an asset's facts
// answer it. A dimension whose table has not shipped is not listed -- its
// column exists but is neither writable nor matched, so a row that later adds
// it adds one entry here.
type configDimension struct {
	Column string
	Table  string
	// Values are the ids the asset holds on this dimension.
	Values func(f AssetConfigFacts) []string
}

// configDimensions are the assignment dimensions live on this tree.
var configDimensions = []configDimension{
	{Column: "locations", Table: "locations", Values: func(f AssetConfigFacts) []string { return f.LocationIDs }},
	{Column: "device_types", Table: "device_types", Values: func(f AssetConfigFacts) []string { return one(f.DeviceTypeID) }},
	{Column: "device_roles", Table: "device_roles", Values: func(f AssetConfigFacts) []string { return one(f.DeviceRoleID) }},
	{Column: "platforms", Table: "platforms", Values: func(f AssetConfigFacts) []string { return one(f.PlatformID) }},
	{Column: "business_units", Table: "business_units", Values: func(f AssetConfigFacts) []string { return one(f.BusinessUnitID) }},
	{Column: "tags", Table: "tags", Values: func(f AssetConfigFacts) []string { return f.TagIDs }},
}

// ConfigContextDimensions names the live assignment columns, for the contract tests.
func ConfigContextDimensions() []string {
	out := make([]string, 0, len(configDimensions))
	for _, d := range configDimensions {
		out = append(out, d.Column)
	}
	return out
}

func one(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func prepareConfigContext(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if s, ok := row["name"].(string); ok {
		row["name"] = strings.TrimSpace(s)
	}
	if w, ok := row["weight"]; ok && w != nil {
		if n, err := sqlParam(ipamCol{Name: "weight", Type: colInt}, w); err == nil {
			if i, ok := n.(int64); ok && (i < 0 || i > 32767) {
				return ipamInvalid("weight must be between 0 and 32767")
			}
		}
	}
	for _, d := range configDimensions {
		ids, ok := row[d.Column].([]any)
		if !ok {
			continue
		}
		for _, e := range ids {
			if err := visible(ctx, tx, d.Table, e); err != nil {
				return err
			}
		}
	}
	return nil
}

func configContextSpecs() []*ipamSpec {
	cols := []ipamCol{
		{Name: "name", Type: colText, Required: true},
		{Name: "weight", Type: colInt},
		{Name: "is_active", Type: colBool},
		{Name: "data", Type: colJSON},
	}
	for _, d := range configDimensions {
		cols = append(cols, ipamCol{Name: d.Column, Type: colUUIDArray})
	}
	return []*ipamSpec{{
		Kind: dcim.ObjectKindConfigContext, Table: "config_contexts", Route: RouteConfigContexts,
		Cols:    withSubstrate(cols...),
		Filters: []ipamFilter{{Param: "is_active", Column: "is_active", Type: colBool}},
		Search:  []string{"name", "description"},
		Order:   "t.weight, lower(t.name), t.id",
		Prepare: prepareConfigContext,
	}}
}
