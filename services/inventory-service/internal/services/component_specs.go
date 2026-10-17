package services

// The asset component tables as engine specs (DCIM BUILD_PLAN row 3.1;
// ADR-0010 D3/D9; DATA_MODEL §2.4): console ports, console server ports, rear
// ports, front ports, device bays, and (API only, D9) power ports and power
// outlets. Interfaces keep their own service (interface_service.go); these seven
// share the IPAM object engine, so they get its CRUD, tenant-scoped
// transactions, change recording and error mapping.
//
// Column names are binding: they are the API property names, the OpenAPI schema
// properties (component_contract_test.go) and the table's column list.
// cable_id / cable_end are in the table (and so in every row) but are not
// writable here: cables arrive with row 3.2 and write their own side.
// module_id is the module that declared the component; module_service.go
// (row 2.4) writes it when a module is installed and clears it on removal.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// The seven component route segments, in DATA_MODEL §2.4's order.
const (
	ComponentConsolePort       = "console-ports"
	ComponentConsoleServerPort = "console-server-ports"
	ComponentFrontPort         = "front-ports"
	ComponentRearPort          = "rear-ports"
	ComponentDeviceBay         = "device-bays"
	ComponentPowerPort         = "power-ports"
	ComponentPowerOutlet       = "power-outlets"
)

// ComponentRoutes lists the component route segments the service serves.
func ComponentRoutes() []string {
	return []string{ComponentConsolePort, ComponentConsoleServerPort, ComponentFrontPort, ComponentRearPort,
		ComponentDeviceBay, ComponentPowerPort, ComponentPowerOutlet}
}

// componentTemplateRoute is the template kind a component kind is made from.
var componentTemplateRoute = map[string]string{
	ComponentConsolePort:       TemplateConsolePort,
	ComponentConsoleServerPort: TemplateConsoleServerPort,
	ComponentFrontPort:         TemplateFrontPort,
	ComponentRearPort:          TemplateRearPort,
	ComponentDeviceBay:         TemplateDeviceBay,
	ComponentPowerPort:         TemplatePowerPort,
	ComponentPowerOutlet:       TemplatePowerOutlet,
}

// rowInt reads a number out of a decoded row or body (json.Number from the
// engine's decoder, float64 from a hand-built map).
func rowInt(v any) (int, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := strconv.Atoi(n.String())
		return i, err == nil
	}
	return 0, false
}

func componentCommon(extra ...ipamCol) []ipamCol {
	cols := []ipamCol{
		{Name: "asset_id", Type: colUUID, Required: true},
		// module_id is the module that declared the component (row 2.4,
		// module_service.go); the service writes it, a caller never does.
		{Name: "module_id", Type: colUUID, Computed: true},
		{Name: "name", Type: colText, Required: true},
		{Name: "label", Type: colText},
	}
	cols = append(cols, extra...)
	cols = append(cols, ipamCol{Name: "mark_connected", Type: colBool})
	cols = append(cols, substrateCols...)
	cols = append(cols, externalIDsCol)
	return append(cols, lifecycleCols...)
}

// preparePortAsset is the check every component shares: the asset is one of
// the tenant's live assets and, once written, a component never moves to
// another asset (its identity is (asset, name) and a cable may hang off it).
func preparePortAsset(ctx context.Context, tx *sql.Tx, table string, id uuid.UUID, tenant uuid.UUID, row map[string]any) error {
	name, _ := row["name"].(string)
	if len(name) < 1 || len(name) > 64 {
		return ipamInvalid("name must be 1 to 64 characters")
	}
	asset := fmt.Sprint(row["asset_id"])
	if id != uuid.Nil {
		var cur string
		if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT asset_id::text FROM public.%s WHERE id = $1`, table), id).Scan(&cur); err != nil {
			return mapIPAMError(err, false)
		}
		if cur != asset {
			return ipamInvalid("asset_id cannot be changed; delete the component and declare it on the other asset")
		}
	}
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2::uuid AND deleted_at IS NULL)`,
		tenant, asset).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("no such asset %s", asset)
	}
	return nil
}

// sameAssetRef checks row[col] names a row of table on the same asset.
func sameAssetRef(ctx context.Context, tx *sql.Tx, table, col string, row map[string]any) error {
	ref := row[col]
	if isEmpty(ref) {
		return nil
	}
	var ok bool
	q := fmt.Sprintf(`SELECT EXISTS (SELECT 1 FROM public.%s WHERE id = $1::uuid AND asset_id = $2::uuid)`, table)
	if err := tx.QueryRowContext(ctx, q, fmt.Sprint(ref), fmt.Sprint(row["asset_id"])).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("%s must name a %s of the same asset", col, table[:len(table)-1])
	}
	return nil
}

func componentSpec(kind dcim.ObjectKind, route string, cols []ipamCol, filters []ipamFilter,
	prep func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error) *ipamSpec {
	table := route
	table = replaceDash(table)
	return &ipamSpec{
		Kind: kind, Table: table, Route: route, Lifecycle: true,
		Cols: cols,
		Filters: append([]ipamFilter{
			{Param: "asset_id", Column: "asset_id", Type: colUUID},
			{Param: "name", Column: "name", Type: colText},
			{Param: "status", Column: "status", Type: colText},
		}, filters...),
		Search: []string{"name", "label", "description"},
		// Natural order (Port2 before Port10), as the interface list sorts.
		Order: `regexp_replace(t.name, '\d+', '#', 'g'),
			array(SELECT lpad(x[1], 12, '0') FROM regexp_matches(t.name, '(\d+)', 'g') AS x), t.name, t.id`,
		Prepare: func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
			if err := preparePortAsset(ctx, tx, table, id, tenant, row); err != nil {
				return err
			}
			if err := refuseMarkConnectedWithCable(row); err != nil {
				return err
			}
			if err := normaliseColor(row, "color"); err != nil {
				return err
			}
			if prep != nil {
				return prep(ctx, tx, tenant, id, row)
			}
			return nil
		},
		// Cable paths run through front and rear ports (row 3.2): a mapping
		// change, a new front port on a rear position, or a deleted component
		// moves every path through it.
		AfterWrite: func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
			return componentCableAfterWrite(ctx, tx, tenant, kind, pre, post)
		},
	}
}

func withAfterWrite(sp *ipamSpec, fn func(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error) *ipamSpec {
	sp.AfterWrite = fn
	return sp
}

func replaceDash(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c == '-' {
			b[i] = '_'
		}
	}
	return string(b)
}

func componentSpecs() []*ipamSpec {
	consolePrep := func(_ context.Context, _ *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
		if n, ok := rowInt(row["speed"]); ok && n < 1 {
			return ipamInvalid("speed must be positive")
		}
		return validType(row, "type", false, func(s string) bool { _, ok := dcim.ParseConsolePortType(s); return ok })
	}
	consoleCols := componentCommon(ipamCol{Name: "type", Type: colText}, ipamCol{Name: "speed", Type: colInt})
	typeFilter := []ipamFilter{{Param: "type", Column: "type", Type: colText}}
	return []*ipamSpec{
		componentSpec(dcim.ObjectKindConsolePort, ComponentConsolePort, consoleCols, typeFilter, consolePrep),
		componentSpec(dcim.ObjectKindConsoleServerPort, ComponentConsoleServerPort, consoleCols, typeFilter, consolePrep),
		componentSpec(dcim.ObjectKindFrontPort, ComponentFrontPort, componentCommon(
			ipamCol{Name: "type", Type: colText, Required: true},
			ipamCol{Name: "color", Type: colText},
			ipamCol{Name: "rear_port_id", Type: colUUID, Required: true},
			ipamCol{Name: "rear_port_position", Type: colInt},
		), append([]ipamFilter{{Param: "rear_port_id", Column: "rear_port_id", Type: colUUID}}, typeFilter...), prepareFrontPort),
		componentSpec(dcim.ObjectKindRearPort, ComponentRearPort, componentCommon(
			ipamCol{Name: "type", Type: colText, Required: true},
			ipamCol{Name: "color", Type: colText},
			ipamCol{Name: "positions", Type: colInt},
		), typeFilter, prepareRearPort),
		withAfterWrite(componentSpec(dcim.ObjectKindDeviceBay, ComponentDeviceBay, componentCommon(
			ipamCol{Name: "installed_asset_id", Type: colUUID},
		), []ipamFilter{{Param: "installed_asset_id", Column: "installed_asset_id", Type: colUUID}}, prepareDeviceBay),
			syncDeviceBayChild),
		componentSpec(dcim.ObjectKindPowerPort, ComponentPowerPort, componentCommon(
			ipamCol{Name: "type", Type: colText},
			ipamCol{Name: "maximum_draw", Type: colInt},
			ipamCol{Name: "allocated_draw", Type: colInt},
		), typeFilter, preparePowerPort),
		componentSpec(dcim.ObjectKindPowerOutlet, ComponentPowerOutlet, componentCommon(
			ipamCol{Name: "type", Type: colText},
			ipamCol{Name: "power_port_id", Type: colUUID},
			ipamCol{Name: "feed_leg", Type: colText},
		), append([]ipamFilter{{Param: "power_port_id", Column: "power_port_id", Type: colUUID}}, typeFilter...), preparePowerOutlet),
	}
}

func portType(row map[string]any) error {
	return validType(row, "type", true, func(s string) bool { _, ok := dcim.ParsePortType(s); return ok })
}

func prepareRearPort(ctx context.Context, tx *sql.Tx, _, id uuid.UUID, row map[string]any) error {
	if err := portType(row); err != nil {
		return err
	}
	pos, ok := rowInt(row["positions"])
	if !ok {
		return nil // the column default (1) applies on create; an update keeps the stored value
	}
	if pos < 1 || pos > 1024 {
		return ipamInvalid("positions must be between 1 and 1024")
	}
	// Shrinking a rear port below a mapped front port would orphan the mapping.
	if id != uuid.Nil {
		var max sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT max(rear_port_position) FROM front_ports WHERE rear_port_id = $1`, id).Scan(&max); err != nil {
			return mapIPAMError(err, false)
		}
		if max.Valid && int(max.Int64) > pos {
			return ipamInvalid("positions cannot be less than %d: a front port is mapped to that position", max.Int64)
		}
	}
	return nil
}

func prepareFrontPort(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if err := portType(row); err != nil {
		return err
	}
	if isEmpty(row["rear_port_id"]) {
		return ipamInvalid("rear_port_id is required")
	}
	if err := sameAssetRef(ctx, tx, "rear_ports", "rear_port_id", row); err != nil {
		return err
	}
	pos := 1
	if p, ok := rowInt(row["rear_port_position"]); ok {
		pos = p
	} else {
		row["rear_port_position"] = json.Number("1")
	}
	var positions int
	if err := tx.QueryRowContext(ctx, `SELECT positions FROM rear_ports WHERE id = $1::uuid`, fmt.Sprint(row["rear_port_id"])).Scan(&positions); err != nil {
		return mapIPAMError(err, false)
	}
	if pos < 1 || pos > positions {
		return ipamInvalid("rear_port_position %d is outside the rear port's %d position(s)", pos, positions)
	}
	return nil
}

func prepareDeviceBay(ctx context.Context, tx *sql.Tx, tenant, _ uuid.UUID, row map[string]any) error {
	inst := row["installed_asset_id"]
	if isEmpty(inst) {
		row["installed_asset_id"] = nil
		return nil
	}
	if fmt.Sprint(inst) == fmt.Sprint(row["asset_id"]) {
		return ipamInvalid("an asset cannot be installed in its own device bay")
	}
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2::uuid AND deleted_at IS NULL)`,
		tenant, fmt.Sprint(inst)).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("no such asset %v", inst)
	}
	return nil
}

func preparePowerPort(_ context.Context, _ *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if err := validType(row, "type", false, func(s string) bool { _, ok := dcim.ParsePowerPortType(s); return ok }); err != nil {
		return err
	}
	max, hasMax := rowInt(row["maximum_draw"])
	alloc, hasAlloc := rowInt(row["allocated_draw"])
	if hasMax && hasAlloc && alloc > max {
		return ipamInvalid("allocated_draw (%d) cannot exceed maximum_draw (%d)", alloc, max)
	}
	return nil
}

func preparePowerOutlet(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if err := validType(row, "type", false, func(s string) bool { _, ok := dcim.ParsePowerOutletType(s); return ok }); err != nil {
		return err
	}
	if err := oneOf(row, "feed_leg", []string{"A", "B", "C"}); err != nil {
		return err
	}
	return sameAssetRef(ctx, tx, "power_ports", "power_port_id", row)
}

// ComponentObjects describes every component kind for the contract tests:
// table, vocabulary kind, writable and create-required columns.
func ComponentObjects() []IPAMObjectInfo {
	var out []IPAMObjectInfo
	for _, sp := range componentSpecs() {
		info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
		for _, c := range sp.Cols {
			if c.Computed {
				continue
			}
			info.Writable = append(info.Writable, c.Name)
			if c.Required {
				info.Required = append(info.Required, c.Name)
			}
		}
		out = append(out, info)
	}
	return out
}
