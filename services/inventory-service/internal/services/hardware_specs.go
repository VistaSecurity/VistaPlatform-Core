package services

// The hardware objects of DCIM BUILD_PLAN row 2.4 (ADR-0010 D4; DATA_MODEL §2)
// as engine specs: module bays, modules, inventory item roles, inventory items
// and virtual chassis. They share the IPAM object engine (ipam_engine.go), so
// each gets its CRUD, tenant-scoped transactions, change recording and error
// mapping; what the schema cannot say is each spec's hooks below and in
// module_service.go / inventory_item_service.go / virtual_chassis_service.go.
//
// Column names are binding: they are the API property names, the OpenAPI
// schema properties (hardware_contract_test.go) and the table's column list.
// Computed columns are written by the service, never by a caller: a module
// bay's module_id (the module that carries a nested bay), a module's asset_id
// (its bay's asset).

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// The hardware route segments under /dcim.
const (
	HardwareModuleBay         = "module-bays"
	HardwareModule            = "modules"
	HardwareInventoryItemRole = "inventory-item-roles"
	HardwareInventoryItem     = "inventory-items"
	HardwareVirtualChassis    = "virtual-chassis"
)

// HardwareRoutes lists the hardware route segments, in order.
func HardwareRoutes() []string {
	return []string{HardwareModuleBay, HardwareModule, HardwareInventoryItemRole, HardwareInventoryItem, HardwareVirtualChassis}
}

// hardwareAssetRoutes are the hardware kinds an asset owns (served under
// /dcim/assets/{id}/{kind} too).
var hardwareAssetRoutes = map[string]bool{HardwareModuleBay: true, HardwareModule: true, HardwareInventoryItem: true}

// moduleOperationalStatuses is NetBox's ModuleStatusChoices
// (modules_operational_status_check).
var moduleOperationalStatuses = []string{"offline", "active", "planned", "staged", "failed", "decommissioning"}

// inventoryComponentKinds are the object kinds an inventory item may name as
// the component it is (inventory_items_component_kind_check), each with its
// table.
var inventoryComponentKinds = map[string]string{
	"interface": "interfaces", "module": "modules",
	"console_port": "console_ports", "console_server_port": "console_server_ports",
	"front_port": "front_ports", "rear_port": "rear_ports",
	"power_port": "power_ports", "power_outlet": "power_outlets",
}

func lifecycleSubstrate(cols ...ipamCol) []ipamCol {
	cols = append(cols, substrateCols...)
	cols = append(cols, externalIDsCol)
	return append(cols, lifecycleCols...)
}

// naturalNameOrder sorts Port2 before Port10, as the component lists do.
const naturalNameOrder = `regexp_replace(t.name, '\d+', '#', 'g'),
			array(SELECT lpad(x[1], 12, '0') FROM regexp_matches(t.name, '(\d+)', 'g') AS x), t.name, t.id`

func hardwareSpecs() []*ipamSpec {
	assetFilters := func(extra ...ipamFilter) []ipamFilter {
		return append([]ipamFilter{
			{Param: "asset_id", Column: "asset_id", Type: colUUID},
			{Param: "status", Column: "status", Type: colText},
		}, extra...)
	}
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindModuleBay, Table: "module_bays", Route: HardwareModuleBay, Lifecycle: true,
			Cols: lifecycleSubstrate(
				ipamCol{Name: "asset_id", Type: colUUID, Required: true},
				ipamCol{Name: "module_id", Type: colUUID, Computed: true},
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "label", Type: colText},
				ipamCol{Name: "position", Type: colText},
			),
			Filters: assetFilters(
				ipamFilter{Param: "name", Column: "name", Type: colText},
				ipamFilter{Param: "module_id", Column: "module_id", Type: colUUID},
			),
			Search:  []string{"name", "label", "position", "description"},
			Order:   naturalNameOrder,
			Prepare: prepareModuleBay,
		},
		{
			Kind: dcim.ObjectKindModule, Table: "modules", Route: HardwareModule, Lifecycle: true,
			Cols: lifecycleSubstrate(
				ipamCol{Name: "asset_id", Type: colUUID, Computed: true},
				ipamCol{Name: "module_bay_id", Type: colUUID, Required: true},
				ipamCol{Name: "module_type_id", Type: colUUID, Required: true},
				ipamCol{Name: "operational_status", Type: colText},
				ipamCol{Name: "serial", Type: colText},
				ipamCol{Name: "asset_tag", Type: colText},
			),
			Filters: assetFilters(
				ipamFilter{Param: "module_bay_id", Column: "module_bay_id", Type: colUUID},
				ipamFilter{Param: "module_type_id", Column: "module_type_id", Type: colUUID},
				ipamFilter{Param: "serial", Column: "serial", Type: colText},
			),
			Search:       []string{"serial", "asset_tag", "description"},
			Order:        "t.created_at, t.id",
			Prepare:      prepareModule,
			BeforeDelete: beforeModuleDelete,
		},
		{
			Kind: dcim.ObjectKindInventoryItemRole, Table: "inventory_item_roles", Route: HardwareInventoryItemRole, Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "color", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}, {Param: "scope", Custom: scopeFilter}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
				if err := prepareSlug(ctx, tx, tenant, id, row); err != nil {
					return err
				}
				return normaliseColor(row, "color")
			},
		},
		{
			Kind: dcim.ObjectKindInventoryItem, Table: "inventory_items", Route: HardwareInventoryItem, Lifecycle: true,
			Cols: lifecycleSubstrate(
				ipamCol{Name: "asset_id", Type: colUUID, Required: true},
				ipamCol{Name: "parent_id", Type: colUUID},
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "label", Type: colText},
				ipamCol{Name: "role_id", Type: colUUID},
				ipamCol{Name: "manufacturer_id", Type: colUUID},
				ipamCol{Name: "part_id", Type: colText},
				ipamCol{Name: "serial", Type: colText},
				ipamCol{Name: "asset_tag", Type: colText},
				ipamCol{Name: "discovered", Type: colBool},
				ipamCol{Name: "component_kind", Type: colText},
				ipamCol{Name: "component_id", Type: colUUID},
			),
			Filters: assetFilters(
				ipamFilter{Param: "name", Column: "name", Type: colText},
				ipamFilter{Param: "parent_id", Column: "parent_id", Type: colUUID},
				ipamFilter{Param: "role_id", Column: "role_id", Type: colUUID},
				ipamFilter{Param: "serial", Column: "serial", Type: colText},
				ipamFilter{Param: "discovered", Column: "discovered", Type: colBool},
				ipamFilter{Param: "component_kind", Column: "component_kind", Type: colText},
			),
			Search:  []string{"name", "label", "part_id", "serial", "description"},
			Order:   naturalNameOrder,
			Prepare: prepareInventoryItem,
		},
		{
			Kind: dcim.ObjectKindVirtualChassis, Table: "virtual_chassis", Route: HardwareVirtualChassis,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "domain", Type: colText},
				ipamCol{Name: "master_asset_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "name", Column: "name", Type: colText},
				{Param: "master_asset_id", Column: "master_asset_id", Type: colUUID},
			},
			Search:       []string{"name", "domain", "description"},
			Order:        "lower(t.name), t.id",
			Prepare:      prepareVirtualChassis,
			AfterWrite:   afterVirtualChassisWrite,
			BeforeDelete: beforeVirtualChassisDelete,
		},
	}
}

// prepareModuleBay: the asset's own, never moved; a position NetBox allows
// (1-30 characters).
func prepareModuleBay(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if err := preparePortAsset(ctx, tx, "module_bays", id, tenant, row); err != nil {
		return err
	}
	if p, ok := row["position"].(string); ok && (len(p) < 1 || len(p) > 30) {
		if p == "" {
			row["position"] = nil
			return nil
		}
		return ipamInvalid("position must be 1 to 30 characters")
	}
	return nil
}

// prepareModule: the bay is the tenant's and gives the module its asset; the
// module type is the tenant's or the platform's. A module never moves bay or
// changes type — remove it and install another.
func prepareModule(ctx context.Context, tx *sql.Tx, _ uuid.UUID, id uuid.UUID, row map[string]any) error {
	if err := oneOf(row, "operational_status", moduleOperationalStatuses); err != nil {
		return err
	}
	if id != uuid.Nil {
		var bay, typ string
		if err := tx.QueryRowContext(ctx, `SELECT module_bay_id::text, module_type_id::text FROM modules WHERE id = $1`, id).Scan(&bay, &typ); err != nil {
			return mapIPAMError(err, false)
		}
		if bay != fmt.Sprint(row["module_bay_id"]) || typ != fmt.Sprint(row["module_type_id"]) {
			return ipamInvalid("a module's bay and module type cannot be changed; remove it and install another")
		}
		return nil
	}
	var asset string
	err := tx.QueryRowContext(ctx, `SELECT asset_id::text FROM module_bays WHERE id = $1::uuid AND status <> 'rejected'`,
		fmt.Sprint(row["module_bay_id"])).Scan(&asset)
	if err == sql.ErrNoRows {
		return ipamInvalid("no such module bay %v", row["module_bay_id"])
	}
	if err != nil {
		return mapIPAMError(err, false)
	}
	row["asset_id"] = asset
	return visible(ctx, tx, "module_types", row["module_type_id"])
}

// prepareInventoryItem: the asset's own and never moved; a parent on the same
// asset and no cycle; a role and manufacturer the tenant can read; a component
// link naming a row of that kind on the same asset.
func prepareInventoryItem(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if err := preparePortAsset(ctx, tx, "inventory_items", id, tenant, row); err != nil {
		return err
	}
	if err := sameAssetRef(ctx, tx, "inventory_items", "parent_id", row); err != nil {
		return err
	}
	if id != uuid.Nil && !isEmpty(row["parent_id"]) {
		var cycle bool
		if err := tx.QueryRowContext(ctx, `
			WITH RECURSIVE up(id, parent_id, d) AS (
				SELECT i.id, i.parent_id, 0 FROM inventory_items i WHERE i.id = $1::uuid
				UNION ALL
				SELECT p.id, p.parent_id, up.d + 1 FROM inventory_items p JOIN up ON p.id = up.parent_id WHERE up.d < 64)
			SELECT EXISTS (SELECT 1 FROM up WHERE up.id = $2)`, fmt.Sprint(row["parent_id"]), id).Scan(&cycle); err != nil {
			return mapIPAMError(err, false)
		}
		if cycle {
			return ipamInvalid("parent_id would make an inventory item its own ancestor")
		}
	}
	if err := visible(ctx, tx, "inventory_item_roles", row["role_id"]); err != nil {
		return err
	}
	if err := visible(ctx, tx, "manufacturers", row["manufacturer_id"]); err != nil {
		return err
	}
	kind, _ := row["component_kind"].(string)
	if isEmpty(row["component_kind"]) != isEmpty(row["component_id"]) {
		return ipamInvalid("component_kind and component_id are set together")
	}
	if kind == "" {
		row["component_kind"], row["component_id"] = nil, nil
		return nil
	}
	table, ok := inventoryComponentKinds[kind]
	if !ok {
		return ipamInvalid("component_kind %q is not a component an inventory item can be", kind)
	}
	if err := sameAssetRef(ctx, tx, table, "component_id", row); err != nil {
		return ipamInvalid("component_id must name a %s of the same asset", kind)
	}
	return nil
}
