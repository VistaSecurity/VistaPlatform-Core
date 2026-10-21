package services

// Virtual circuits as engine specs (DCIM gap 10; NetBox 4.2
// circuits/virtual-circuit-types, virtual-circuits and
// virtual-circuit-terminations; schema block `DCIM: gap10 virtual circuits`).
// They are circuit objects: served under /circuits by the circuits store, gated
// by circuits.read / circuits.manage, and written by the NetBox sync through
// the same engine. Column names are binding — they are the API property names,
// the OpenAPI schema properties (circuits_contract_test.go) and the
// query-language fields.
//
// A virtual circuit runs over a provider network (its provider is the
// network's); a termination is an interface, with a role from NetBox's
// VirtualCircuitTerminationRoleChoices. The choice set is not in the
// standards/netbox-choices snapshot (it carries dcim choice sets only), so it
// is NetBox 4.2's: peer, hub, spoke.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// The virtual circuit routes under /circuits.
const (
	CircuitRouteVirtualCircuitTypes        = "virtual-circuit-types"
	CircuitRouteVirtualCircuits            = "virtual-circuits"
	CircuitRouteVirtualCircuitTerminations = "virtual-circuit-terminations"
)

// VirtualCircuitTerminationRoles is virtual_circuit_terminations.role (NetBox
// VirtualCircuitTerminationRoleChoices).
var VirtualCircuitTerminationRoles = []string{"peer", "hub", "spoke"}

// virtualCircuitListSelect adds, to a virtual circuit list row, its provider
// network's and provider's names, its type's name and its terminations with
// each interface and the asset that owns it: the sub-view's columns in one read.
const virtualCircuitListSelect = `to_jsonb(t) || jsonb_build_object(
	'provider_network_name', pn.name,
	'provider_id', pn.provider_id,
	'provider_name', pv.name,
	'type_name', vct.name,
	'terminations', COALESCE((SELECT jsonb_agg(jsonb_build_object(
		'id', x.id, 'role', x.role, 'interface_id', x.interface_id, 'interface_name', i.name,
		'asset_id', i.asset_id,
		'asset_name', (SELECT COALESCE(a.display_name, a.hostname, host(a.primary_address), a.id::text)
		                 FROM public.assets a WHERE a.tenant_id = i.tenant_id AND a.id = i.asset_id))
		ORDER BY x.role, i.name, x.id)
		FROM public.virtual_circuit_terminations x
		JOIN public.interfaces i ON i.tenant_id = x.tenant_id AND i.id = x.interface_id
		WHERE x.tenant_id = t.tenant_id AND x.virtual_circuit_id = t.id), '[]'::jsonb))`

const virtualCircuitListJoin = `LEFT JOIN public.provider_networks pn ON pn.tenant_id = t.tenant_id AND pn.id = t.provider_network_id
	LEFT JOIN public.providers pv ON pv.tenant_id = pn.tenant_id AND pv.id = pn.provider_id
	LEFT JOIN public.virtual_circuit_types vct ON vct.tenant_id = t.tenant_id AND vct.id = t.type_id`

// virtualCircuitTerminationListSelect adds the interface's and its asset's
// names and the virtual circuit's cid: what the interface page shows.
const virtualCircuitTerminationListSelect = `to_jsonb(t) || jsonb_build_object(
	'virtual_circuit_cid', vc.cid,
	'interface_name', i.name,
	'asset_id', i.asset_id,
	'asset_name', (SELECT COALESCE(a.display_name, a.hostname, host(a.primary_address), a.id::text)
	                 FROM public.assets a WHERE a.tenant_id = i.tenant_id AND a.id = i.asset_id))`

const virtualCircuitTerminationListJoin = `LEFT JOIN public.virtual_circuits vc ON vc.tenant_id = t.tenant_id AND vc.id = t.virtual_circuit_id
	LEFT JOIN public.interfaces i ON i.tenant_id = t.tenant_id AND i.id = t.interface_id`

// providerFilter: virtual circuits over any of this provider's networks.
func providerFilter(v string, n int) (string, any, error) {
	id, err := uuid.Parse(v)
	if err != nil {
		return "", nil, ipamInvalid("provider_id must be a UUID")
	}
	return fmt.Sprintf("EXISTS (SELECT 1 FROM public.provider_networks f WHERE f.tenant_id = t.tenant_id AND f.id = t.provider_network_id AND f.provider_id = $%d::uuid)", n), id, nil
}

func virtualCircuitSpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindVirtualCircuitType, Table: "virtual_circuit_types", Route: CircuitRouteVirtualCircuitTypes,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "color", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
				if err := normaliseColor(row, "color"); err != nil {
					return err
				}
				return prepareSlug(ctx, tx, tenant, id, row)
			},
		},
		{
			Kind: dcim.ObjectKindVirtualCircuit, Table: "virtual_circuits", Route: CircuitRouteVirtualCircuits,
			Cols: withSubstrate(
				ipamCol{Name: "cid", Type: colText, Required: true},
				ipamCol{Name: "provider_network_id", Type: colUUID, Required: true},
				ipamCol{Name: "provider_account_id", Type: colUUID},
				ipamCol{Name: "type_id", Type: colUUID, Required: true},
				ipamCol{Name: "operational_status", Type: colText},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "provider_network_id", Column: "provider_network_id", Type: colUUID},
				{Param: "provider_account_id", Column: "provider_account_id", Type: colUUID},
				{Param: "provider_id", Custom: providerFilter},
				{Param: "type_id", Column: "type_id", Type: colUUID},
				{Param: "operational_status", Column: "operational_status", Type: colText},
				{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
			},
			Search:     []string{"cid", "description"},
			Order:      "lower(t.cid), t.id",
			ListSelect: virtualCircuitListSelect,
			Join:       virtualCircuitListJoin,
			Prepare:    prepareVirtualCircuit,
		},
		{
			Kind: dcim.ObjectKindVirtualCircuitTermination, Table: "virtual_circuit_terminations", Route: CircuitRouteVirtualCircuitTerminations,
			Cols: withSubstrate(
				ipamCol{Name: "virtual_circuit_id", Type: colUUID, Required: true},
				ipamCol{Name: "role", Type: colText},
				ipamCol{Name: "interface_id", Type: colUUID, Required: true},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "virtual_circuit_id", Column: "virtual_circuit_id", Type: colUUID},
				{Param: "interface_id", Column: "interface_id", Type: colUUID},
				{Param: "role", Column: "role", Type: colText},
			},
			Search:     []string{"role", "description"},
			Order:      "t.virtual_circuit_id, t.role, t.id",
			ListSelect: virtualCircuitTerminationListSelect,
			Join:       virtualCircuitTerminationListJoin,
			Prepare:    prepareVirtualCircuitTermination,
		},
	}
}

// prepareVirtualCircuit checks what a foreign key says only as a 500: that the
// provider network and type are the tenant's, and that the provider account,
// if any, belongs to the provider network's provider (NetBox
// VirtualCircuit.clean).
func prepareVirtualCircuit(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if cid, ok := row["cid"].(string); ok {
		row["cid"] = strings.TrimSpace(cid)
	}
	if err := oneOf(row, "operational_status", CircuitOperationalStatuses); err != nil {
		return err
	}
	if row["operational_status"] == nil {
		row["operational_status"] = "active"
	}
	if err := visible(ctx, tx, "provider_networks", row["provider_network_id"]); err != nil {
		return err
	}
	if err := visible(ctx, tx, "virtual_circuit_types", row["type_id"]); err != nil {
		return err
	}
	acct := row["provider_account_id"]
	if isEmpty(acct) {
		row["provider_account_id"] = nil
		return nil
	}
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.provider_accounts a
		JOIN public.provider_networks n ON n.tenant_id = a.tenant_id AND n.provider_id = a.provider_id
		WHERE a.id = $1::uuid AND n.id = $2::uuid)`,
		fmt.Sprint(acct), fmt.Sprint(row["provider_network_id"])).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("provider account %v is not an account of the provider network's provider", acct)
	}
	return nil
}

// prepareVirtualCircuitTermination checks the role and that the virtual
// circuit and the interface are the tenant's. A rejected interface (a
// discovery a person turned down) cannot carry a termination.
func prepareVirtualCircuitTermination(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if r, ok := row["role"].(string); ok {
		row["role"] = strings.ToLower(strings.TrimSpace(r))
	}
	if err := oneOf(row, "role", VirtualCircuitTerminationRoles); err != nil {
		return err
	}
	if row["role"] == nil {
		row["role"] = "peer"
	}
	if err := visible(ctx, tx, "virtual_circuits", row["virtual_circuit_id"]); err != nil {
		return err
	}
	if isEmpty(row["interface_id"]) {
		return ipamInvalid("interface_id is required")
	}
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.interfaces WHERE id = $1::uuid AND status <> 'rejected')`,
		fmt.Sprint(row["interface_id"])).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("no such interface %v", row["interface_id"])
	}
	return nil
}
