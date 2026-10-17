package services

// Circuits as engine specs (DCIM BUILD_PLAN row 4.1; ADR-0010 D8; DATA_MODEL
// §6): providers, provider accounts, provider networks, circuit types,
// circuits, circuit terminations, circuit groups and their assignments. Column
// names are binding — they are the API property names, the OpenAPI schema
// properties (circuits_contract_test.go) and the query-language fields.
//
// Every object runs on the IPAM object engine (ipam_engine.go): one
// tenant-scoped transaction per call, RLS in force, every write recorded in
// object_changes. circuit_types is a platform catalogue (tenant_id NULL rows
// seeded, refused on write with ErrIPAMReadOnly).

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// The circuit object routes under /circuits, in DATA_MODEL §6's order.
const (
	CircuitRouteProviders        = "providers"
	CircuitRouteProviderAccounts = "provider-accounts"
	CircuitRouteProviderNetworks = "provider-networks"
	CircuitRouteCircuitTypes     = "circuit-types"
	CircuitRouteCircuits         = "circuits"
	CircuitRouteTerminations     = "circuit-terminations"
	CircuitRouteGroups           = "circuit-groups"
	CircuitRouteGroupAssignments = "circuit-group-assignments"
)

// CircuitObjectRoutes lists every route the circuits store serves.
func CircuitObjectRoutes() []string {
	var out []string
	for _, sp := range circuitSpecs() {
		out = append(out, sp.Route)
	}
	return out
}

// CircuitOperationalStatuses is circuits.operational_status (NetBox
// CircuitStatusChoices).
var CircuitOperationalStatuses = []string{"planned", "provisioning", "active", "offline", "deprovisioning", "decommissioned"}

// CircuitTerminationKinds are the objects a circuit termination may land on
// (NetBox 4.2: site, location, region, site group, provider network).
var CircuitTerminationKinds = []string{"site", "location", "region", "site_group", "provider_network"}

var circuitPriorities = []string{"primary", "secondary", "tertiary", "inactive"}

// circuitListSelect adds, to a circuit list row, its provider's and type's
// names and its A/Z terminations with each target's name: the lens's columns
// in one read.
const circuitListSelect = `to_jsonb(t) || jsonb_build_object(
	'provider_name', cp.name,
	'type_name', cty.name,
	'terminations', COALESCE((SELECT jsonb_agg(jsonb_build_object(
		'id', x.id, 'term_side', x.term_side, 'termination_kind', x.termination_kind,
		'termination_id', x.termination_id,
		'termination_name', public.circuit_termination_target_name(x.termination_kind, x.termination_id),
		'port_speed_kbps', x.port_speed_kbps) ORDER BY x.term_side)
		FROM public.circuit_terminations x WHERE x.tenant_id = t.tenant_id AND x.circuit_id = t.id), '[]'::jsonb))`

const circuitListJoin = `LEFT JOIN public.providers cp ON cp.id = t.provider_id LEFT JOIN public.circuit_types cty ON cty.id = t.type_id`

// terminationFilter: circuits with a termination on this target id (a site,
// location, … — the site page's Circuits card).
func terminationFilter(v string, n int) (string, any, error) {
	id, err := uuid.Parse(v)
	if err != nil {
		return "", nil, ipamInvalid("termination_id must be a UUID")
	}
	return fmt.Sprintf("EXISTS (SELECT 1 FROM public.circuit_terminations x WHERE x.tenant_id = t.tenant_id AND x.circuit_id = t.id AND x.termination_id = $%d::uuid)", n), id, nil
}

func circuitSpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindProvider, Table: "providers", Route: CircuitRouteProviders,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "asns", Type: colBigintArray},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindProviderAccount, Table: "provider_accounts", Route: CircuitRouteProviderAccounts,
			Cols: withSubstrate(
				ipamCol{Name: "provider_id", Type: colUUID, Required: true},
				ipamCol{Name: "account", Type: colText, Required: true},
				ipamCol{Name: "name", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "provider_id", Column: "provider_id", Type: colUUID}},
			Search:  []string{"account", "name", "description"},
			Order:   "t.provider_id, t.account, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if n, ok := row["name"].(string); ok && strings.TrimSpace(n) == "" {
					row["name"] = nil
				}
				return visible(ctx, tx, "providers", row["provider_id"])
			},
		},
		{
			Kind: dcim.ObjectKindProviderNetwork, Table: "provider_networks", Route: CircuitRouteProviderNetworks,
			Cols: withSubstrate(
				ipamCol{Name: "provider_id", Type: colUUID, Required: true},
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "service_id", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "provider_id", Column: "provider_id", Type: colUUID}},
			Search:  []string{"name", "service_id", "description"},
			Order:   "t.provider_id, lower(t.name), t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				return visible(ctx, tx, "providers", row["provider_id"])
			},
		},
		{
			Kind: dcim.ObjectKindCircuitType, Table: "circuit_types", Route: CircuitRouteCircuitTypes, Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "color", Type: colText},
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
			Kind: dcim.ObjectKindCircuit, Table: "circuits", Route: CircuitRouteCircuits,
			Cols: withSubstrate(
				ipamCol{Name: "cid", Type: colText, Required: true},
				ipamCol{Name: "provider_id", Type: colUUID, Required: true},
				ipamCol{Name: "provider_account_id", Type: colUUID},
				ipamCol{Name: "type_id", Type: colUUID, Required: true},
				ipamCol{Name: "operational_status", Type: colText},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				ipamCol{Name: "install_date", Type: colDate},
				ipamCol{Name: "termination_date", Type: colDate},
				ipamCol{Name: "commit_rate_kbps", Type: colBigint},
				ipamCol{Name: "distance", Type: colNumeric},
				ipamCol{Name: "distance_unit", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "provider_id", Column: "provider_id", Type: colUUID},
				{Param: "provider_account_id", Column: "provider_account_id", Type: colUUID},
				{Param: "type_id", Column: "type_id", Type: colUUID},
				{Param: "operational_status", Column: "operational_status", Type: colText},
				{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
				{Param: "termination_id", Custom: terminationFilter},
			},
			Search:     []string{"cid", "description"},
			Order:      "lower(t.cid), t.id",
			ListSelect: circuitListSelect,
			Join:       circuitListJoin,
			Prepare:    prepareCircuit,
			AfterWrite: circuitAfterWrite,
		},
		{
			Kind: dcim.ObjectKindCircuitTermination, Table: "circuit_terminations", Route: CircuitRouteTerminations,
			Cols: withSubstrate(
				ipamCol{Name: "circuit_id", Type: colUUID, Required: true},
				ipamCol{Name: "term_side", Type: colText, Required: true},
				ipamCol{Name: "termination_kind", Type: colText},
				ipamCol{Name: "termination_id", Type: colUUID},
				ipamCol{Name: "port_speed_kbps", Type: colBigint},
				ipamCol{Name: "upstream_speed_kbps", Type: colBigint},
				ipamCol{Name: "xconnect_id", Type: colText},
				ipamCol{Name: "pp_info", Type: colText},
				ipamCol{Name: "mark_connected", Type: colBool},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "circuit_id", Column: "circuit_id", Type: colUUID},
				{Param: "termination_kind", Column: "termination_kind", Type: colText},
				{Param: "termination_id", Column: "termination_id", Type: colUUID},
			},
			Search:     []string{"xconnect_id", "pp_info", "description"},
			Order:      "t.circuit_id, t.term_side, t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object('termination_name', public.circuit_termination_target_name(t.termination_kind, t.termination_id))`,
			Prepare:    prepareCircuitTermination,
			AfterWrite: circuitTerminationAfterWrite,
		},
		{
			Kind: dcim.ObjectKindCircuitGroup, Table: "circuit_groups", Route: CircuitRouteGroups,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "lower(t.name), t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindCircuitGroupAssignment, Table: "circuit_group_assignments", Route: CircuitRouteGroupAssignments,
			Cols: []ipamCol{
				{Name: "group_id", Type: colUUID, Required: true},
				{Name: "circuit_id", Type: colUUID, Required: true},
				{Name: "priority", Type: colText},
			},
			Filters: []ipamFilter{{Param: "group_id", Column: "group_id", Type: colUUID}, {Param: "circuit_id", Column: "circuit_id", Type: colUUID}},
			Order:   "t.group_id, t.circuit_id, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := oneOf(row, "priority", circuitPriorities); err != nil {
					return err
				}
				if err := visible(ctx, tx, "circuit_groups", row["group_id"]); err != nil {
					return err
				}
				return visible(ctx, tx, "circuits", row["circuit_id"])
			},
		},
	}
}

// prepareCircuit checks the references a foreign key cannot (a circuit type is
// a catalogue row: an FK does not see RLS) and that the provider account, if
// any, is the circuit's provider's.
func prepareCircuit(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if cid, ok := row["cid"].(string); ok {
		row["cid"] = strings.TrimSpace(cid)
	}
	if err := oneOf(row, "operational_status", CircuitOperationalStatuses); err != nil {
		return err
	}
	if row["operational_status"] == nil {
		row["operational_status"] = "active"
	}
	if err := oneOf(row, "distance_unit", []string{"km", "m", "mi", "ft"}); err != nil {
		return err
	}
	for _, c := range []string{"install_date", "termination_date"} {
		if s, ok := row[c].(string); ok && strings.TrimSpace(s) == "" {
			row[c] = nil
		}
	}
	if err := visible(ctx, tx, "providers", row["provider_id"]); err != nil {
		return err
	}
	if err := visible(ctx, tx, "circuit_types", row["type_id"]); err != nil {
		return err
	}
	acct := row["provider_account_id"]
	if isEmpty(acct) {
		row["provider_account_id"] = nil
		return nil
	}
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.provider_accounts WHERE id = $1::uuid AND provider_id = $2::uuid)`,
		fmt.Sprint(acct), fmt.Sprint(row["provider_id"])).Scan(&ok); err != nil {
		return mapIPAMError(err, false)
	}
	if !ok {
		return ipamInvalid("provider account %v is not an account of the circuit's provider", acct)
	}
	return nil
}

// prepareCircuitTermination checks the side, and that the target (a site,
// location, region, site group or provider network) is one of the tenant's.
// The target is polymorphic, so there is no FK to do it; a kind whose table
// has not shipped yet is refused rather than stored unchecked.
func prepareCircuitTermination(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if err := refuseMarkConnectedWithCable(row); err != nil {
		return err
	}
	side, _ := row["term_side"].(string)
	side = strings.ToUpper(strings.TrimSpace(side))
	if side != "A" && side != "Z" {
		return ipamInvalid("term_side must be A or Z")
	}
	row["term_side"] = side
	if err := visible(ctx, tx, "circuits", row["circuit_id"]); err != nil {
		return err
	}
	kind, _ := row["termination_kind"].(string)
	kind = strings.TrimSpace(kind)
	if kind == "" {
		row["termination_kind"], row["termination_id"] = nil, nil
		return nil
	}
	row["termination_kind"] = kind
	known := false
	for _, k := range CircuitTerminationKinds {
		known = known || k == kind
	}
	if !known {
		return ipamInvalid("termination_kind %q is not one of %s", kind, strings.Join(CircuitTerminationKinds, ", "))
	}
	if isEmpty(row["termination_id"]) {
		return ipamInvalid("termination_id is required with termination_kind")
	}
	table := kind + "s"
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ipamInvalid("%s terminations are not available yet (no %s table)", kind, pq.QuoteIdentifier(table))
	}
	return visible(ctx, tx, table, row["termination_id"])
}
