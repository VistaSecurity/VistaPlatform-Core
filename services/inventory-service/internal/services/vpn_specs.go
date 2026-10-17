package services

// The VPN objects (DCIM row 4.3; ADR-0010 D8; DATA_MODEL §7 VPN) as object
// engine specs: tunnel groups, tunnels, tunnel terminations, IKE / IPsec
// proposals, policies and profiles, L2VPNs and L2VPN terminations. Column
// names are the API property names and the OpenAPI schema properties.
//
// Every algorithm a proposal names is resolved, in Prepare, to its NetBox
// spelling AND to its `algorithms` row (`*_algorithm_id`, computed — a caller
// never writes it). That link is what makes the catalogue score a tunnel the
// way it scores TLS and SSH; an algorithm the catalogue does not hold keeps
// its text and a NULL id, which is "unassessed", never a guess.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

// VPNRoutes is the route segments under /inventory-service/vpn, in order.
var VPNRoutes = []string{
	"tunnel-groups", "tunnels", "tunnel-terminations",
	"ike-proposals", "ike-policies", "ipsec-proposals", "ipsec-policies", "ipsec-profiles",
	"l2vpns", "l2vpn-terminations",
}

// vpnAlgorithmSelect projects a catalogue row into the assessment the UI
// renders beside a proposal's algorithm: code, strength, deprecation, risk and
// PQC status. NULL when the algorithm is not catalogued.
func vpnAlgorithmSelect(col string) string {
	return `(SELECT jsonb_build_object('code', a.code, 'name', a.name, 'strength', a.strength,
	    'deprecation_status', a.deprecation_status, 'risk_score', a.risk_score, 'is_pqc', COALESCE(a.is_pqc, false),
	    'primitive', a.primitive) FROM public.algorithms a WHERE a.id = t.` + col + `)`
}

// vpnProposalIDsSelect is a policy's proposals, as the list of their ids.
func vpnProposalIDsSelect(junction, policyCol, proposalCol string) string {
	return `COALESCE((SELECT jsonb_agg(j.` + proposalCol + ` ORDER BY j.` + proposalCol + `) FROM public.` + junction +
		` j WHERE j.tenant_id = t.tenant_id AND j.` + policyCol + ` = t.id), '[]'::jsonb)`
}

// tunnelPostureSelect adds what the Tunnels lens shows beside a tunnel row:
// its IKE version and PFS group (through its profile), its terminations with
// the interface and asset each is on, the weakest catalogue component across
// both phases, and the PQC class of its key exchanges (the pqc_readiness.go
// denylist: any classical key-agreement / KEM / signature / PKE component makes
// the tunnel need migration).
const tunnelPostureSelect = `to_jsonb(t) || jsonb_build_object(
    'ike_version', (SELECT ip.version FROM public.ipsec_profiles pr JOIN public.ike_policies ip ON ip.tenant_id = pr.tenant_id AND ip.id = pr.ike_policy_id
                     WHERE pr.tenant_id = t.tenant_id AND pr.id = t.ipsec_profile_id),
    'pfs_group', (SELECT sp.pfs_group FROM public.ipsec_profiles pr JOIN public.ipsec_policies sp ON sp.tenant_id = pr.tenant_id AND sp.id = pr.ipsec_policy_id
                   WHERE pr.tenant_id = t.tenant_id AND pr.id = t.ipsec_profile_id),
    'terminations', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', tt.id, 'role', tt.role, 'interface_id', i.id, 'interface', i.name,
                                  'asset_id', i.asset_id, 'asset_name', COALESCE(a.display_name, a.hostname), 'outside_ip', host(oip.address)) ORDER BY i.name)
                       FROM public.tunnel_terminations tt
                       JOIN public.interfaces i ON i.tenant_id = tt.tenant_id AND i.id = tt.termination_id
                       LEFT JOIN public.assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id
                       LEFT JOIN public.ip_addresses oip ON oip.tenant_id = tt.tenant_id AND oip.id = tt.outside_ip_id
                      WHERE tt.tenant_id = t.tenant_id AND tt.tunnel_id = t.id), '[]'::jsonb),
    'weakest_component', (SELECT jsonb_build_object('code', al.code, 'phase', ta.phase, 'role', ta.role, 'risk_score', al.risk_score,
                                  'strength', al.strength, 'deprecation_status', al.deprecation_status)
                            FROM public.tunnel_algorithms ta JOIN public.algorithms al ON al.id = ta.algorithm_id
                           WHERE ta.tenant_id = t.tenant_id AND ta.tunnel_id = t.id AND al.risk_score IS NOT NULL
                           ORDER BY al.risk_score DESC, al.code LIMIT 1),
    'pqc_status', (SELECT CASE
                       WHEN count(*) = 0 THEN 'unclassified'
                       WHEN bool_or(NOT COALESCE(al.is_pqc, false) AND al.primitive IN ('signature', 'kem', 'key-agree', 'pke')) THEN 'needs_migration'
                       WHEN bool_or(COALESCE(al.is_pqc, false)) THEN 'pqc_ready'
                       WHEN bool_and(al.primitive IS NOT NULL AND al.primitive <> 'other') THEN 'symmetric_safe'
                       ELSE 'unclassified' END
                     FROM public.tunnel_algorithms ta JOIN public.algorithms al ON al.id = ta.algorithm_id
                    WHERE ta.tenant_id = t.tenant_id AND ta.tunnel_id = t.id))`

func vpnSpecs() []*ipamSpec {
	ikeProposalSelect := `to_jsonb(t) || jsonb_build_object('encryption_assessment', ` + vpnAlgorithmSelect("encryption_algorithm_id") +
		`, 'authentication_assessment', ` + vpnAlgorithmSelect("authentication_algorithm_id") +
		`, 'group_assessment', ` + vpnAlgorithmSelect("group_algorithm_id") + `)`
	ipsecProposalSelect := `to_jsonb(t) || jsonb_build_object('encryption_assessment', ` + vpnAlgorithmSelect("encryption_algorithm_id") +
		`, 'authentication_assessment', ` + vpnAlgorithmSelect("authentication_algorithm_id") + `)`
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindTunnelGroup, Table: "tunnel_groups", Route: "tunnel-groups",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "t.name, t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindTunnel, Table: "tunnels", Route: "tunnels", Lifecycle: true,
			Cols: withSubstrate(append([]ipamCol{
				{Name: "name", Type: colText, Required: true},
				{Name: "group_id", Type: colUUID},
				{Name: "operational_status", Type: colText},
				{Name: "encapsulation", Type: colText, Required: true},
				{Name: "ipsec_profile_id", Type: colUUID},
				{Name: "business_unit_id", Type: colUUID},
				{Name: "tunnel_id", Type: colBigint},
				externalIDsCol,
			}, lifecycleCols...)...),
			Filters: []ipamFilter{
				{Param: "group_id", Column: "group_id", Type: colUUID},
				{Param: "encapsulation", Column: "encapsulation", Type: colText},
				{Param: "operational_status", Column: "operational_status", Type: colText},
				{Param: "ipsec_profile_id", Column: "ipsec_profile_id", Type: colUUID},
				{Param: "status", Column: "status", Type: colText},
				{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
			},
			Search:     []string{"name", "description"},
			Order:      "t.name, t.id",
			ListSelect: tunnelPostureSelect,
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := visible(ctx, tx, "tunnel_groups", row["group_id"]); err != nil {
					return err
				}
				return visible(ctx, tx, "ipsec_profiles", row["ipsec_profile_id"])
			},
		},
		{
			Kind: dcim.ObjectKindTunnelTermination, Table: "tunnel_terminations", Route: "tunnel-terminations",
			Cols: withSubstrate(
				ipamCol{Name: "tunnel_id", Type: colUUID, Required: true},
				ipamCol{Name: "role", Type: colText},
				ipamCol{Name: "termination_kind", Type: colText},
				ipamCol{Name: "termination_id", Type: colUUID, Required: true},
				ipamCol{Name: "outside_ip_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "tunnel_id", Column: "tunnel_id", Type: colUUID},
				{Param: "termination_id", Column: "termination_id", Type: colUUID},
				{Param: "role", Column: "role", Type: colText},
			},
			Order: "t.tunnel_id, t.role, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := visible(ctx, tx, "tunnels", row["tunnel_id"]); err != nil {
					return err
				}
				if err := visible(ctx, tx, "interfaces", row["termination_id"]); err != nil {
					return err
				}
				return visible(ctx, tx, "ip_addresses", row["outside_ip_id"])
			},
		},
		{
			Kind: dcim.ObjectKindIkeProposal, Table: "ike_proposals", Route: "ike-proposals",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "authentication_method", Type: colText},
				ipamCol{Name: "encryption_algorithm", Type: colText},
				ipamCol{Name: "authentication_algorithm", Type: colText},
				ipamCol{Name: "group", Type: colInt},
				ipamCol{Name: "sa_lifetime_seconds", Type: colInt},
				ipamCol{Name: "encryption_algorithm_id", Type: colUUID, Computed: true},
				ipamCol{Name: "authentication_algorithm_id", Type: colUUID, Computed: true},
				ipamCol{Name: "group_algorithm_id", Type: colUUID, Computed: true},
				externalIDsCol,
			),
			Filters:    []ipamFilter{{Param: "group", Column: "group", Type: colInt}, {Param: "encryption_algorithm", Column: "encryption_algorithm", Type: colText}},
			Search:     []string{"name", "encryption_algorithm", "authentication_algorithm", "description"},
			Order:      "t.name, t.id",
			ListSelect: ikeProposalSelect,
			Prepare:    prepareIKEProposal,
		},
		{
			Kind: dcim.ObjectKindIkePolicy, Table: "ike_policies", Route: "ike-policies",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "version", Type: colInt},
				ipamCol{Name: "mode", Type: colText},
				ipamCol{Name: "preshared_key_present", Type: colBool},
				externalIDsCol,
			),
			Filters:    []ipamFilter{{Param: "version", Column: "version", Type: colInt}},
			Search:     []string{"name", "description"},
			Order:      "t.name, t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object('proposals', ` + vpnProposalIDsSelect("ike_policy_proposals", "ike_policy_id", "ike_proposal_id") + `)`,
		},
		{
			Kind: dcim.ObjectKindIpsecProposal, Table: "ipsec_proposals", Route: "ipsec-proposals",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "encryption_algorithm", Type: colText},
				ipamCol{Name: "authentication_algorithm", Type: colText},
				ipamCol{Name: "sa_lifetime_seconds", Type: colInt},
				ipamCol{Name: "sa_lifetime_data_kb", Type: colInt},
				ipamCol{Name: "encryption_algorithm_id", Type: colUUID, Computed: true},
				ipamCol{Name: "authentication_algorithm_id", Type: colUUID, Computed: true},
				externalIDsCol,
			),
			Filters:    []ipamFilter{{Param: "encryption_algorithm", Column: "encryption_algorithm", Type: colText}},
			Search:     []string{"name", "encryption_algorithm", "authentication_algorithm", "description"},
			Order:      "t.name, t.id",
			ListSelect: ipsecProposalSelect,
			Prepare:    prepareIPsecProposal,
		},
		{
			Kind: dcim.ObjectKindIpsecPolicy, Table: "ipsec_policies", Route: "ipsec-policies",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "pfs_group", Type: colInt},
				ipamCol{Name: "pfs_group_algorithm_id", Type: colUUID, Computed: true},
				externalIDsCol,
			),
			Search: []string{"name", "description"},
			Order:  "t.name, t.id",
			ListSelect: `to_jsonb(t) || jsonb_build_object('proposals', ` + vpnProposalIDsSelect("ipsec_policy_proposals", "ipsec_policy_id", "ipsec_proposal_id") +
				`, 'pfs_group_assessment', ` + vpnAlgorithmSelect("pfs_group_algorithm_id") + `)`,
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				id, err := groupAlgorithmID(ctx, tx, row["pfs_group"])
				if err != nil {
					return err
				}
				row["pfs_group_algorithm_id"] = id
				return nil
			},
		},
		{
			Kind: dcim.ObjectKindIpsecProfile, Table: "ipsec_profiles", Route: "ipsec-profiles",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "mode", Type: colText},
				ipamCol{Name: "ike_policy_id", Type: colUUID, Required: true},
				ipamCol{Name: "ipsec_policy_id", Type: colUUID, Required: true},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "ike_policy_id", Column: "ike_policy_id", Type: colUUID}, {Param: "ipsec_policy_id", Column: "ipsec_policy_id", Type: colUUID}},
			Search:  []string{"name", "description"},
			Order:   "t.name, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := visible(ctx, tx, "ike_policies", row["ike_policy_id"]); err != nil {
					return err
				}
				return visible(ctx, tx, "ipsec_policies", row["ipsec_policy_id"])
			},
		},
		{
			Kind: dcim.ObjectKindL2vpn, Table: "l2vpns", Route: "l2vpns",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "type", Type: colText, Required: true},
				ipamCol{Name: "identifier", Type: colBigint},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "type", Column: "type", Type: colText}, {Param: "business_unit_id", Column: "business_unit_id", Type: colUUID}},
			Search:  []string{"name", "slug", "description"},
			Order:   "t.name, t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindL2vpnTermination, Table: "l2vpn_terminations", Route: "l2vpn-terminations",
			Cols: withSubstrate(
				ipamCol{Name: "l2vpn_id", Type: colUUID, Required: true},
				ipamCol{Name: "assigned_kind", Type: colText, Required: true},
				ipamCol{Name: "assigned_id", Type: colUUID, Required: true},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "l2vpn_id", Column: "l2vpn_id", Type: colUUID}, {Param: "assigned_kind", Column: "assigned_kind", Type: colText}},
			Order:   "t.l2vpn_id, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := visible(ctx, tx, "l2vpns", row["l2vpn_id"]); err != nil {
					return err
				}
				switch row["assigned_kind"] {
				case "interface":
					return visible(ctx, tx, "interfaces", row["assigned_id"])
				case "vlan":
					return visible(ctx, tx, "vlans", row["assigned_id"])
				}
				return ipamInvalid("assigned_kind must be interface or vlan")
			},
		},
	}
}

// algorithmIDByCode resolves a catalogue code to its row id, nil when the
// catalogue has no such row (or code is empty).
func algorithmIDByCode(ctx context.Context, tx *sql.Tx, code string) (any, error) {
	if code == "" {
		return nil, nil
	}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM public.algorithms WHERE code = $1`, code).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("resolve algorithm %s: %w", code, err)
	}
	return id.String(), nil
}

// intOf reads an API-shape integer (json.Number, int, int64, float64, string).
func intOf(v any) (int, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		i, err := strconv.Atoi(fmt.Sprint(n))
		return i, err == nil
	}
}

func groupAlgorithmID(ctx context.Context, tx *sql.Tx, group any) (any, error) {
	g, ok := intOf(group)
	if !ok || g == 0 {
		return nil, nil
	}
	return algorithmIDByCode(ctx, tx, cryptoparse.IKEGroupCode(g))
}

// resolveAlgorithmColumns rewrites the encryption / authentication algorithm
// columns to NetBox's spelling and sets their catalogue ids.
func resolveAlgorithmColumns(ctx context.Context, tx *sql.Tx, row map[string]any) error {
	if s, ok := row["encryption_algorithm"].(string); ok && s != "" {
		name, code := cryptoparse.CanonicalIKEEncryption(s)
		row["encryption_algorithm"] = name
		id, err := algorithmIDByCode(ctx, tx, code)
		if err != nil {
			return err
		}
		row["encryption_algorithm_id"] = id
	} else {
		row["encryption_algorithm_id"] = nil
	}
	if s, ok := row["authentication_algorithm"].(string); ok && s != "" {
		name, code := cryptoparse.CanonicalIKEIntegrity(s)
		row["authentication_algorithm"] = name
		id, err := algorithmIDByCode(ctx, tx, code)
		if err != nil {
			return err
		}
		row["authentication_algorithm_id"] = id
	} else {
		row["authentication_algorithm_id"] = nil
	}
	return nil
}

func prepareIKEProposal(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if err := resolveAlgorithmColumns(ctx, tx, row); err != nil {
		return err
	}
	id, err := groupAlgorithmID(ctx, tx, row["group"])
	if err != nil {
		return err
	}
	row["group_algorithm_id"] = id
	return nil
}

func prepareIPsecProposal(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	return resolveAlgorithmColumns(ctx, tx, row)
}
