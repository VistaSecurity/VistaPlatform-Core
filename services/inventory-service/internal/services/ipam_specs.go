package services

// The thirteen IPAM objects as engine specs (DCIM DATA_MODEL §5). Column names
// are binding: they are the API property names, the OpenAPI schema properties
// (ipam_spec_parity_test.go) and the query-language fields.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
	"github.com/vistasecurity/vistaplatform/shared/dcim/sites"
)

// Substrate columns every object carries and a caller may write.
var substrateCols = []ipamCol{
	{Name: "description", Type: colText},
	{Name: "comments", Type: colText},
	{Name: "custom_fields", Type: colJSON},
	{Name: "source_kind", Type: colText},
	{Name: "source_ref", Type: colText},
}

var externalIDsCol = ipamCol{Name: "external_ids", Type: colJSON}

// The lifecycle status a person may set (approve = pending → active).
var lifecycleCols = []ipamCol{{Name: "status", Type: colText}}

func withSubstrate(cols ...ipamCol) []ipamCol {
	return append(cols, substrateCols...)
}

// nonUniqueRoles are the IP address roles NetBox exempts from uniqueness
// (IPADDRESS_ROLES_NONUNIQUE): one address legitimately on several devices.
var nonUniqueRoles = []string{"anycast", "vip", "vrrp", "hsrp", "glbp", "carp"}

func ipamSpecs() []*ipamSpec {
	return []*ipamSpec{
		{
			Kind: dcim.ObjectKindRir, Table: "rirs", Route: "rirs", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "is_private", Type: colBool},
			),
			Filters: []ipamFilter{{Param: "is_private", Column: "is_private", Type: colBool}, {Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "t.name, t.id",
			Prepare: prepareSlug,
		},
		{
			Kind: dcim.ObjectKindAggregate, Table: "aggregates", Route: "aggregates",
			Cols: withSubstrate(
				ipamCol{Name: "prefix", Type: colCidr, Required: true},
				ipamCol{Name: "rir_id", Type: colUUID, Required: true},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				ipamCol{Name: "date_added", Type: colDate},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "rir_id", Column: "rir_id", Type: colUUID}, {Param: "business_unit_id", Column: "business_unit_id", Type: colUUID}},
			Search:  []string{"prefix", "description"},
			Order:   "family(t.prefix), t.prefix",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if err := normalisePrefix(row, "prefix"); err != nil {
					return err
				}
				return visible(ctx, tx, "rirs", row["rir_id"])
			},
		},
		{
			Kind: dcim.ObjectKindVrf, Table: "vrfs", Route: "vrfs",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "rd", Type: colText},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				ipamCol{Name: "enforce_unique", Type: colBool},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "rd", Column: "rd", Type: colText}, {Param: "business_unit_id", Column: "business_unit_id", Type: colUUID}},
			Search:  []string{"name", "rd", "description"},
			Order:   "t.name, t.id",
			Prepare: func(_ context.Context, _ *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				if rd, ok := row["rd"].(string); ok && strings.TrimSpace(rd) == "" {
					row["rd"] = nil
				}
				return nil
			},
		},
		{
			Kind: dcim.ObjectKindRouteTarget, Table: "route_targets", Route: "route-targets",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				externalIDsCol,
			),
			Search: []string{"name", "description"},
			Order:  "t.name, t.id",
		},
		{
			Kind: dcim.ObjectKindPrefixRole, Table: "prefix_roles", Route: "prefix-roles", Catalogue: true,
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "weight", Type: colInt},
			),
			Filters: []ipamFilter{{Param: "slug", Column: "slug", Type: colText}},
			Search:  []string{"name", "slug", "description"},
			Order:   "t.weight, t.name, t.id",
			Prepare: prepareSlug,
		},
		prefixSpec(),
		{
			Kind: dcim.ObjectKindIpRange, Table: "ip_ranges", Route: "ip-ranges",
			Cols: withSubstrate(
				ipamCol{Name: "start_address", Type: colInet, Required: true},
				ipamCol{Name: "end_address", Type: colInet, Required: true},
				ipamCol{Name: "size", Type: colNumeric, Computed: true},
				ipamCol{Name: "vrf_id", Type: colUUID},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				ipamCol{Name: "operational_status", Type: colText},
				ipamCol{Name: "role_id", Type: colUUID},
				ipamCol{Name: "mark_utilized", Type: colBool},
				externalIDsCol,
			),
			Filters: []ipamFilter{
				{Param: "vrf_id", Column: "vrf_id", Type: colUUID},
				{Param: "role_id", Column: "role_id", Type: colUUID},
				{Param: "operational_status", Column: "operational_status", Type: colText},
				{Param: "parent", Custom: parentFilter("public.ipam_host(t.start_address)")},
			},
			Search:     []string{"start_address", "end_address", "description"},
			Order:      "family(t.start_address), t.start_address, t.id",
			Prepare:    prepareIPRange,
			AfterWrite: refreshAfterRangeWrite,
			Present:    presentRangeSize,
		},
		ipAddressSpec(),
		{
			Kind: dcim.ObjectKindVlanGroup, Table: "vlan_groups", Route: "vlan-groups",
			Cols: withSubstrate(
				ipamCol{Name: "name", Type: colText, Required: true},
				ipamCol{Name: "slug", Type: colText},
				ipamCol{Name: "scope_kind", Type: colText},
				ipamCol{Name: "scope_id", Type: colUUID},
				ipamCol{Name: "vid_ranges", Type: colVidRanges},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "scope_kind", Column: "scope_kind", Type: colText}, {Param: "scope_id", Column: "scope_id", Type: colUUID}},
			Search:  []string{"name", "slug", "description"},
			Order:   "t.name, t.id",
			Prepare: func(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
				if err := prepareSlug(ctx, tx, tenant, id, row); err != nil {
					return err
				}
				if err := checkIPAMScope(ctx, tx, row); err != nil {
					return err
				}
				if v, ok := row["vid_ranges"]; ok && v != nil {
					if _, err := vidRanges(v); err != nil {
						return ipamInvalid("vid_ranges: %v", err)
					}
				}
				return nil
			},
			Present: presentVidRanges,
		},
		{
			Kind: dcim.ObjectKindVlan, Table: "vlans", Route: "vlans", Lifecycle: true,
			Cols: withSubstrate(append([]ipamCol{
				{Name: "vid", Type: colInt, Required: true},
				{Name: "name", Type: colText, Required: true},
				{Name: "group_id", Type: colUUID},
				{Name: "site_id", Type: colUUID},
				{Name: "business_unit_id", Type: colUUID},
				{Name: "operational_status", Type: colText},
				{Name: "role_id", Type: colUUID},
				{Name: "qinq_role", Type: colText},
				{Name: "qinq_svlan_id", Type: colUUID},
				externalIDsCol,
			}, lifecycleCols...)...),
			Filters: []ipamFilter{
				{Param: "group_id", Column: "group_id", Type: colUUID},
				{Param: "site_id", Column: "site_id", Type: colUUID},
				{Param: "vid", Column: "vid", Type: colInt},
				{Param: "role_id", Column: "role_id", Type: colUUID},
				{Param: "status", Column: "status", Type: colText},
				{Param: "operational_status", Column: "operational_status", Type: colText},
			},
			Search: []string{"name", "vid", "description"},
			Order:  "t.vid, t.name, t.id",
			// The VLANs lens shows each VLAN's prefixes; one aggregate per row
			// instead of a query per row from the browser.
			ListSelect: `to_jsonb(t) || jsonb_build_object('prefixes', COALESCE((SELECT jsonb_agg(p.prefix::text ORDER BY p.prefix)
			    FROM public.prefixes p WHERE p.tenant_id = t.tenant_id AND p.vlan_id = t.id AND p.status <> 'rejected'), '[]'::jsonb))`,
			Prepare: prepareVLAN,
		},
		{
			Kind: dcim.ObjectKindFhrpGroup, Table: "fhrp_groups", Route: "fhrp-groups",
			Cols: withSubstrate(
				ipamCol{Name: "protocol", Type: colText, Required: true},
				ipamCol{Name: "group_id", Type: colInt, Required: true},
				ipamCol{Name: "name", Type: colText},
				ipamCol{Name: "auth_type", Type: colText},
				ipamCol{Name: "auth_key_present", Type: colBool},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "protocol", Column: "protocol", Type: colText}, {Param: "group_id", Column: "group_id", Type: colInt}},
			Search:  []string{"name", "protocol", "description"},
			Order:   "t.protocol, t.group_id, t.id",
		},
		{
			Kind: dcim.ObjectKindFhrpGroupAssignment, Table: "fhrp_group_assignments", Route: "fhrp-group-assignments",
			Cols: []ipamCol{
				{Name: "group_id", Type: colUUID, Required: true},
				{Name: "interface_id", Type: colUUID, Required: true},
				{Name: "priority", Type: colInt},
			},
			Filters: []ipamFilter{{Param: "group_id", Column: "group_id", Type: colUUID}, {Param: "interface_id", Column: "interface_id", Type: colUUID}},
			Order:   "t.group_id, t.priority DESC, t.id",
		},
		{
			Kind: dcim.ObjectKindAsn, Table: "asns", Route: "asns",
			Cols: withSubstrate(
				ipamCol{Name: "asn", Type: colBigint, Required: true},
				ipamCol{Name: "rir_id", Type: colUUID},
				ipamCol{Name: "business_unit_id", Type: colUUID},
				externalIDsCol,
			),
			Filters: []ipamFilter{{Param: "rir_id", Column: "rir_id", Type: colUUID}, {Param: "asn", Column: "asn", Type: colBigint}},
			Search:  []string{"asn", "description"},
			Order:   "t.asn",
			Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
				return visible(ctx, tx, "rirs", row["rir_id"])
			},
		},
	}
}

func prefixSpec() *ipamSpec {
	return &ipamSpec{
		Kind: dcim.ObjectKindPrefix, Table: "prefixes", Route: "prefixes", Lifecycle: true,
		Cols: withSubstrate(append([]ipamCol{
			{Name: "prefix", Type: colCidr, Required: true},
			{Name: "vrf_id", Type: colUUID},
			{Name: "scope_kind", Type: colText},
			{Name: "scope_id", Type: colUUID},
			{Name: "business_unit_id", Type: colUUID},
			{Name: "vlan_id", Type: colUUID},
			{Name: "role_id", Type: colUUID},
			{Name: "operational_status", Type: colText},
			{Name: "is_pool", Type: colBool},
			{Name: "mark_utilized", Type: colBool},
			{Name: "network_type", Type: colText},
			{Name: "environment", Type: colText},
			{Name: "auto_approve_discoveries", Type: colBool},
			{Name: "auto_approve_sources", Type: colTextArray},
			{Name: "dhcp_managed", Type: colBool},
			{Name: "active_probes_disabled", Type: colBool},
			{Name: "sensitive", Type: colBool},
			{Name: "gateway_ip_id", Type: colUUID},
			{Name: "gateway_asset_id", Type: colUUID},
			{Name: "gateway_source_ref", Type: colText},
			{Name: "cloud_network_ref", Type: colText},
			externalIDsCol,
		}, lifecycleCols...)...),
		Filters: []ipamFilter{
			{Param: "vrf_id", Column: "vrf_id", Type: colUUID},
			{Param: "vlan_id", Column: "vlan_id", Type: colUUID},
			{Param: "role_id", Column: "role_id", Type: colUUID},
			{Param: "status", Column: "status", Type: colText},
			{Param: "operational_status", Column: "operational_status", Type: colText},
			{Param: "business_unit_id", Column: "business_unit_id", Type: colUUID},
			{Param: "network_type", Column: "network_type", Type: colText},
			{Param: "within", Custom: func(v string, n int) (string, any, error) {
				p, err := ipam.ParsePrefix(v)
				if err != nil {
					return "", nil, ipamInvalid("within: %v", err)
				}
				return fmt.Sprintf("t.prefix << $%d::cidr", n), p.String(), nil
			}},
			{Param: "contains", Custom: func(v string, n int) (string, any, error) {
				a, err := ipam.ParseAddr(v)
				if err != nil {
					return "", nil, ipamInvalid("contains: %v", err)
				}
				return fmt.Sprintf("t.prefix >>= $%d::inet", n), a.String(), nil
			}},
		},
		Search: []string{"prefix", "description", "network_type", "cloud_network_ref"},
		Order:  "COALESCE(t.vrf_id, '" + zeroUUID + "'::uuid), family(t.prefix), t.prefix, t.id",
		ListSelect: `to_jsonb(t) || jsonb_build_object('utilization', COALESCE(u.utilization, 0), ` +
			`'child_count', COALESCE(u.child_count, 0), 'ip_count', COALESCE(u.ip_count, 0))`,
		Join: `LEFT JOIN public.prefix_utilization u ON u.prefix_id = t.id`,
		Prepare: func(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
			if err := normalisePrefix(row, "prefix"); err != nil {
				return err
			}
			if err := visible(ctx, tx, "prefix_roles", row["role_id"]); err != nil {
				return err
			}
			return checkIPAMScope(ctx, tx, row)
		},
		AfterWrite: afterPrefixWrite,
	}
}

func ipAddressSpec() *ipamSpec {
	return &ipamSpec{
		Kind: dcim.ObjectKindIpAddress, Table: "ip_addresses", Route: "ip-addresses", Lifecycle: true,
		Cols: withSubstrate(append([]ipamCol{
			{Name: "address", Type: colInet, Required: true},
			{Name: "vrf_id", Type: colUUID},
			{Name: "business_unit_id", Type: colUUID},
			{Name: "operational_status", Type: colText},
			{Name: "role", Type: colText},
			{Name: "assigned_kind", Type: colText},
			{Name: "assigned_id", Type: colUUID},
			{Name: "nat_inside_id", Type: colUUID},
			{Name: "dns_name", Type: colText},
			{Name: "mac_address", Type: colMAC},
			{Name: "last_seen_source", Type: colText},
			externalIDsCol,
		}, lifecycleCols...)...),
		Filters: []ipamFilter{
			{Param: "vrf_id", Column: "vrf_id", Type: colUUID},
			{Param: "role", Column: "role", Type: colText},
			{Param: "status", Column: "status", Type: colText},
			{Param: "operational_status", Column: "operational_status", Type: colText},
			{Param: "assigned_kind", Column: "assigned_kind", Type: colText},
			{Param: "assigned_id", Column: "assigned_id", Type: colUUID},
			{Param: "dns_name", Column: "dns_name", Type: colText},
			{Param: "mac_address", Column: "mac_address", Type: colMAC},
			{Param: "parent", Custom: parentFilter("t.host")},
		},
		Search: []string{"address", "dns_name", "description"},
		Order:  "COALESCE(t.vrf_id, '" + zeroUUID + "'::uuid), family(t.address), t.host, t.id",
		// The asset holding each address, where something says so: through the
		// interface it is assigned to (row 1.2), else as an asset's primary or
		// out-of-band address — the same order ipam_find.go uses.
		ListSelect: `to_jsonb(t) || jsonb_build_object('asset', COALESCE(
		    (SELECT jsonb_build_object('id', a.id,
		        'name', COALESCE(a.display_name, a.hostname, host(a.primary_address), a.id::text))
		       FROM public.interfaces i JOIN public.assets a ON a.tenant_id = i.tenant_id AND a.id = i.asset_id
		      WHERE t.assigned_kind = 'interface' AND i.tenant_id = t.tenant_id AND i.id = t.assigned_id
		        AND a.deleted_at IS NULL),
		    (SELECT jsonb_build_object('id', a.id,
		        'name', COALESCE(a.display_name, a.hostname, host(a.primary_address), a.id::text))
		       FROM public.assets a WHERE a.tenant_id = t.tenant_id AND a.deleted_at IS NULL
		        AND (a.primary_ip4_id = t.id OR a.primary_ip6_id = t.id OR a.oob_ip_id = t.id) LIMIT 1)))`,
		Prepare:    prepareIPAddress,
		AfterWrite: refreshAfterAddressWrite,
	}
}

// parentFilter keeps rows whose address expression lies inside a prefix
// (?parent=10.0.0.0/24). Addresses compare by their host part, with the
// leakproof >= / <= an index can serve under RLS.
func parentFilter(expr string) func(string, int) (string, any, error) {
	return func(v string, n int) (string, any, error) {
		p, err := ipam.ParsePrefix(v)
		if err != nil {
			return "", nil, ipamInvalid("parent: %v", err)
		}
		return fmt.Sprintf("%s BETWEEN public.ipam_host(network($%d::cidr)) AND public.ipam_host(broadcast($%d::cidr))", expr, n, n), p.String(), nil
	}
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify makes a NetBox-style slug from a name.
func Slugify(name string) string {
	s := strings.Trim(slugStrip.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if len(s) > 100 {
		s = strings.Trim(s[:100], "-")
	}
	return s
}

func prepareSlug(_ context.Context, _ *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if isEmpty(row["slug"]) {
		name, _ := row["name"].(string)
		row["slug"] = Slugify(name)
	}
	if isEmpty(row["slug"]) {
		return ipamInvalid("slug is required (the name has no letters or digits)")
	}
	return nil
}

func normalisePrefix(row map[string]any, col string) error {
	s, ok := row[col].(string)
	if !ok {
		return ipamInvalid("%s must be a string", col)
	}
	p, err := ipam.ParsePrefix(s)
	if err != nil {
		return ipamInvalid("%s: %v", col, err)
	}
	row[col] = p.String()
	return nil
}

func prepareIPRange(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	var addrs [2]string
	for i, col := range []string{"start_address", "end_address"} {
		s, _ := row[col].(string)
		p, err := ipam.ParseInterfaceAddr(s)
		if err != nil {
			return ipamInvalid("%s: %v", col, err)
		}
		row[col] = p.String()
		addrs[i] = p.Addr().String()
	}
	start, _ := ipam.ParseAddr(addrs[0])
	end, _ := ipam.ParseAddr(addrs[1])
	r, err := ipam.NewRange(start, end)
	if err != nil {
		return ipamInvalid("%v", err)
	}
	row["size"] = ipam.RangeSize(r.Start, r.End).String()
	if err := visible(ctx, tx, "prefix_roles", row["role_id"]); err != nil {
		return err
	}
	// NetBox refuses a range overlapping another in the same VRF.
	var clash bool
	err = tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM public.ip_ranges
		 WHERE tenant_id = $1 AND COALESCE(vrf_id, '`+zeroUUID+`'::uuid) = COALESCE($2::uuid, '`+zeroUUID+`'::uuid)
		   AND id <> $3 AND family(start_address) = family($4::inet)
		   AND public.ipam_host(start_address) <= public.ipam_host($5::inet)
		   AND public.ipam_host(end_address) >= public.ipam_host($4::inet))`,
		tenant, nullableString(row["vrf_id"]), id, addrs[0], addrs[1]).Scan(&clash)
	if err != nil {
		return err
	}
	if clash {
		return fmt.Errorf("%w: the range overlaps another IP range in this VRF", ErrIPAMConflict)
	}
	return nil
}

func presentRangeSize(row map[string]any) {
	if v, ok := row["size"]; ok && v != nil {
		row["size"] = fmt.Sprint(v)
	}
}

func prepareVLAN(ctx context.Context, tx *sql.Tx, _, _ uuid.UUID, row map[string]any) error {
	if err := visible(ctx, tx, "prefix_roles", row["role_id"]); err != nil {
		return err
	}
	if err := visible(ctx, tx, "sites", row["site_id"]); err != nil {
		return err
	}
	g := nullableString(row["group_id"])
	if g == nil {
		return nil
	}
	vid, err := sqlParam(ipamCol{Name: "vid", Type: colInt}, row["vid"])
	if err != nil {
		return err
	}
	var found, inside bool
	err = tx.QueryRowContext(ctx, `
		SELECT true, EXISTS (SELECT 1 FROM unnest(g.vid_ranges) r WHERE $2::int <@ r)
		  FROM public.vlan_groups g WHERE g.id = $1::uuid`, g, vid).Scan(&found, &inside)
	if err != nil && err != sql.ErrNoRows {
		return mapIPAMError(err, false)
	}
	if !found {
		return ipamInvalid("no such VLAN group %v", g)
	}
	if !inside {
		return ipamInvalid("VLAN %v is outside the group's VLAN ID ranges", vid)
	}
	return nil
}

// ipAddressUniqueness enforces (tenant, VRF, host) uniqueness when the VRF
// enforces it (the global table always does), with NetBox's role rule
// (IPADDRESS_ROLES_NONUNIQUE): an anycast/VIP/FHRP address may share its host
// with other such addresses, and nothing else may share at all. An advisory
// lock on the tuple closes the race between two concurrent writers.
func ipAddressUniqueness(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, vrf any, address, role string) error {
	shared := false
	for _, r := range nonUniqueRoles {
		if role == r {
			shared = true
		}
	}
	enforce := true
	if vrf != nil {
		if err := tx.QueryRowContext(ctx, `SELECT enforce_unique FROM public.vrfs WHERE id = $1::uuid`, vrf).Scan(&enforce); err != nil {
			if err == sql.ErrNoRows {
				return ipamInvalid("no such VRF %v", vrf)
			}
			return err
		}
	}
	if !enforce {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		fmt.Sprintf("ipam-ip:%s:%v:%s", tenant, vrf, address)); err != nil {
		return err
	}
	// A shared-role address conflicts only with a unique-role duplicate; a
	// unique-role address conflicts with any duplicate.
	var dup bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM public.ip_addresses
		 WHERE tenant_id = $1 AND COALESCE(vrf_id, '`+zeroUUID+`'::uuid) = COALESCE($2::uuid, '`+zeroUUID+`'::uuid)
		   AND host = public.ipam_host($3::inet)
		   AND status <> 'rejected' AND id <> $4
		   AND (NOT $6 OR role IS NULL OR role <> ALL ($5::text[])))`,
		tenant, vrf, address, id, "{"+strings.Join(nonUniqueRoles, ",")+"}", shared).Scan(&dup)
	if err != nil {
		return err
	}
	if dup {
		return fmt.Errorf("%w: %s already exists in this VRF, which enforces unique addresses", ErrIPAMConflict, address)
	}
	return nil
}

func prepareIPAddress(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	s, _ := row["address"].(string)
	p, err := ipam.ParseInterfaceAddr(s)
	if err != nil {
		return ipamInvalid("address: %v", err)
	}
	row["address"] = p.String()
	// An address assigned to an interface names one of this tenant's
	// interfaces (row 1.2). assigned_id is polymorphic, so no FK can say so;
	// the explicit tenant predicate holds even on a pool that bypasses RLS.
	if kind, _ := row["assigned_kind"].(string); kind == "interface" && row["assigned_id"] != nil {
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.interfaces
		    WHERE tenant_id = $1 AND id = $2::uuid AND status <> 'rejected')`, tenant, fmt.Sprint(row["assigned_id"])).Scan(&ok); err != nil {
			return mapIPAMError(err, false)
		}
		if !ok {
			return ipamInvalid("assigned_id: no such interface %v", row["assigned_id"])
		}
	}
	role, _ := row["role"].(string)
	if rejected, _ := row["status"].(string); rejected == "rejected" {
		return nil
	}
	return ipAddressUniqueness(ctx, tx, tenant, id, nullableString(row["vrf_id"]), p.Addr().String(), role)
}

func nullableString(v any) any {
	if v == nil {
		return nil
	}
	s := fmt.Sprint(v)
	if s == "" {
		return nil
	}
	return s
}

// checkIPAMScope is the service check DATA_MODEL section 5 puts on a prefix's
// or VLAN group's scope (DCIM row 2.1): scope_kind and scope_id go together and
// name an existing region, site group, site or location the tenant can see.
// The CHECK constraint only constrains the kind's spelling; a scope naming a
// rack or cluster cannot resolve until those tables ship, so it is refused.
func checkIPAMScope(ctx context.Context, tx *sql.Tx, row map[string]any) error {
	kind, _ := nullableString(row["scope_kind"]).(string)
	var id *uuid.UUID
	if raw := nullableString(row["scope_id"]); raw != nil {
		u, err := uuid.Parse(fmt.Sprint(raw))
		if err != nil {
			return ipamInvalid("scope_id is not a uuid")
		}
		id = &u
	}
	if err := sites.CheckScope(ctx, tx, kind, id); err != nil {
		if errors.Is(err, sites.ErrScope) {
			return ipamInvalid("%v", err)
		}
		return mapIPAMError(err, false)
	}
	return nil
}
