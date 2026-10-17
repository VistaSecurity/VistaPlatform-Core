package dcimfixture

// IPAM populators (DCIM BUILD_PLAN row 1.3): VRFs, route targets, aggregates,
// VLAN groups and VLANs, prefixes, IP ranges, IP addresses, the utilisation
// cache, FHRP groups and ASNs, at the §12 shape (Scale1: 20,000 prefixes
// holding 200,000 IP addresses across 50 VRFs).
//
// Shape. Site s lives in VRF s % VRFs and owns the container
// 10.<s / VRFs>.0.0/16 there (so sites never collide within a VRF) with
// PrefixesPerSite-1 /24 children 10.k.j.0/24 (j = 1..). Each prefix holds
// IPsPerPrefix addresses (.1, .2, …; the container's sit in 10.k.0.0/24, which
// no child covers). Each child /24 has a VLAN (vid j+1) in its site's VLAN
// group; each site has one reserved range 10.k.255.1-50 and one FHRP group and
// one ASN.
//
// Every table here has a global primary key, so ids are database defaults
// (README rule 3); rows are written with set-based INSERT … SELECT and linked
// by name. The names are witnessed in Go, in the same order, so the digest
// covers them.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/network/addrscope"
)

func privatePrefixes() []string {
	var out []string
	for _, p := range addrscope.PrivateRanges() {
		out = append(out, p.String())
	}
	return out
}

// VRFs is the number of VRFs the IPAM populator creates: §12's 50 at Scale1,
// one per ten sites, at least one.
func (s Scale) VRFs() int {
	n := s.Sites / 10
	if n < 1 {
		n = 1
	}
	if n > 50 {
		n = 50
	}
	return n
}

// VRFName is the stable name of VRF v.
func VRFName(v int) string { return fmt.Sprintf("vrf-%02d", v) }

// SitePrefix is the /16 container a site owns in its VRF.
func (s Scale) SitePrefix(site int) string { return fmt.Sprintf("10.%d.0.0/16", site/s.VRFs()) }

// ipamTables are every table the IPAM populator writes.
var ipamTables = []string{"vrfs", "route_targets", "vrf_import_targets", "vrf_export_targets", "rirs", "aggregates",
	"vlan_groups", "vlans", "prefixes", "ip_ranges", "ip_addresses", "prefix_utilization", "fhrp_groups", "asns"}

type ipamStatement struct {
	table string
	sql   string
	args  []any
}

// ipamPopulators is one populator per IPAM table (Summary.Counts is keyed by
// table), each running its statement; the first validates the scale and
// witnesses the names.
func ipamPopulators() []Populator {
	var out []Populator
	for i, table := range ipamStatementTables {
		i := i
		out = append(out, Populator{Name: table, Requires: ipamTables, Run: func(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
			if i == 0 {
				if err := ipamWitness(e); err != nil {
					return 0, err
				}
			}
			st := ipamStatements(e)[i]
			// The statements join tables this same transaction just filled;
			// without statistics the planner nests loops over them (minutes
			// at Scale1 instead of seconds).
			if _, err := tx.ExecContext(ctx, `ANALYZE public.vrfs, public.vlan_groups, public.vlans, public.prefixes`); err != nil {
				return 0, fmt.Errorf("ipam analyze: %w", err)
			}
			res, err := tx.ExecContext(ctx, st.sql, st.args...)
			if err != nil {
				return 0, fmt.Errorf("ipam %s: %w", st.table, err)
			}
			n, _ := res.RowsAffected()
			return int(n), nil
		}})
	}
	return out
}

var ipamStatementTables = []string{"vrfs", "route_targets", "vrf_import_targets", "vrf_export_targets", "aggregates",
	"vlan_groups", "vlans", "prefixes", "ip_ranges", "ip_addresses", "prefix_utilization", "fhrp_groups", "asns"}

func ipamWitness(e *Env) error {
	s := e.Scale
	if s.PrefixesPerSite < 1 || s.PrefixesPerSite > 255 || s.IPsPerPrefix > 250 || s.Sites/s.VRFs() > 254 {
		return fmt.Errorf("ipam: scale %+v does not fit the 10.k.j.0/24 plan", s)
	}
	nv, kids := s.VRFs(), s.PrefixesPerSite-1
	for v := 0; v < nv; v++ {
		e.Witness(VRFName(v))
	}
	for site := 0; site < s.Sites; site++ {
		e.Witness(VRFName(site%nv) + "|" + s.SitePrefix(site))
		k := site / nv
		for j := 1; j <= kids; j++ {
			e.Witness(fmt.Sprintf("10.%d.%d.0/24", k, j))
		}
	}
	return nil
}

func ipamStatements(e *Env) []ipamStatement {
	s := e.Scale
	nv, kids, ips := s.VRFs(), s.PrefixesPerSite-1, s.IPsPerPrefix
	// Joins, not per-row subqueries: 200,000 address rows each looking up
	// their VRF by name would dominate the populate time.
	siteVRF := `generate_series(0, $3 - 1) s JOIN public.vrfs f ON f.tenant_id = $1 AND f.name = 'vrf-' || lpad((s % $2)::text, 2, '0')`
	stmts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO public.vrfs (tenant_id, name, rd) SELECT $1, 'vrf-' || lpad(v::text, 2, '0'), '65000:' || v FROM generate_series(0, $2 - 1) v`, []any{e.Tenant, nv}},
		{`INSERT INTO public.route_targets (tenant_id, name) SELECT $1, '65000:' || (1000 + v) FROM generate_series(0, $2 - 1) v`, []any{e.Tenant, nv}},
		{`INSERT INTO public.vrf_import_targets (tenant_id, vrf_id, route_target_id)
		    SELECT $1, f.id, r.id FROM public.vrfs f JOIN public.route_targets r ON r.tenant_id = $1
		       AND r.name = '65000:' || (1000 + substr(f.name, 5)::int) WHERE f.tenant_id = $1`, []any{e.Tenant}},
		{`INSERT INTO public.vrf_export_targets (tenant_id, vrf_id, route_target_id)
		    SELECT tenant_id, vrf_id, route_target_id FROM public.vrf_import_targets WHERE tenant_id = $1`, []any{e.Tenant}},
		// One aggregate per RFC 1918 / RFC 4193 range, from addrscope (the one
		// definition of private address space), under its RIR.
		{`INSERT INTO public.aggregates (tenant_id, prefix, rir_id, date_added)
		    SELECT $1, p::cidr, (SELECT id FROM public.rirs WHERE tenant_id IS NULL
		                          AND slug = CASE WHEN family(p::cidr) = 4 THEN 'rfc-1918' ELSE 'rfc-4193' END), DATE '2026-01-01'
		      FROM unnest($2::text[]) p`, []any{e.Tenant, pq.Array(privatePrefixes())}},
		{`INSERT INTO public.vlan_groups (tenant_id, name, slug) SELECT $1, 'site-' || lpad(s::text, 4, '0'), 'site-' || lpad(s::text, 4, '0') FROM generate_series(0, $2 - 1) s`, []any{e.Tenant, s.Sites}},
		{`INSERT INTO public.vlans (tenant_id, vid, name, group_id, status)
		    SELECT $1, j + 1, 'vlan-' || (j + 1), g.id, 'active'
		      FROM public.vlan_groups g, generate_series(1, $2) j WHERE g.tenant_id = $1`, []any{e.Tenant, kids}},
		{`INSERT INTO public.prefixes (tenant_id, vrf_id, prefix, operational_status, network_type, environment, vlan_id, dhcp_managed, first_seen_at, last_seen_at)
		    SELECT $1, f.id, ('10.' || (s / $2) || '.0.0/16')::cidr, 'container', 'corporate', 'production', NULL::uuid, NULL::boolean, $5::timestamptz, $5::timestamptz
		      FROM ` + siteVRF + `
		    UNION ALL
		    SELECT $1, f.id, ('10.' || (s / $2) || '.' || j || '.0/24')::cidr, 'active', NULL, NULL, v.id, j % 4 = 0, $5::timestamptz, $5::timestamptz
		      FROM ` + siteVRF + `
		      CROSS JOIN generate_series(1, $4) j
		      JOIN public.vlan_groups g ON g.tenant_id = $1 AND g.name = 'site-' || lpad(s::text, 4, '0')
		      JOIN public.vlans v ON v.tenant_id = $1 AND v.group_id = g.id AND v.vid = j + 1`, []any{e.Tenant, nv, s.Sites, kids, Epoch}},
		{`INSERT INTO public.ip_ranges (tenant_id, vrf_id, start_address, end_address, size, mark_utilized, operational_status)
		    SELECT $1, f.id, ('10.' || (s / $2) || '.255.1')::inet, ('10.' || (s / $2) || '.255.50')::inet, 50, true, 'reserved'
		      FROM ` + siteVRF, []any{e.Tenant, nv, s.Sites}},
		{`INSERT INTO public.ip_addresses (tenant_id, vrf_id, address, status, source_kind, last_seen_source, first_seen_at, last_seen_at, observation_count)
		    SELECT $1, f.id, ('10.' || (s / $2) || '.' || j || '.' || h || '/24')::inet, 'active', 'measured', 'arp', $5, $5, 1
		      FROM ` + siteVRF + ` CROSS JOIN generate_series(0, $4) j CROSS JOIN generate_series(1, $6) h`, []any{e.Tenant, nv, s.Sites, kids, Epoch, ips}},
		// The cache, as the service would compute it: a /24 counts its
		// addresses over 254; a container counts its children's space.
		{`INSERT INTO public.prefix_utilization (prefix_id, tenant_id, child_count, ip_count, utilization, refreshed_at)
		    SELECT p.id, $1,
		           CASE WHEN p.operational_status = 'container' THEN $2 ELSE 0 END,
		           CASE WHEN p.operational_status = 'container' THEN $3 * ($2 + 1) ELSE $3 END,
		           CASE WHEN p.operational_status = 'container' THEN round(100.0 * $2 * 256 / 65536, 2)
		                ELSE round(100.0 * $3 / 254, 2) END,
		           $4
		      FROM public.prefixes p WHERE p.tenant_id = $1`, []any{e.Tenant, kids, ips, Epoch}},
		{`INSERT INTO public.fhrp_groups (tenant_id, protocol, group_id, name)
		    SELECT $1, 'vrrp3', 1 + s % 255, 'site-' || lpad(s::text, 4, '0') || '-gw' FROM generate_series(0, $2 - 1) s`, []any{e.Tenant, s.Sites}},
		{`INSERT INTO public.asns (tenant_id, asn, rir_id)
		    SELECT $1, 4200000000 + s, (SELECT id FROM public.rirs WHERE tenant_id IS NULL AND slug = 'arin') FROM generate_series(0, $2 - 1) s`, []any{e.Tenant, s.Sites}},
	}
	out := make([]ipamStatement, len(stmts))
	for i, st := range stmts {
		out[i] = ipamStatement{table: ipamStatementTables[i], sql: st.sql, args: st.args}
	}
	return out
}
