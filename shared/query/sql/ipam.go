package sql

// IPAM fields on the asset target (DCIM BUILD_PLAN row 1.3; QUERY_LANGUAGE §15
// D2): the asset's IP addresses (`ip.`), the longest-match prefix of each in
// its VRF (`prefix.`), that prefix's VLAN (`vlan.`) and the address's VRF
// (`vrf.`). All computed at query time, none stored on the asset.
//
// "The asset's addresses" are the ip_addresses rows its primary and
// out-of-band columns name (`primary_ip4_id`, `primary_ip6_id`, `oob_ip_id`)
// and, since row 1.4, every address assigned to one of its interfaces — where
// the identity engine files the addresses it observes.
//
// Every field is row-shaped: `ip.address:10.0.0.0/24` is "some address of the
// asset is in 10.0.0.0/24", and `!=` negates the whole EXISTS (rowShaped).

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

// zeroUUID folds the global table (vrf_id IS NULL) into a comparable key, the
// same fold the schema's identity indexes use.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

func isIPAMDerived(d string) bool {
	for _, p := range []string{"asset.ip.", "asset.prefix.", "asset.vlan.", "asset.vrf."} {
		if strings.HasPrefix(d, p) {
			return true
		}
	}
	return false
}

var ipamColumns = map[string]string{
	"asset.ip.address":          "host",
	"asset.ip.dns_name":         "dns_name",
	"asset.ip.status":           "operational_status",
	"asset.ip.role":             "role",
	"asset.prefix.prefix":       "prefix",
	"asset.prefix.status":       "operational_status",
	"asset.prefix.network_type": "network_type",
	"asset.vlan.vid":            "vid",
	"asset.vlan.name":           "name",
	"asset.vrf.name":            "name",
}

func (b *builder) ipamOver(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	col, ok := ipamColumns[f.Accessor.Derived]
	if !ok {
		return b.fail(sp, "field %q has no IPAM builder", f.Text)
	}
	a, ok := b.assetAlias(sc, f, sp)
	if !ok {
		return "FALSE"
	}
	ip := b.alias("ip")
	from := "ip_addresses " + ip
	// No tenant predicate anywhere: row-level security scopes every relation
	// to the caller's tenant, and the translator never writes one (the
	// conformance suite refuses SQL that does).
	ifc := b.alias("ifc")
	where := "(" + ip + ".id IN (" + a + ".primary_ip4_id, " + a + ".primary_ip6_id, " + a + ".oob_ip_id)" +
		" OR (" + ip + ".assigned_kind = " + b.param("interface") + " AND " + ip + ".assigned_id IN (SELECT " + ifc + ".id FROM interfaces " + ifc +
		" WHERE " + ifc + ".asset_id = " + a + ".id)))" +
		" AND " + ip + ".status <> " + b.param("rejected")
	var val expr
	switch {
	case strings.HasPrefix(f.Accessor.Derived, "asset.ip."):
		val = expr{alias: ip, sql: ip + "." + col}
	case f.Accessor.Derived == "asset.vrf.name":
		vrf := b.alias("vrf")
		from += " JOIN vrfs " + vrf + " ON " + vrf + ".id = " + ip + ".vrf_id"
		val = expr{alias: vrf, sql: vrf + "." + col}
	default:
		// The longest-match prefix of the address, within its VRF.
		p, px := b.alias("p"), b.alias("px")
		zero := b.param(zeroUUID) + "::uuid"
		from += " JOIN LATERAL (SELECT " + p + ".* FROM prefixes " + p +
			" WHERE COALESCE(" + p + ".vrf_id, " + zero + ") = COALESCE(" + ip + ".vrf_id, " + zero + ")" +
			" AND " + p + ".prefix >>= " + ip + ".host AND " + p + ".status <> " + b.param("rejected") +
			" ORDER BY masklen(" + p + ".prefix) DESC LIMIT 1) " + px + " ON TRUE"
		if strings.HasPrefix(f.Accessor.Derived, "asset.vlan.") {
			vl := b.alias("vl")
			from += " JOIN vlans " + vl + " ON " + vl + ".id = " + px + ".vlan_id"
			val = expr{alias: vl, sql: vl + "." + col}
		} else {
			val = expr{alias: px, sql: px + "." + col}
			if col == "prefix" {
				// cidr compares as inet for containment.
				val.sql = "(" + val.sql + ")::inet"
			}
		}
	}
	return "EXISTS (SELECT 1 FROM " + from + " WHERE " + where + " AND " + inner(val) + ")"
}
