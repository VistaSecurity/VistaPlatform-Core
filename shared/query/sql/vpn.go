package sql

// Tunnel fields on the asset target (DCIM BUILD_PLAN row 4.3; QUERY_LANGUAGE
// §15): `tunnel` (a tunnel one of the asset's interfaces terminates, by name),
// `tunnel.encapsulation`, `tunnel.ike_version` and `tunnel.pfs_group` (through
// the tunnel's IPsec profile). Row-shaped: `!=` negates the whole EXISTS.

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

func isTunnelDerived(d string) bool {
	return d == "asset.tunnel" || strings.HasPrefix(d, "asset.tunnel.")
}

func (b *builder) tunnelOver(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	tt, ifc, tn := b.alias("tt"), b.alias("tif"), b.alias("tn")
	from := "tunnel_terminations " + tt +
		" JOIN interfaces " + ifc + " ON " + ifc + ".id = " + tt + ".termination_id" +
		" JOIN tunnels " + tn + " ON " + tn + ".id = " + tt + ".tunnel_id"
	where := ifc + ".asset_id = " + sc.self + ".id AND " + tn + ".status <> " + b.param("rejected")
	var val expr
	switch f.Accessor.Derived {
	case "asset.tunnel":
		val = expr{alias: tn, sql: tn + ".name"}
	case "asset.tunnel.encapsulation":
		val = expr{alias: tn, sql: tn + ".encapsulation"}
	case "asset.tunnel.ike_version":
		pr, ip := b.alias("tpr"), b.alias("tik")
		from += " JOIN ipsec_profiles " + pr + " ON " + pr + ".id = " + tn + ".ipsec_profile_id" +
			" JOIN ike_policies " + ip + " ON " + ip + ".id = " + pr + ".ike_policy_id"
		val = expr{alias: ip, sql: ip + ".version"}
	case "asset.tunnel.pfs_group":
		pr, sp2 := b.alias("tpr"), b.alias("tsp")
		from += " JOIN ipsec_profiles " + pr + " ON " + pr + ".id = " + tn + ".ipsec_profile_id" +
			" JOIN ipsec_policies " + sp2 + " ON " + sp2 + ".id = " + pr + ".ipsec_policy_id"
		val = expr{alias: sp2, sql: sp2 + ".pfs_group"}
	default:
		return b.fail(sp, "field %q has no tunnel builder", f.Text)
	}
	return "EXISTS (SELECT 1 FROM " + from + " WHERE " + where + " AND " + inner(val) + ")"
}
