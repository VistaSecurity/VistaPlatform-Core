package sql

// Wireless fields on the asset target (DCIM BUILD_PLAN row 4.4; QUERY_LANGUAGE
// §15): the wireless LANs an asset's interfaces serve. Computed at query time
// from interfaces.wireless_lan_ids, none stored on the asset.
//
// Row-shaped like the IPAM fields: `wireless_lan.ssid:Guest` is "some LAN the
// asset serves is Guest", and `!=` negates the whole EXISTS (rowShaped).

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

func isWirelessDerived(d string) bool { return strings.HasPrefix(d, "asset.wireless_lan.") }

var wirelessColumns = map[string]string{
	"asset.wireless_lan.ssid":      "ssid",
	"asset.wireless_lan.auth_type": "auth_type",
}

func (b *builder) wirelessOver(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	col, ok := wirelessColumns[f.Accessor.Derived]
	if !ok {
		return b.fail(sp, "field %q has no wireless builder", f.Text)
	}
	a, ok := b.assetAlias(sc, f, sp)
	if !ok {
		return "FALSE"
	}
	ifc, wl := b.alias("ifc"), b.alias("wl")
	// No tenant predicate: row-level security scopes every relation.
	from := "interfaces " + ifc + " JOIN wireless_lans " + wl + " ON " + wl + ".id = ANY(" + ifc + ".wireless_lan_ids)"
	where := ifc + ".asset_id = " + a + ".id AND " + ifc + ".status <> " + b.param("rejected") +
		" AND " + wl + ".status <> " + b.param("rejected")
	return "EXISTS (SELECT 1 FROM " + from + " WHERE " + where + " AND " + inner(expr{alias: wl, sql: wl + "." + col}) + ")"
}
