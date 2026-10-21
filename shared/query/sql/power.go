package sql

// Power-feed fields on the asset target (DCIM BUILD_PLAN row 6.1;
// QUERY_LANGUAGE §15): the power feeds an asset's power ports reach — the
// complete cable paths (cable_paths, origin a power port of the asset,
// destination a power feed) that shared/dcim/cablepath keeps, through a PDU
// when there is one. Computed at query time, none stored on the asset.
//
// Row-shaped like the cabling fields: `power_feed.status = failed` is "some
// feed the asset draws from has failed", and `!=` negates the whole EXISTS.
// `power_feed.panel`, `.rack` and `.site` match the feed's panel, the rack it
// serves and its panel's site by name (a site also by slug).

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

func isPowerDerived(d string) bool { return strings.HasPrefix(d, "asset.power_feed.") }

var powerFeedColumns = map[string]string{
	"asset.power_feed.status":          "operational_status",
	"asset.power_feed.type":            "type",
	"asset.power_feed.supply":          "supply",
	"asset.power_feed.phase":           "phase",
	"asset.power_feed.voltage":         "voltage",
	"asset.power_feed.amperage":        "amperage",
	"asset.power_feed.available_power": "available_power",
}

func (b *builder) powerOver(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	a, ok := b.assetAlias(sc, f, sp)
	if !ok {
		return "FALSE"
	}
	pp, cp, pf := b.alias("ppt"), b.alias("pcp"), b.alias("pf")
	// No tenant predicate: row-level security scopes every relation.
	from := "power_ports " + pp + " JOIN cable_paths " + cp + " ON " + cp + ".origin_kind = " + b.param("power_port") +
		" AND " + cp + ".origin_id = " + pp + ".id AND " + cp + ".destination_kind = " + b.param("power_feed") + " AND " + cp + ".is_complete" +
		" JOIN power_feeds " + pf + " ON " + pf + ".id = " + cp + ".destination_id"
	where := pp + ".asset_id = " + a + ".id AND " + pp + ".status <> " + b.param("rejected")
	var cond string
	switch f.Accessor.Derived {
	case "asset.power_feed.panel":
		pn := b.alias("ppn")
		from += " JOIN power_panels " + pn + " ON " + pn + ".id = " + pf + ".power_panel_id"
		cond = inner(expr{alias: pn, sql: pn + ".name"})
	case "asset.power_feed.rack":
		rk := b.alias("prk")
		from += " JOIN racks " + rk + " ON " + rk + ".id = " + pf + ".rack_id"
		cond = inner(expr{alias: rk, sql: rk + ".name"})
	case "asset.power_feed.site":
		pn, st := b.alias("ppn"), b.alias("pst")
		from += " JOIN power_panels " + pn + " ON " + pn + ".id = " + pf + ".power_panel_id JOIN sites " + st + " ON " + st + ".id = " + pn + ".site_id"
		cond = "(" + inner(expr{alias: st, sql: st + ".name"}) + " OR " + inner(expr{alias: st, sql: st + ".slug"}) + ")"
	default:
		col, ok := powerFeedColumns[f.Accessor.Derived]
		if !ok {
			return b.fail(sp, "field %q has no power builder", f.Text)
		}
		cond = inner(expr{alias: pf, sql: pf + "." + col})
	}
	return "EXISTS (SELECT 1 FROM " + from + " WHERE " + where + " AND " + cond + ")"
}
