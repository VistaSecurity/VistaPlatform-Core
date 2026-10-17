package sql

// Cabling fields on the asset target (DCIM BUILD_PLAN row 3.2; QUERY_LANGUAGE
// §15): the cables on an asset's components, through cable_terminations'
// denormalised asset_id. Computed at query time, none stored on the asset.
//
// Row-shaped like the wireless fields: `cable.type = cat6` is "some cable on
// the asset is CAT6", and `!=` negates the whole EXISTS (rowShaped).
// `cabled_to` is the asset on the far end of one of those cables (the link
// peer, not the end of a path through patch panels), by hostname or display
// name.

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

func isCablingDerived(d string) bool {
	return strings.HasPrefix(d, "asset.cable.") || d == "asset.cabled_to"
}

var cablingColumns = map[string]string{
	"asset.cable.type":   "type",
	"asset.cable.status": "operational_status",
}

func (b *builder) cablingOver(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	a, ok := b.assetAlias(sc, f, sp)
	if !ok {
		return "FALSE"
	}
	ct, cb := b.alias("ctn"), b.alias("cb")
	// No tenant predicate: row-level security scopes every relation.
	from := "cable_terminations " + ct + " JOIN cables " + cb + " ON " + cb + ".id = " + ct + ".cable_id"
	where := ct + ".asset_id = " + a + ".id AND " + cb + ".status <> " + b.param("rejected")
	if f.Accessor.Derived == "asset.cabled_to" {
		far, fa := b.alias("far"), b.alias("fa")
		from += " JOIN cable_terminations " + far + " ON " + far + ".cable_id = " + ct + ".cable_id AND " + far + ".cable_end <> " + ct + ".cable_end" +
			" JOIN assets " + fa + " ON " + fa + ".id = " + far + ".asset_id"
		return "EXISTS (SELECT 1 FROM " + from + " WHERE " + where + " AND " + fa + ".deleted_at IS NULL AND (" +
			inner(expr{alias: fa, sql: fa + ".hostname"}) + " OR " + inner(expr{alias: fa, sql: fa + ".display_name"}) + "))"
	}
	col, ok := cablingColumns[f.Accessor.Derived]
	if !ok {
		return b.fail(sp, "field %q has no cabling builder", f.Text)
	}
	return "EXISTS (SELECT 1 FROM " + from + " WHERE " + where + " AND " + inner(expr{alias: cb, sql: cb + "." + col}) + ")"
}
