package sql

// Virtual circuit fields on the asset target (DCIM gap 10; QUERY_LANGUAGE
// §15): a virtual circuit one of the asset's interfaces terminates. Computed
// at query time from virtual_circuit_terminations, none stored on the asset.
//
//   virtual_circuit           the circuit's ID (cid), or its type's name or slug
//   virtual_circuit.cid       the cid alone
//   virtual_circuit.provider  the provider (of the circuit's provider network), by name or slug
//   virtual_circuit.role      the asset interface's role in it (peer, hub, spoke)
//
// Row-shaped like the tunnel fields: `!=` negates the whole EXISTS, so an
// asset with no virtual circuit satisfies it.

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
)

func isVirtualCircuitDerived(d string) bool {
	return d == "asset.virtual_circuit" || strings.HasPrefix(d, "asset.virtual_circuit.")
}

func (b *builder) virtualCircuitOver(sc scope, f ast.FieldRef, sp ast.Span, inner func(expr) string) string {
	vt, ifc, vc := b.alias("vct"), b.alias("vif"), b.alias("vc")
	// No tenant predicate: row-level security scopes every relation.
	from := "virtual_circuit_terminations " + vt +
		" JOIN interfaces " + ifc + " ON " + ifc + ".id = " + vt + ".interface_id" +
		" JOIN virtual_circuits " + vc + " ON " + vc + ".id = " + vt + ".virtual_circuit_id"
	where := ifc + ".asset_id = " + sc.self + ".id AND " + ifc + ".status <> " + b.param("rejected")
	var cond string
	switch f.Accessor.Derived {
	case "asset.virtual_circuit":
		ty := b.alias("vcy")
		from += " JOIN virtual_circuit_types " + ty + " ON " + ty + ".id = " + vc + ".type_id"
		cond = "(" + inner(expr{alias: vc, sql: vc + ".cid"}) +
			" OR " + inner(expr{alias: ty, sql: ty + ".name"}) +
			" OR " + inner(expr{alias: ty, sql: ty + ".slug"}) + ")"
	case "asset.virtual_circuit.cid":
		cond = inner(expr{alias: vc, sql: vc + ".cid"})
	case "asset.virtual_circuit.provider":
		pn, pv := b.alias("vpn"), b.alias("vpv")
		from += " JOIN provider_networks " + pn + " ON " + pn + ".id = " + vc + ".provider_network_id" +
			" JOIN providers " + pv + " ON " + pv + ".id = " + pn + ".provider_id"
		cond = "(" + inner(expr{alias: pv, sql: pv + ".name"}) +
			" OR " + inner(expr{alias: pv, sql: pv + ".slug"}) + ")"
	case "asset.virtual_circuit.role":
		cond = inner(expr{alias: vt, sql: vt + ".role"})
	default:
		return b.fail(sp, "field %q has no virtual circuit builder", f.Text)
	}
	return "EXISTS (SELECT 1 FROM " + from + " WHERE " + where + " AND " + cond + ")"
}
