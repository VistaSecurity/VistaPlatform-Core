package sql

import (
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// The child-collection and traversal shapes — §7.2's shapes 3 and 4.
//
// The join chains live here, in code, rather than in the catalogue: they are
// the whitelist. A collection pair that is not in the switch below has no SQL
// shape and is refused, so adding a collection is a deliberate act with a
// reviewed join path, not a catalogue entry that silently starts generating
// queries.

// sub builds an EXISTS over a child collection (§5.1). `exists(<collection>)`
// arrives here with a nil predicate and means "at least one row".
func (b *builder) sub(t *ast.Sub, sc scope) string {
	innerName, ok := catalog.CollectionTarget[t.Collection]
	if !ok {
		return b.fail(t.Sp, "unknown collection %q", t.Collection)
	}
	innerTgt, ok := catalog.FindTarget(b.cat, innerName)
	if !ok {
		return b.fail(t.Sp, "the catalogue has no target for collection %q", t.Collection)
	}

	if t.Collection == "finding" && sc.target.Name == "asset" {
		return b.findingSub(t, sc, innerTgt)
	}

	from, correlate, child, ok := b.childShape(sc, t.Collection, innerTgt, t.Sp)
	if !ok {
		return "FALSE"
	}
	clause := "EXISTS (SELECT 1 FROM " + from + " WHERE " + correlate
	if t.Predicate != nil {
		clause += " AND " + b.node(t.Predicate, child)
	}
	return clause + ")"
}

// childShape returns the FROM fragment, the correlation predicate and the scope
// an inner predicate is translated in, for one (target, collection) pair.
func (b *builder) childShape(sc scope, collection string, inner catalog.Target, sp ast.Span) (from, correlate string, child scope, ok bool) {
	self := sc.self
	newScope := func(alias string, rels map[string]string, assetAlias string) scope {
		if rels == nil {
			rels = map[string]string{}
		}
		return scope{target: inner, self: alias, rels: rels, assetAlias: assetAlias}
	}

	switch sc.target.Name + "/" + collection {
	case "asset/endpoint":
		e := b.alias("e")
		return "asset_endpoints " + e, e + ".asset_id = " + self + ".id",
			newScope(e, nil, sc.assetAlias), true

	case "asset/software":
		si, sp2 := b.alias("si"), b.alias("sp")
		return "software_installs " + si + " JOIN software_products " + sp2 +
				" ON " + sp2 + ".id = " + si + ".product_id",
			si + ".asset_id = " + self + ".id",
			newScope(si, map[string]string{"product": sp2}, sc.assetAlias), true

	case "asset/identifier":
		ai := b.alias("ai")
		return b.identifierRows() + " " + ai, ai + ".asset_id = " + self + ".id",
			newScope(ai, nil, sc.assetAlias), true

	case "asset/relationship":
		// Either end: an edge "of" an asset is one it takes part in. Traversal
		// is the directional form; this collection is the raw edge list, and
		// it does not filter on status, which is how §5.6's
		// `relationship:(status:pending)` escape hatch works.
		r := b.alias("r")
		return "asset_relationships " + r,
			"(" + r + ".from_asset_id = " + self + ".id OR " + r + ".to_asset_id = " + self + ".id)",
			newScope(r, nil, sc.assetAlias), true

	case "asset/crypto":
		// LEFT JOIN, not JOIN: see configurationAssetID below.
		ci, e := b.alias("ci"), b.alias("e")
		return "crypto_implementations " + ci + " LEFT JOIN asset_endpoints " + e +
				" ON " + e + ".id = " + ci + ".endpoint_id",
			configurationOwnedBy(ci, e, self),
			newScope(ci, nil, sc.assetAlias), true

	case "asset/cert":
		// The junction is the only link read, deliberately: fixed the
		// leaf-certificate divergence at the WRITE side rather than unioning
		// `crypto_implementations.certificate_id` into every reader.
		c, cic, ci, e := b.alias("c"), b.alias("cic"), b.alias("ci"), b.alias("e")
		return "certificates " + c +
				" JOIN crypto_implementation_certificates " + cic + " ON " + cic + ".certificate_id = " + c + ".id" +
				" JOIN crypto_implementations " + ci + " ON " + ci + ".id = " + cic + ".crypto_implementation_id" +
				" LEFT JOIN asset_endpoints " + e + " ON " + e + ".id = " + ci + ".endpoint_id",
			configurationOwnedBy(ci, e, self),
			newScope(c, nil, sc.assetAlias), true

	case "endpoint/crypto":
		// An INNER match on endpoint_id, and correctly so: this asks for the
		// configurations measured at ONE socket, and a configuration with no
		// endpoint was measured at none. `endpoint_id = <e>.id` is UNKNOWN
		// where the column is NULL, so such a row is excluded rather than
		// attached to an arbitrary endpoint. Reaching it is the ASSET's job.
		ci := b.alias("ci")
		return "crypto_implementations " + ci, ci + ".endpoint_id = " + self + ".id",
			newScope(ci, nil, sc.assetAlias), true

	case "endpoint/cert":
		c, cic, ci := b.alias("c"), b.alias("cic"), b.alias("ci")
		return "certificates " + c +
				" JOIN crypto_implementation_certificates " + cic + " ON " + cic + ".certificate_id = " + c + ".id" +
				" JOIN crypto_implementations " + ci + " ON " + ci + ".id = " + cic + ".crypto_implementation_id",
			ci + ".endpoint_id = " + self + ".id",
			newScope(c, nil, sc.assetAlias), true

	case "crypto_configuration/cert":
		// No endpoint in the chain at all, so nothing to fix here: a
		// configuration's certificates are whatever the junction links to it.
		c, cic := b.alias("c"), b.alias("cic")
		return "certificates " + c +
				" JOIN crypto_implementation_certificates " + cic + " ON " + cic + ".certificate_id = " + c + ".id",
			cic + ".crypto_implementation_id = " + self + ".id",
			newScope(c, nil, sc.assetAlias), true

	case "asset/interface":
		// DCIM BUILD_PLAN row 1.2. A rejected observation is kept only so it
		// is recognised next time; it is not one of the asset's interfaces.
		ifc := b.alias("ifc")
		return "interfaces " + ifc,
			ifc + ".asset_id = " + self + ".id AND " + ifc + ".status <> " + b.param("rejected"),
			newScope(ifc, nil, sc.assetAlias), true

	case "endpoint/asset", "software_install/asset", "identifier/asset", "interface/asset":
		a := b.alias("a")
		return "assets " + a, a + ".id = " + self + "." + sc.target.AssetIDColumn,
			newScope(a, nil, a), true

	case "crypto_configuration/asset":
		// The lookup rendering of configurationAssetID: there is nothing to
		// LEFT JOIN the endpoint ONTO here, because the configuration is the
		// outer row. Writing it as `assets a LEFT JOIN asset_endpoints e ON
		// e.id = <self>.endpoint_id` would parse, but the join condition names
		// no column of `assets`, so the planner has to materialise every asset
		// in the tenant before it can filter — a scalar lookup keeps this a
		// primary-key probe on both tables.
		a, e := b.alias("a"), b.alias("e")
		return "assets " + a,
			a + ".id = " + configurationAssetID(self,
				"(SELECT "+e+".asset_id FROM asset_endpoints "+e+
					" WHERE "+e+".id = "+self+".endpoint_id)"),
			newScope(a, nil, a), true

	case "certificate/asset":
		// Walks UP the same chain asset/cert walks down, so it has to agree
		// with it row for row: junction → configuration → (endpoint, where
		// there is one) → asset.
		cic, ci, e, a := b.alias("cic"), b.alias("ci"), b.alias("e"), b.alias("a")
		return "crypto_implementation_certificates " + cic +
				" JOIN crypto_implementations " + ci + " ON " + ci + ".id = " + cic + ".crypto_implementation_id" +
				" LEFT JOIN asset_endpoints " + e + " ON " + e + ".id = " + ci + ".endpoint_id" +
				" JOIN assets " + a + " ON " + a + ".id = " + configurationAssetID(ci, e+".asset_id"),
			cic + ".certificate_id = " + self + ".id",
			newScope(a, nil, a), true

	case "finding/asset":
		a := b.alias("a")
		return "assets " + a,
			"(" + a + ".id = " + self + ".subject_id AND " + self + ".subject_type = " + b.param("asset") + ")",
			newScope(a, nil, a), true
	}

	b.reject(sp, "%q is not reachable from %q; there is no SQL shape for that pair", collection, sc.target.Name)
	return "", "", scope{}, false
}

// configurationAssetID is the expression for "the asset this crypto
// configuration belongs to", given the configuration's alias and the SQL that
// resolves its ENDPOINT's asset — NULL where it has no endpoint.
//
// `crypto_implementations.endpoint_id` is NULLABLE and documented as such:
// "NULL for a configuration that is not tied to one socket: an at-rest cloud
// resource has no endpoint at all … asset_id stays and is the roll-up target"
// (schema.sql). The `asset/crypto` and `asset/cert` shapes inner-joined it, so
// `crypto:(…)` and `cert:(…)` from an asset — the inventory facet rail, saved
// views, the `ask` seam, a compliance measurement over the `asset` shape — could
// not see a single at-rest configuration, nor any certificate reachable only
// through one. §5.1 defines those collections as EXISTS over the asset's
// children, so that was a defect and not a narrowing anyone chose.
//
// The endpoint stays AUTHORITATIVE where there is one: a configuration whose
// endpoint moves to another asset follows the endpoint. The fallback applies
// only where the walk has no endpoint to follow.
//
// This is the same rule, spelled the same way, as shared/findings.AssetSubjects
// () — and it has to be: `finding:(…)` resolves through that one
// and `crypto:(…)` through this one, over the same rows. Two spellings of one
// intention is the drift that got the has_findings facet withdrawn in Gate 1.
// TestAssetChildShapes_AgreeWithFindingsSubjectPaths pins them together.
//
// COALESCE rather than the OR form `(endpoint_id = e.id AND e.asset_id = …) OR
// (endpoint_id IS NULL AND asset_id = …)`: one equality can be a hash key, so a
// whole-inventory scan stays a hash semi-join, where the OR would force a nested
// loop. Both joins it reaches through are on indexed columns
// (`asset_endpoints` PK, `idx_crypto_implementations_partitioned_asset_id`), and
// neither carries a tenant predicate — by design, the translator emits none and
// RLS does the scoping (§7.2).
func configurationAssetID(ci, endpointAssetID string) string {
	return "COALESCE(" + endpointAssetID + ", " + ci + ".asset_id)"
}

// configurationOwnedBy is configurationAssetID as a correlation predicate, for a
// shape that has already LEFT JOINed the endpoint as `e`.
func configurationOwnedBy(ci, e, asset string) string {
	return configurationAssetID(ci, e+".asset_id") + " = " + asset + ".id"
}

// findingSub resolves `finding:(…)` over findings whose subject is the asset or
// any of its descendants — its endpoints, the crypto configurations and
// certificates at those endpoints, and its software installs (§5.1, Q4).
// "Assets with a critical finding" is what the question means; most findings
// are on configurations and certificates, so the asset-only reading would
// return almost nothing.
// The five subject paths themselves live in shared/findings, NOT here, because
// this is not the only reader that has to walk them: the per-asset findings read
// behind the asset page's Findings tab and the `has_findings` facet count ask
// the same question and must return the same set. Two spellings of that
// intention is exactly the drift that got the facet withdrawn in Gate 1 — it
// counted one table while the click it produced queried another.
func (b *builder) findingSub(t *ast.Sub, sc scope, inner catalog.Target) string {
	a := sc.self
	f := b.alias("f")
	child := scope{target: inner, self: f, rels: map[string]string{}, assetAlias: sc.assetAlias}

	// b.param, not a literal: every value this builder emits is bound, and the
	// subject types are no exception even though they are code constants.
	subjects := findings.AssetSubjectClause(f, a, b.alias, func(subjectType string) string {
		return b.param(subjectType)
	})

	clause := "EXISTS (SELECT 1 FROM findings " + f + " WHERE (" + subjects + ")"
	if t.Predicate != nil {
		clause += " AND " + b.node(t.Predicate, child)
	}
	return clause + ")"
}

// traverse builds §7.2's shape 4: a depth-bounded recursive CTE over
// asset_relationships, joined back to assets and wrapped in an EXISTS.
//
// Edges whose status is not active are excluded (§5.6); a query that wants the
// others asks for them with `relationship:(status:pending)` at the outer level.
//
// The CTE carries (id, depth) and nothing else, and the recursive term is
// UNION — not UNION ALL — so a node reached by several routes at the same depth
// produces ONE row (§13 A7). That is measured, not assumed: over a four-layer
// mesh of sixteen nodes the old shape produced 340 rows and this one 16. It is
// also bounded in a way the old one was not: at most |reachable| × depth rows,
// against the number of distinct simple PATHS, which is exponential in a dense
// graph. Two hops through a busy switch is a dense graph.
//
// The visited-path array had to go with UNION ALL, because keeping it defeats
// the deduplication entirely — every route to a node carries a different path,
// so the rows are distinct and UNION removes nothing. (Measured: 340 either
// way. Postgres's SEARCH/CYCLE clause does not help for the same reason, and on
// a graph with a cycle it produced twice the rows.) Cycle-safety does not
// depend on it: termination comes from the depth bound, which §5.6 caps at 6,
// and the REACHABLE SET is identical either way — a walk that revisits a node
// reaches nothing a shorter simple walk does not.
//
// What the path did do besides pruning is exclude the starting asset from its
// own result, and that IS semantic: "what does this asset depend on" should not
// answer "itself" because of a cycle three hops out. So the source is excluded
// explicitly, in both terms. Nothing is lost: anything reachable THROUGH the
// source is reachable FROM it at a lower depth.
func (b *builder) traverse(t *ast.Traverse, sc scope) string {
	if !sc.target.Traversable || sc.assetAlias == "" {
		return b.fail(t.Sp, "relationships join assets; %q is not traversable", sc.target.Name)
	}
	assetTgt, ok := catalog.FindTarget(b.cat, "asset")
	if !ok {
		return b.fail(t.Sp, "the catalogue has no asset target")
	}

	dir := t.Direction
	typ := t.Type
	if t.Form == ast.FormNamed {
		// The name resolves to a canonical type and the direction it walks.
		if rel, found := ast.LookupRelationship(t.Name); found {
			typ, dir = rel.Type, rel.Direction
		} else {
			return b.fail(t.Sp, "unknown relationship %q", t.Name)
		}
	}

	cte := b.alias("w")
	edge := b.alias("r")
	edge2 := b.alias("r")
	target := b.alias("a")
	src := sc.assetAlias

	status := b.param("active")
	depth := b.param(t.Depth)
	var typeParam string
	if typ != "" {
		typeParam = b.param(typ)
	}

	typeClause := func(alias string) string {
		if typeParam == "" {
			return ""
		}
		return " AND " + alias + ".type = " + typeParam
	}

	anchorJoin, anchorNext := edgeStep(edge, dir, src+".id")
	stepJoin, stepNext := edgeStep(edge2, dir, cte+".id")

	anchor := "SELECT " + anchorNext + " AS id, 1 AS depth" +
		" FROM asset_relationships " + edge +
		" WHERE " + anchorJoin + " AND " + edge + ".status = " + status + typeClause(edge) +
		" AND " + anchorNext + " <> " + src + ".id"

	step := "SELECT " + stepNext + ", " + cte + ".depth + 1" +
		" FROM " + cte + " JOIN asset_relationships " + edge2 + " ON " + stepJoin +
		" WHERE " + cte + ".depth < " + depth +
		" AND " + edge2 + ".status = " + status + typeClause(edge2) +
		" AND " + stepNext + " <> " + src + ".id"

	child := scope{target: assetTgt, self: target, rels: map[string]string{}, assetAlias: target}
	inner := b.node(t.Predicate, child)

	return "EXISTS (WITH RECURSIVE " + cte + "(id, depth) AS (" +
		anchor + " UNION " + step + ")" +
		" SELECT 1 FROM " + cte + " JOIN assets " + target + " ON " + target + ".id = " + cte + ".id" +
		" WHERE " + inner + ")"
}

// edgeStep returns the predicate that attaches an edge to the current node and
// the expression for the node at the other end, for one direction.
func edgeStep(edge string, dir ast.Direction, from string) (join, next string) {
	switch dir {
	case ast.DirIn:
		return edge + ".to_asset_id = " + from, edge + ".from_asset_id"
	case ast.DirAny:
		return "(" + edge + ".from_asset_id = " + from + " OR " + edge + ".to_asset_id = " + from + ")",
			"CASE WHEN " + edge + ".from_asset_id = " + from + " THEN " + edge + ".to_asset_id ELSE " + edge + ".from_asset_id END"
	default:
		return edge + ".from_asset_id = " + from, edge + ".to_asset_id"
	}
}

// overRelation reaches a field that lives on a relation the current shape has
// not joined, by wrapping the comparison in its own EXISTS. Like the child
// shapes, the join is whitelisted here rather than described by the catalogue.
func (b *builder) overRelation(sc scope, f ast.FieldRef, sp ast.Span, raw bool, inner func(expr) string) string {
	switch sc.target.Name + "/" + f.Accessor.Rel {
	case "software_install/product":
		p := b.alias("sp")
		joined := sc
		joined.rels = map[string]string{"product": p}
		return "EXISTS (SELECT 1 FROM software_products " + p +
			" WHERE " + p + ".id = " + sc.self + ".product_id AND " +
			b.overValueMode(joined, f, sp, raw, inner) + ")"
	}
	return b.fail(sp, "field %q needs relation %q, and %q has no shape that joins it",
		f.Text, f.Accessor.Rel, sc.target.Name)
}

// derived builds the whitelisted derived fields (§8's two gaps). The builder
// name comes from the catalogue and is matched against this switch, so a
// catalogue cannot introduce SQL of its own.
//
// A derived field is reached through overValue like any other, so it gets the
// whole per-type comparison machinery for free: `:` is case-insensitive, `=` is
// not, `*` becomes a LIKE pattern, `~` is a regex, `in` is an OR, and `exists`
// is a presence test. It used to be a switch of its own that compared
// case-sensitively and accepted only ":" and "=", so `proposed_by:match*`
// searched for the literal string "match*" and `proposed_by:*` validated and
// then failed `untranslatable`.
func (b *builder) derivedOver(sc scope, f ast.FieldRef, sp ast.Span, raw bool, inner func(expr) string) string {
	if isIPAMDerived(f.Accessor.Derived) {
		return b.ipamOver(sc, f, sp, inner)
	}
	if isTunnelDerived(f.Accessor.Derived) {
		return b.tunnelOver(sc, f, sp, inner)
	}
	if isWirelessDerived(f.Accessor.Derived) {
		return b.wirelessOver(sc, f, sp, inner)
	}
	if isVirtualCircuitDerived(f.Accessor.Derived) {
		return b.virtualCircuitOver(sc, f, sp, inner)
	}
	if isCablingDerived(f.Accessor.Derived) {
		return b.cablingOver(sc, f, sp, inner)
	}
	if isPowerDerived(f.Accessor.Derived) {
		return b.powerOver(sc, f, sp, inner)
	}
	switch f.Accessor.Derived {
	case "asset.proposed_by":
		// Sugar for "a machine proposed this class, and here is which one"
		// (§4.3). The kind guard wraps the whole predicate, so a row whose class
		// nothing proposed is excluded whatever the operator says.
		//
		// TWO kinds and not one. §4.3 wrote this as `source=inferred` because
		// `inferred` was the only machine-proposed kind there was; workstream
		// 2.10b added `rule` — a class argued from a curated classification_rules
		// row, whose id `class_source_ref` then carries. Leaving the guard at
		// `inferred` made those unreachable through the very field that exists to
		// name the proposer: the `proposed_by` FACET lists their `rule:<id>`
		// refs (it reads the column with no kind filter), and clicking one
		// returned nothing. A facet that filters to zero is the silent wrong
		// answer, not an empty result.
		//
		// `measured` and `declared` stay out, and that is the line: a sensor id
		// or a user id in class_source_ref says who OBSERVED or DECIDED the
		// class, not who proposed it, and folding them in would make
		// `proposed_by:*` mean "has a class_source_ref", which is every row.
		return "(" + sc.self + ".class_source_kind IN (" + b.param("inferred") + ", " + b.param("rule") + ")" +
			" AND " + inner(expr{alias: sc.self, sql: sc.self + ".class_source_ref"}) + ")"

	case "interface.mac_address":
		// macaddr8 renders an EUI-48 as EUI-64 (ff:fe in the middle); fold it
		// back so `mac_address:"00:11:22:33:44:55"` matches what a person
		// typed and the API shows. A real EUI-64 keeps its eight octets.
		m := sc.self + ".mac_address"
		return inner(expr{alias: sc.self, sql: "(CASE WHEN substr(" + m + "::text, 10, 5) = " + b.param("ff:fe") + " THEN (" + m +
			"::macaddr)::text ELSE " + m + "::text END)"})
	case "interface.virtual_device_context":
		// A virtual device context the interface belongs to (DCIM gap 1), by
		// name, through the membership junction. Row-shaped, so `!=` means
		// "in no context of that name".
		j, c := b.alias("ivc"), b.alias("vdc")
		return "EXISTS (SELECT 1 FROM interface_virtual_device_contexts " + j +
			" JOIN virtual_device_contexts " + c + " ON " + c + ".id = " + j + ".virtual_device_context_id" +
			" WHERE " + j + ".interface_id = " + sc.self + ".id AND " + c + ".status <> " + b.param("rejected") +
			" AND " + inner(expr{alias: c, sql: c + ".name"}) + ")"
	case "asset.business_unit":
		// The unit the asset is assigned to, matched by NAME or SLUG. An EXISTS
		// over the one referenced row (rowShaped, so `!=` negates the whole
		// predicate: "not Finance" must mean neither its name nor its slug is
		// Finance, which two OR-ed `<>` could not say).
		bu := b.alias("bu")
		return "EXISTS (SELECT 1 FROM business_units " + bu +
			" WHERE " + bu + ".id = " + sc.self + ".business_unit_id" +
			" AND (" + inner(expr{alias: bu, sql: bu + ".name"}) +
			" OR " + inner(expr{alias: bu, sql: bu + ".slug"}) + "))"

	case "asset.business_unit_parent":
		// The named unit AND every descendant of it (`in` semantics down the
		// parent_id tree). UNION, not UNION ALL, so a cycle that slipped past the
		// service's depth check still terminates.
		root, tree, kid, bu := b.alias("bur"), b.alias("but"), b.alias("buk"), b.alias("bu")
		return "EXISTS (WITH RECURSIVE " + tree + "(id) AS (" +
			"SELECT " + root + ".id FROM business_units " + root +
			" WHERE (" + inner(expr{alias: root, sql: root + ".name"}) +
			" OR " + inner(expr{alias: root, sql: root + ".slug"}) + ")" +
			" UNION SELECT " + kid + ".id FROM business_units " + kid +
			" JOIN " + tree + " ON " + kid + ".parent_id = " + tree + ".id)" +
			" SELECT 1 FROM " + tree + " " + bu + " WHERE " + bu + ".id = " + sc.self + ".business_unit_id)"

	case "asset.site":
		// The site the asset is in, by NAME or SLUG (DCIM row 2.1); row-shaped
		// like business_unit, so `!=` negates the whole EXISTS.
		st := b.alias("st")
		return "EXISTS (SELECT 1 FROM sites " + st +
			" WHERE " + st + ".id = " + sc.self + ".site_id" +
			" AND (" + inner(expr{alias: st, sql: st + ".name"}) +
			" OR " + inner(expr{alias: st, sql: st + ".slug"}) + "))"

	case "asset.site_group", "asset.site_region":
		// The site's group (or region) named X AND every descendant of it, the
		// NetBox filter's semantics. UNION, not UNION ALL, so a cycle that
		// slipped past the service's checks still terminates.
		table, col := "site_groups", "group_id"
		if f.Accessor.Derived == "asset.site_region" {
			table, col = "regions", "region_id"
		}
		root, tree, kid, st := b.alias("sgr"), b.alias("sgt"), b.alias("sgk"), b.alias("st")
		return "EXISTS (WITH RECURSIVE " + tree + "(id) AS (" +
			"SELECT " + root + ".id FROM " + table + " " + root +
			" WHERE (" + inner(expr{alias: root, sql: root + ".name"}) +
			" OR " + inner(expr{alias: root, sql: root + ".slug"}) + ")" +
			" UNION SELECT " + kid + ".id FROM " + table + " " + kid +
			" JOIN " + tree + " ON " + kid + ".parent_id = " + tree + ".id)" +
			" SELECT 1 FROM sites " + st + " JOIN " + tree + " ON " + st + "." + col + " = " + tree + ".id" +
			" WHERE " + st + ".id = " + sc.self + ".site_id)"

	case "asset.location":
		// The asset's location OR any location above it, by name, slug or name
		// path (public.location_path: "HQ / Floor 2"), so `location = "Floor 2"`
		// finds what is in Room 201 on that floor. Walks up from the asset's
		// location, bounded like every tree read here.
		l0, up, lp, lx := b.alias("lo"), b.alias("lup"), b.alias("lp"), b.alias("lx")
		return "EXISTS (WITH RECURSIVE " + up + "(id, parent_id, d) AS (" +
			"SELECT " + l0 + ".id, " + l0 + ".parent_id, 0 FROM locations " + l0 + " WHERE " + l0 + ".id = " + sc.self + ".location_id" +
			" UNION ALL SELECT " + lp + ".id, " + lp + ".parent_id, " + up + ".d + 1 FROM locations " + lp + " JOIN " + up + " ON " + lp + ".id = " + up + ".parent_id WHERE " + up + ".d < 32)" +
			" SELECT 1 FROM " + up + " JOIN locations " + lx + " ON " + lx + ".id = " + up + ".id" +
			" WHERE (" + inner(expr{alias: lx, sql: lx + ".name"}) +
			" OR " + inner(expr{alias: lx, sql: lx + ".slug"}) +
			" OR " + inner(expr{alias: lx, sql: "public.location_path(" + lx + ".id)"}) + "))"

	case "asset.device_type":
		// The assigned device type (DCIM row 2.2), by model, slug or part
		// number. Row-shaped like business_unit: `!=` negates the whole EXISTS.
		dt := b.alias("dt")
		return "EXISTS (SELECT 1 FROM device_types " + dt +
			" WHERE " + dt + ".id = " + sc.self + ".device_type_id" +
			" AND (" + inner(expr{alias: dt, sql: dt + ".model"}) +
			" OR " + inner(expr{alias: dt, sql: dt + ".slug"}) +
			" OR " + inner(expr{alias: dt, sql: dt + ".part_number"}) + "))"

	case "asset.device_type_manufacturer":
		// The assigned device type's manufacturer, by name or slug.
		dt, mf := b.alias("dt"), b.alias("mf")
		return "EXISTS (SELECT 1 FROM device_types " + dt + " JOIN manufacturers " + mf +
			" ON " + mf + ".id = " + dt + ".manufacturer_id" +
			" WHERE " + dt + ".id = " + sc.self + ".device_type_id" +
			" AND (" + inner(expr{alias: mf, sql: mf + ".name"}) +
			" OR " + inner(expr{alias: mf, sql: mf + ".slug"}) + "))"

	case "asset.device_role":
		dr := b.alias("dr")
		return "EXISTS (SELECT 1 FROM device_roles " + dr +
			" WHERE " + dr + ".id = " + sc.self + ".device_role_id" +
			" AND (" + inner(expr{alias: dr, sql: dr + ".name"}) +
			" OR " + inner(expr{alias: dr, sql: dr + ".slug"}) + "))"

	case "asset.platform":
		pf := b.alias("pf")
		return "EXISTS (SELECT 1 FROM platforms " + pf +
			" WHERE " + pf + ".id = " + sc.self + ".platform_id" +
			" AND (" + inner(expr{alias: pf, sql: pf + ".name"}) +
			" OR " + inner(expr{alias: pf, sql: pf + ".slug"}) + "))"

	case "asset.cluster", "asset.cluster_type", "asset.cluster_group":
		// The asset's cluster (DCIM row 4.2): a VM's (assets.cluster_id) or a
		// host's (cluster_hosts), matched by the cluster's name, its type's
		// name or slug, or its group's name or slug. Row-shaped like
		// business_unit: `!=` negates the whole EXISTS.
		cl, ch := b.alias("cl"), b.alias("ch")
		member := "(" + cl + ".id = " + sc.self + ".cluster_id OR EXISTS (SELECT 1 FROM cluster_hosts " + ch +
			" WHERE " + ch + ".cluster_id = " + cl + ".id AND " + ch + ".asset_id = " + sc.self + ".id))"
		switch f.Accessor.Derived {
		case "asset.cluster_type":
			ct := b.alias("ct")
			return "EXISTS (SELECT 1 FROM clusters " + cl + " JOIN cluster_types " + ct + " ON " + ct + ".id = " + cl + ".type_id" +
				" WHERE " + member + " AND (" + inner(expr{alias: ct, sql: ct + ".name"}) +
				" OR " + inner(expr{alias: ct, sql: ct + ".slug"}) + "))"
		case "asset.cluster_group":
			cg := b.alias("cg")
			return "EXISTS (SELECT 1 FROM clusters " + cl + " JOIN cluster_groups " + cg + " ON " + cg + ".id = " + cl + ".group_id" +
				" WHERE " + member + " AND (" + inner(expr{alias: cg, sql: cg + ".name"}) +
				" OR " + inner(expr{alias: cg, sql: cg + ".slug"}) + "))"
		}
		return "EXISTS (SELECT 1 FROM clusters " + cl + " WHERE " + member +
			" AND " + inner(expr{alias: cl, sql: cl + ".name"}) + ")"
	case "asset.circuit", "asset.circuit_provider", "asset.circuit_cid":
		// Circuits terminating where the asset is (DCIM row 4.1): a circuit
		// termination on the asset's location. Row-shaped like device_type, so
		// `!=` negates the whole EXISTS and an asset with no circuit satisfies
		// it. A bare `circuit` matches the circuit's ID (cid) or its type's name
		// or slug (`circuit = mpls`); `.cid` the cid alone; `.provider` the
		// provider's name or slug.
		ctm, ci := b.alias("ctm"), b.alias("ci")
		from := "EXISTS (SELECT 1 FROM circuit_terminations " + ctm + " JOIN circuits " + ci +
			" ON " + ci + ".id = " + ctm + ".circuit_id"
		where := " WHERE " + ctm + ".termination_kind = " + b.param("location") + " AND " + ctm + ".termination_id = " + sc.self + ".location_id"
		switch f.Accessor.Derived {
		case "asset.circuit_provider":
			pv := b.alias("pv")
			return from + " JOIN providers " + pv + " ON " + pv + ".id = " + ci + ".provider_id" + where +
				" AND (" + inner(expr{alias: pv, sql: pv + ".name"}) +
				" OR " + inner(expr{alias: pv, sql: pv + ".slug"}) + "))"
		case "asset.circuit_cid":
			return from + where + " AND " + inner(expr{alias: ci, sql: ci + ".cid"}) + ")"
		}
		cty := b.alias("cty")
		return from + " JOIN circuit_types " + cty + " ON " + cty + ".id = " + ci + ".type_id" + where +
			" AND (" + inner(expr{alias: ci, sql: ci + ".cid"}) +
			" OR " + inner(expr{alias: cty, sql: cty + ".name"}) +
			" OR " + inner(expr{alias: cty, sql: cty + ".slug"}) + "))"

	case "asset.rack":
		// The rack the asset is in (DCIM row 2.3), by NAME or FACILITY ID;
		// row-shaped like site, so `!=` negates the whole EXISTS.
		rk := b.alias("rk")
		return "EXISTS (SELECT 1 FROM racks " + rk +
			" WHERE " + rk + ".id = " + sc.self + ".rack_id" +
			" AND (" + inner(expr{alias: rk, sql: rk + ".name"}) +
			" OR " + inner(expr{alias: rk, sql: rk + ".facility_id"}) + "))"

	case "asset.module_type":
		// A module installed in the asset (DCIM row 2.4), by its module
		// type's model, part number or slug; row-shaped like rack.
		mo, mt := b.alias("mo"), b.alias("mt")
		return "EXISTS (SELECT 1 FROM modules " + mo + " JOIN module_types " + mt + " ON " + mt + ".id = " + mo + ".module_type_id" +
			" WHERE " + mo + ".asset_id = " + sc.self + ".id AND " + mo + ".status <> " + b.param("rejected") +
			" AND (" + inner(expr{alias: mt, sql: mt + ".model"}) +
			" OR " + inner(expr{alias: mt, sql: mt + ".part_number"}) +
			" OR " + inner(expr{alias: mt, sql: mt + ".slug"}) + "))"

	case "asset.inventory_item_serial":
		// The serial of any of the asset's inventory items (DCIM row 2.4).
		ii := b.alias("ii")
		return "EXISTS (SELECT 1 FROM inventory_items " + ii +
			" WHERE " + ii + ".asset_id = " + sc.self + ".id AND " + ii + ".status <> " + b.param("rejected") +
			" AND " + inner(expr{alias: ii, sql: ii + ".serial"}) + ")"

	case "asset.inventory_item_stock_state":
		// The stock state of any of the asset's inventory items (DCIM gap 8):
		// installed, or rma for a part out for RMA still in the asset.
		ii := b.alias("ii")
		return "EXISTS (SELECT 1 FROM inventory_items " + ii +
			" WHERE " + ii + ".asset_id = " + sc.self + ".id AND " + ii + ".status <> " + b.param("rejected") +
			" AND " + inner(expr{alias: ii, sql: ii + ".stock_state"}) + ")"

	case "asset.virtual_chassis":
		// The virtual chassis the asset is a member of (DCIM row 2.4), by
		// name or domain.
		vc := b.alias("vc")
		return "EXISTS (SELECT 1 FROM virtual_chassis " + vc +
			" WHERE " + vc + ".id = " + sc.self + ".virtual_chassis_id" +
			" AND (" + inner(expr{alias: vc, sql: vc + ".name"}) +
			" OR " + inner(expr{alias: vc, sql: vc + ".domain"}) + "))"

	case "asset.rack_site", "asset.rack_role":
		// The asset's rack's site (or rack role), by name or slug.
		table, col := "sites", "site_id"
		if f.Accessor.Derived == "asset.rack_role" {
			table, col = "rack_roles", "role_id"
		}
		rk, ob := b.alias("rk"), b.alias("ro")
		return "EXISTS (SELECT 1 FROM racks " + rk + " JOIN " + table + " " + ob +
			" ON " + ob + ".id = " + rk + "." + col +
			" WHERE " + rk + ".id = " + sc.self + ".rack_id" +
			" AND (" + inner(expr{alias: ob, sql: ob + ".name"}) +
			" OR " + inner(expr{alias: ob, sql: ob + ".slug"}) + "))"

	case "asset.cloud_provider", "asset.cloud_account", "asset.cloud_type":
		// The cloud_resource attributes (DCIM row 4.6). The same jsonb read the
		// `attr.` namespace compiles to, so `provider:aws` and
		// `attr.provider:aws` are one predicate.
		key := map[string]string{
			"asset.cloud_provider": "provider",
			"asset.cloud_account":  "account_id",
			"asset.cloud_type":     "provider_type",
		}[f.Accessor.Derived]
		return inner(expr{alias: sc.self, sql: "(" + sc.self + ".attributes ->> " + b.param(key) + ")"})

	case "asset.region":
		// The location region, or a cloud resource's provider region when it
		// has none — the same expression the `region` facet counts.
		return inner(expr{alias: sc.self, sql: "COALESCE(NULLIF(" + sc.self + ".region, " + b.param("") + "), " +
			sc.self + ".attributes ->> " + b.param("region") + ")"})

	case "asset.end_of_support":
		// The effective end of support (DCIM gap 4): a value, not an EXISTS,
		// so `end_of_support < now` is "the earlier of the two dates has
		// passed" and an asset with neither date is UNKNOWN (no row).
		return inner(expr{alias: sc.self, sql: AssetEffectiveEndOfSupportSQL(sc.self, b.alias)})

	case "asset.cert_trust":
		// The worst trust status of the asset's certificates, the
		// same expression the asset facet groups by (AssetCertTrustSQL). A
		// value, not an EXISTS: `cert_trust:untrusted` means "the worst is
		// untrusted", not "has an untrusted one".
		return inner(expr{sql: AssetCertTrustSQL(sc.self, b.alias)})

	case "crypto.strength":
		// Worst-component-wins: a configuration is weak if any algorithm it
		// negotiates is weak, which is the same rule catalogue_risk.go applies
		// to the score. That makes it row-shaped, so `!=` negates the whole
		// EXISTS (see rowShaped).
		cia, alg := b.alias("cia"), b.alias("alg")
		return "EXISTS (SELECT 1 FROM crypto_implementation_algorithms " + cia +
			" JOIN algorithms " + alg + " ON " + alg + ".id = " + cia + ".algorithm_id" +
			" WHERE " + cia + ".crypto_implementation_id = " + sc.self + ".id" +
			" AND " + inner(expr{alias: alg, sql: alg + ".strength"}) + ")"

	case "crypto.algorithm_deprecated":
		cia, alg := b.alias("cia"), b.alias("alg")
		from := " FROM crypto_implementation_algorithms " + cia +
			" JOIN algorithms " + alg + " ON " + alg + ".id = " + cia + ".algorithm_id" +
			" WHERE " + cia + ".crypto_implementation_id = " + sc.self + ".id"
		if raw {
			// Presence asks whether the data to compute the flag is there at
			// all, which is a question about the rows.
			return "EXISTS (SELECT 1" + from +
				" AND " + inner(expr{alias: alg, sql: alg + ".deprecation_status"}) + ")"
		}
		// The VALUE is an aggregate over the rows, not a per-row column: "does
		// this configuration use a deprecated algorithm". Comparing per row
		// would make `algorithm.deprecated:false` mean "has some algorithm
		// that is not deprecated" instead of "has none that is".
		return inner(expr{sql: "(EXISTS (SELECT 1" + from +
			" AND lower(" + alg + ".deprecation_status) IN (" +
			b.param("deprecated") + ", " + b.param("obsolete") + ")))"})
	}
	return b.fail(sp, "no builder for derived field %q", f.Text)
}

// derivedRowShaped reports whether a derived builder wraps its comparison in an
// EXISTS over child rows, so `!=` must negate the whole thing (S3's rule).
//
// crypto.strength is the only one: proposed_by reads columns of the current
// row, and algorithm.deprecated's value is already an aggregate over the rows
// rather than a per-row column.
func derivedRowShaped(derived string) bool {
	switch derived {
	case "crypto.strength", "asset.business_unit", "asset.business_unit_parent",
		"asset.site", "asset.site_group", "asset.site_region", "asset.location",
		"asset.device_type", "asset.device_type_manufacturer", "asset.device_role", "asset.platform",
		"asset.cluster", "asset.cluster_type", "asset.cluster_group",
		"asset.circuit", "asset.circuit_provider", "asset.circuit_cid",
		"asset.rack", "asset.rack_site", "asset.rack_role",
		"asset.module_type", "asset.inventory_item_serial", "asset.inventory_item_stock_state", "asset.virtual_chassis",
		"interface.virtual_device_context":
		return true
	}
	return isIPAMDerived(derived) || isTunnelDerived(derived) || isWirelessDerived(derived) || isCablingDerived(derived) ||
		isPowerDerived(derived) || isVirtualCircuitDerived(derived)
}
