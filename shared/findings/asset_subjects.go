package findings

// Subject resolution: which findings are "on" an asset.
//
// A finding names its subject with `(subject_type, subject_id)` and the subject
// is usually NOT the asset — most findings are on a crypto configuration, a
// certificate or a software install that BELONGS to an asset. "Assets with a
// critical finding" means the asset, any of its descendants, and the edges it
// is an end of (see AssetSubjects) — so every reader that asks that question
// has to walk the same paths.
//
// There are two such readers and they must agree exactly:
//
//   - the query language's `finding:(…)` sub-predicate (shared/query/sql), which
//     is what a saved view, the facet rail's click and an agent's query all
//     compile to;
//   - the per-asset findings read the asset page's Findings tab calls
//     (compliance-engine), and the `has_findings` facet count beside the
//     inventory list.
//
// They disagreed once already — the facet counted `compliance_findings` by
// `asset_id` while the click wrote `finding:(…)` over `findings` — and the
// number therefore described a different set from the list it led to. The facet
// was withdrawn rather than left to lie (Gate 1) and is restored here, against
// ONE definition rather than two spellings of an intention.

// OpenSQL is OpenQuery (generated from standards/findings-registry.yaml) as raw
// SQL over a findings alias, for a reader that is already writing SQL by hand
// and has no query-language translator in reach — the per-asset findings read in
// compliance-engine.
//
// This is the one hand-written twin of the generated constant, and
// TestOpenSQL_MatchesOpenQuery pins it to the generated text so a change to the
// YAML that is not mirrored here fails the build rather than quietly answering a
// different question.
func OpenSQL(alias string) string {
	return "(" + alias + ".detection_state = 'ACTIVE'" +
		" AND " + WorkflowOpenSQL(alias) + ")"
}

// WorkflowOpenSQL is the WORKFLOW half of OpenSQL on its own: has anybody dealt
// with this finding? It exists for the one reader that already constrains
// `detection_state` separately and would otherwise have to re-spell this half —
// findingListWhere in compliance-engine, which builds the Findings page's WHERE,
// the per-producer facet tally and the Dashboard's "Critical findings" rollup
// from one expression.
//
// Split out rather than copied, and OpenSQL is COMPOSED from it rather than the
// two being written side by side, so TestOpenSQL_IsOpenQueryInSQL still pins the
// whole predicate to the generated OpenQuery: a change to the registry's
// definition of "open" that is not mirrored here fails the build. A second
// hand-written `NOT IN ('RESOLVED', 'SUPPRESSED')` is exactly how the tile and
// the page it links to came to count different sets in the first place.
//
// Not a complete definition of "open" by itself. A caller that does not
// otherwise scope `detection_state` wants OpenSQL — this half alone counts
// findings that have since gone away.
func WorkflowOpenSQL(alias string) string {
	return alias + ".workflow_status NOT IN ('RESOLVED', 'SUPPRESSED')"
}

// ConfigurationAssetSQL is the ONE expression that resolves the asset a crypto
// configuration belongs to, given an alias for `crypto_implementations` and an
// alias for the `asset_endpoints` row LEFT JOINed on its `endpoint_id`.
//
// The endpoint is AUTHORITATIVE where there is one — a configuration whose
// endpoint moved to another host follows the endpoint — and `ci.asset_id` is the
// roll-up target where `endpoint_id` is NULL (an at-rest cloud resource has no
// socket at all).
//
// It is exported, and used by AssetSubjects below, because a SECOND reader
// resolves the same thing and the two silently disagreed: the `crypto` producer
// wrote its `producer_assessments` coverage rows against bare `ci.asset_id`
// while the findings it raised were reachable, through AssetSubjects, from the
// ENDPOINT's asset. For a configuration whose endpoint had moved, the platform
// therefore claimed asset A was assessed and put the finding on asset B —
// "assessed and clean" on one asset and an unexplained finding on another, from
// one producer pass. Both now splice this fragment, and
// TestCryptoProducer_ResolvesAssetsThroughTheSharedFragment diffs the producer's
// SQL against it, so a change in one cannot drift from the other.
func ConfigurationAssetSQL(ciAlias, endpointAlias string) string {
	return "COALESCE(" + endpointAlias + ".asset_id, " + ciAlias + ".asset_id)"
}

// AssetSubject is one subject type a finding may carry that belongs to an asset,
// with the SQL that resolves it back to that asset.
type AssetSubject struct {
	// Type is the subject_type value, from the registry's vocabulary.
	Type string
	// Self is true for the `asset` subject, whose subject_id IS the asset's own
	// id — there is no id list to select.
	Self bool
	// IDs is a SELECT returning the ids of this subject for ONE asset row,
	// correlated to the asset alias passed to AssetSubjects. Empty when Self.
	IDs string
}

// AssetSubjects returns the seven subject paths from an asset, in a fixed order.
//
// `uniq` mints a unique table alias for a prefix; the caller owns the numbering
// so the fragment can be spliced into a larger query without colliding with its
// aliases. It is called ONCE per alias, in the order the paths appear below, so
// a caller whose generator is a counter gets stable, reproducible SQL.
//
// Deliberately NOT covering every subject type in the registry: `control` and
// `framework` have no asset-descendant path that is true by construction, and
// inventing one would silently widen what "a finding on this asset" means. A
// finding on one of those is reachable by naming it, not by walking down from
// an asset.
//
// # The relationship path is an INCIDENCE, not a descent
//
// A relationship is not "under" either asset it joins — it is an edge between
// them — which is why it was left out at first. But the only finding written on
// a relationship subject is `hygiene/orphan_relationship`, whose whole content
// is "an edge from THIS asset points at one that is gone": it was unreachable
// from either asset page and from the `has_findings` facet, so the one surface
// where a person would act on it never showed it. An edge is reached from
// EITHER end, because the surviving end may be either of them.
//
// That is a deliberate widening of "a finding on this asset", stated here
// rather than absorbed: an asset with a broken edge does carry that problem,
// and it is the asset's owner who fixes it. It cannot double-count across both
// ends — `orphan_relationship` fires only when one end is missing, so exactly
// one end is an asset a query can reach.
//
// # The key path
//
// `key` was on the excluded list too. It was excluded while nothing
// produced a key-subject finding, which made the question moot; the `crypto`
// producer now raises `pqc_vulnerable` on a key, and a key does have a path that
// is true by construction — the same one the Keys lens's "used by N assets"
// count already walks, `implementation_keys` → `crypto_implementations` → the
// asset, identical in shape to the certificate path below it. Without it the
// finding would exist and be unreachable: invisible to `finding:(…)`, to the
// `has_findings` facet, to the asset page's Findings tab and to the risk
// rollup — a row nothing leads to, which is the failure this file was written
// to stop.
//
// # Why the configuration and certificate paths LEFT JOIN the endpoint
//
// They were inner joins on `crypto_implementations.endpoint_id`, which is
// NULLABLE and documented as such: "NULL for a configuration that is not tied
// to one socket: an at-rest cloud resource has no endpoint at all … asset_id
// stays and is the roll-up target" (schema.sql). Every such configuration — and
// every certificate reachable only through one — was therefore invisible to
// `finding:(…)`, to the `has_findings` facet and to the per-asset findings read,
// with no error anywhere. COALESCE keeps the endpoint AUTHORITATIVE where there
// is one (a configuration whose endpoint moved to another asset follows the
// endpoint) and falls back to the roll-up target where there is not.
func AssetSubjects(assetAlias string, uniq func(prefix string) string) []AssetSubject {
	e := uniq("e")
	ci := uniq("ci")
	e2 := uniq("e")
	c := uniq("c")
	cic := uniq("cic")
	ci2 := uniq("ci")
	e3 := uniq("e")
	si := uniq("si")
	r := uniq("r")
	k := uniq("k")
	ik := uniq("ik")
	ci3 := uniq("ci")
	e4 := uniq("e")

	return []AssetSubject{
		{Type: SubjectAsset, Self: true},
		{
			Type: SubjectEndpoint,
			IDs: "SELECT " + e + ".id FROM asset_endpoints " + e +
				" WHERE " + e + ".asset_id = " + assetAlias + ".id",
		},
		{
			Type: SubjectCryptoConfiguration,
			IDs: "SELECT " + ci + ".id FROM crypto_implementations " + ci +
				" LEFT JOIN asset_endpoints " + e2 + " ON " + e2 + ".id = " + ci + ".endpoint_id" +
				" WHERE " + ConfigurationAssetSQL(ci, e2) + " = " + assetAlias + ".id",
		},
		{
			Type: SubjectCertificate,
			IDs: "SELECT " + c + ".id FROM certificates " + c +
				" JOIN crypto_implementation_certificates " + cic + " ON " + cic + ".certificate_id = " + c + ".id" +
				" JOIN crypto_implementations " + ci2 + " ON " + ci2 + ".id = " + cic + ".crypto_implementation_id" +
				" LEFT JOIN asset_endpoints " + e3 + " ON " + e3 + ".id = " + ci2 + ".endpoint_id" +
				" WHERE " + ConfigurationAssetSQL(ci2, e3) + " = " + assetAlias + ".id",
		},
		{
			Type: SubjectSoftwareInstall,
			IDs: "SELECT " + si + ".id FROM software_installs " + si +
				" WHERE " + si + ".asset_id = " + assetAlias + ".id",
		},
		{
			Type: SubjectRelationship,
			IDs: "SELECT " + r + ".id FROM asset_relationships " + r +
				" WHERE " + r + ".from_asset_id = " + assetAlias + ".id" +
				" OR " + r + ".to_asset_id = " + assetAlias + ".id",
		},
		// The key path is the certificate path with one more junction: a key
		// hangs off a configuration through implementation_keys, and the
		// configuration hangs off the asset the same way, endpoint first, through the
		// shared ConfigurationAssetSQL fragment.
		//
		// Appended LAST on purpose, AFTER `relationship` — the caller's alias
		// numbering follows this order, so inserting a path anywhere else
		// renumbers every generated query that already exists. When this and
		// the relationship path landed in the same merge, keeping relationship
		// where it already was and putting key behind it meant only the new
		// branch was added to the existing SQL, not a renumbering of all of it.
		{
			Type: SubjectKey,
			IDs: "SELECT " + k + ".id FROM keys " + k +
				" JOIN implementation_keys " + ik + " ON " + ik + ".key_id = " + k + ".id" +
				" JOIN crypto_implementations " + ci3 + " ON " + ci3 + ".id = " + ik + ".implementation_id" +
				" LEFT JOIN asset_endpoints " + e4 + " ON " + e4 + ".id = " + ci3 + ".endpoint_id" +
				" WHERE " + ConfigurationAssetSQL(ci3, e4) + " = " + assetAlias + ".id",
		},
	}
}

// AssetSubjectClause is AssetSubjects rendered as one OR-ed boolean over a
// findings alias, for a caller that has no parameter binder of its own.
//
// `subjectTypeSQL` turns a subject-type value into the SQL that stands for it —
// a placeholder from the caller's binder, or a quoted literal. It is a callback
// rather than a plain literal so the query-language builder, which binds every
// value it emits, can keep doing that.
func AssetSubjectClause(findingAlias, assetAlias string, uniq func(prefix string) string, subjectTypeSQL func(string) string) string {
	parts := make([]string, 0, 7)
	for _, s := range AssetSubjects(assetAlias, uniq) {
		if s.Self {
			parts = append(parts, "("+findingAlias+".subject_type = "+subjectTypeSQL(s.Type)+
				" AND "+findingAlias+".subject_id = "+assetAlias+".id)")
			continue
		}
		parts = append(parts, "("+findingAlias+".subject_type = "+subjectTypeSQL(s.Type)+
			" AND "+findingAlias+".subject_id IN ("+s.IDs+"))")
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " OR " + p
	}
	return out
}
