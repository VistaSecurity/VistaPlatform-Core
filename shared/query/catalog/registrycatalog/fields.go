package registrycatalog

import (
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
)

// The first-class field table: every target of QUERY_LANGUAGE §4.1 with the
// columns of DATA_MODEL §2–§4 behind it.
//
// This half is HAND-WRITTEN and cannot be otherwise. A column name is not a
// field name — the language says `first_seen` where the column is
// `first_discovered_at`, `segment_id` where it is `network_segment_id`, `risk`
// where it is `risk_score` plus the column that proves anybody scored it — and
// nothing in the schema records which columns are queryable at all. What IS
// generated is everything else: the namespaces (namespaces.go) come from
// shared/assetclass, shared/facts and shared/findings, and every closed value
// set (enums.go) is pinned to the schema by a test.
//
// It is exported so the TypeScript mirror can be generated from it rather than
// typed again: AllTargets and FirstClassFields are the whole input a generator
// needs, and they are plain data.

// ---------------------------------------------------------------- targets --

// targets is §4.1's nine collections plus `measurement` (§12 amendment 3),
// with the physical shape the translator joins.
var targets = []catalog.Target{
	{
		Name: "asset", Table: "assets", Alias: "a", IDColumn: "id",
		Subs:         []string{"endpoint", "software", "finding", "cert", "crypto", "identifier", "relationship"},
		Traversable:  true,
		FreeTextable: true,
	},
	{
		Name: "endpoint", Table: "asset_endpoints", Alias: "e", IDColumn: "id",
		AssetIDColumn: "asset_id",
		Subs:          []string{"asset", "crypto", "cert"},
	},
	{
		Name: "certificate", Table: "certificates", Alias: "c", IDColumn: "id",
		Subs: []string{"asset"},
	},
	{
		// crypto_implementations is a view over the partitioned table
		// (schema.sql); DATA_MODEL §7 gives it `endpoint_id` in phase 1, which
		// is the column the endpoint join needs and does not have yet.
		Name: "crypto_configuration", Table: "crypto_implementations", Alias: "ci", IDColumn: "id",
		Subs: []string{"asset", "cert"},
	},
	{
		Name: "finding", Table: "findings", Alias: "f", IDColumn: "id",
		Subs: []string{"asset"},
	},
	{
		Name: "software_install", Table: "software_installs", Alias: "si", IDColumn: "id",
		AssetIDColumn: "asset_id",
		Subs:          []string{"asset"},
	},
	{
		Name: "identifier", Table: "asset_identifiers", Alias: "ai", IDColumn: "id",
		AssetIDColumn: "asset_id",
		Subs:          []string{"asset"},
	},
	{
		// An edge has two ends, so "the asset of a relationship" is ambiguous;
		// there is no `asset:(…)` shape from here rather than an invented one.
		Name: "relationship", Table: "asset_relationships", Alias: "r", IDColumn: "id",
	},
	{
		// §4.1, §8: the in-flight discovery an approval rule sees. No table —
		// the identification engine holds it in memory, so a predicate over it
		// is evaluated there and the SQL translator refuses it rather than
		// inventing a table.
		Name: "observation", Table: "", Alias: "o", IDColumn: "",
		InMemory: true,
	},
	{
		// §12 amendment 3: §8 reserves `value` for a measurement's extracted
		// scalar, and a predicate needs a target to resolve against. Table-less
		// for the same reason as observation.
		Name: "measurement", Table: "", Alias: "m", IDColumn: "",
		InMemory: true,
	},
}

// AllTargets returns §4.1's targets and their physical shape. The slice is a
// copy: it is package state, and a generator that sorted it in place would
// reorder the catalogue for every later caller in the process.
func AllTargets() []catalog.Target {
	out := make([]catalog.Target, len(targets))
	copy(out, targets)
	return out
}

// ----------------------------------------------------------- constructors --

func col(name string, t ast.FieldType) catalog.FieldInfo {
	return catalog.FieldInfo{Name: name, Type: t, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: name}}
}

// colAs is a field whose language name differs from its column, which is most
// of the renames in this file: the accessor is the only place that knows.
func colAs(name, column string, t ast.FieldType) catalog.FieldInfo {
	return catalog.FieldInfo{Name: name, Type: t, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: column}}
}

// enumAs is a keyword column with a closed value set.
//
// The `::text` cast is applied to EVERY one of them, whether the column is a
// Postgres enum or a text column with a CHECK. For an enum it is required:
// neither lower() nor a text comparison exists for an enum, and a value outside
// the type raises "invalid input value for enum" at query time — an error where
// the honest answer is "no rows". For a text column it is a no-op. Applying it
// uniformly means the catalogue does not have to carry which is which, and a
// column promoted from text to an enum later keeps working.
func enumAs(name, column string, values ...string) catalog.FieldInfo {
	f := colAs(name, column, ast.TypeKeyword)
	f.Accessor.Cast = "text"
	f.Enum = values
	return f
}

// derived names a whitelisted builder in the translator (§8's two computed
// fields). The catalogue does not know how it is built, only that it exists and
// what type it yields.
func derived(name, builder string, t ast.FieldType) catalog.FieldInfo {
	return catalog.FieldInfo{
		Name: name, Type: t,
		Accessor: ast.Accessor{Kind: ast.AccessorDerived, Derived: builder},
	}
}

func relCol(rel, name, column string, t ast.FieldType) catalog.FieldInfo {
	return catalog.FieldInfo{
		Name: name, Type: t,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Rel: rel, Column: column},
	}
}

func withDescription(f catalog.FieldInfo, d string) catalog.FieldInfo {
	f.Description = d
	return f
}

// withEnum closes a field's value set without changing how it is read. It is
// separate from enumAs because a DERIVED field has a closed set too — §4.3's
// `strength` is one of four catalogue words — and it has no column.
func withEnum(f catalog.FieldInfo, values ...string) catalog.FieldInfo {
	f.Enum = values
	return f
}

// ----------------------------------------------------------------- tables --

var assetFields = []catalog.FieldInfo{
	{
		Name: "class", Type: ast.TypeClass,
		Accessor:    ast.Accessor{Kind: ast.AccessorColumn, Column: "class_key", PathColumn: "class_path"},
		Description: "class key; \":\" matches the subtree, \"=\" the class exactly",
	},
	col("display_name", ast.TypeText),
	col("hostname", ast.TypeText),
	col("description", ast.TypeText),
	col("primary_address", ast.TypeInet),
	enumAs("environment", "environment", environmentValues...),
	col("business_unit", ast.TypeKeyword),
	col("owner_email", ast.TypeKeyword),
	col("support_group", ast.TypeKeyword),
	col("site", ast.TypeKeyword),
	col("region", ast.TypeKeyword),
	col("zone", ast.TypeKeyword),
	enumAs("status", "asset_status", assetStatusValues...),
	enumAs("ownership", "asset_ownership", assetOwnershipValues...),
	enumAs("stale_status", "stale_status", staleStatusValues...),
	enumAs("source", "class_source_kind", classSourceKindValues...),
	withDescription(derived("proposed_by", "asset.proposed_by", ast.TypeKeyword),
		"sugar for source in (inferred, rule) and class_source_ref=<producer> (§12 amendment 7)"),
	{
		Name: "risk", Type: ast.TypeBand,
		Accessor: ast.Accessor{
			Kind: ast.AccessorColumn, Column: "risk_score", AssessedBy: "risk_assessed_by",
		},
		Description: "risk band; not_assessed means nobody scored it",
	},
	col("risk_score", ast.TypeNumber),
	col("risk_assessed_by", ast.TypeKeywordArray),
	col("confidence_score", ast.TypeNumber),
	col("class_confidence", ast.TypeNumber),
	colAs("first_seen", "first_discovered_at", ast.TypeTimestamp),
	colAs("last_seen", "last_seen_at", ast.TypeTimestamp),
	col("created_at", ast.TypeTimestamp),
	col("updated_at", ast.TypeTimestamp),
	colAs("segment_id", "network_segment_id", ast.TypeUUID),
	col("location_id", ast.TypeUUID),
	withDescription(col("id", ast.TypeUUID),
		"the row's own primary key; the any-kind identifier form is id.any (§13 A1)"),
}

var endpointFields = []catalog.FieldInfo{
	col("address", ast.TypeInet),
	col("fqdn", ast.TypeText),
	col("port", ast.TypeNumber),
	enumAs("transport", "transport", endpointTransportValues...),
	enumAs("protocol", "protocol", protocolValues...),
	col("service_name", ast.TypeKeyword),
	{
		// §5.5 forbids a lexical fallback for a version, so the accessor names
		// the normalised key DATA_MODEL §2 adds alongside it. Whatever writes
		// service_version_sort must call ast.VersionSortKey, or the comparison
		// compares two different normalisations.
		Name: "service_version", Type: ast.TypeVersion,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "service_version", SortColumn: "service_version_sort"},
	},
	enumAs("status", "status", endpointStatusValues...),
	// THREE-VALUED, and the query language gets that for free from SQL: NULL
	// matches neither `= true` nor `= false`, which is exactly right, because
	// NULL here means nobody established the binding. Every endpoint a network
	// scan found is NULL — a scan cannot know, it only sees what answers — and
	// only a host's own view of its sockets (the agent's host inventory, 2.11b)
	// writes either boolean. So `endpoint.bound_local = false` is "measured, and
	// exposed to the network", not "not known to be loopback", and that
	// distinction is the whole reason the column is nullable.
	//
	// Registered here because otherwise the column has no reader at all: it is
	// written by the host-inventory consumer and read by nothing, and a measured
	// value nobody can ask for is the reader-less-table shape this repo keeps
	// paying for. This is the surface a tenant can reach it from today; the
	// asset page's endpoint list does not show it yet.
	col("bound_local", ast.TypeBoolean),
	col("sni", ast.TypeKeywordArray),
	col("alpn", ast.TypeKeywordArray),
	colAs("last_seen", "last_seen_at", ast.TypeTimestamp),
	colAs("last_scanned", "last_scanned_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

var certificateFields = []catalog.FieldInfo{
	col("subject_dn", ast.TypeText),
	col("issuer_dn", ast.TypeText),
	col("fingerprint_sha256", ast.TypeKeyword),
	colAs("key_algorithm", "public_key_algorithm", ast.TypeKeyword),
	colAs("signature_alg", "signature_algorithm", ast.TypeKeyword),
	enumAs("certificate_state", "certificate_state", certificateStateValues...),
	colAs("key_size", "public_key_size", ast.TypeNumber),
	col("not_before", ast.TypeTimestamp),
	col("not_after", ast.TypeTimestamp),
	colAs("self_signed", "is_self_signed", ast.TypeBoolean),
	col("id", ast.TypeUUID),
}

// cryptoFields is §4.3's crypto_configuration table, added by §12 amendment 5.
// The field names are the spec's, and three of them differ from the column:
// `signature_algorithm` and `hash_algorithm` happen to match, `key_exchange`
// and `symmetric_algorithm` do not.
var cryptoFields = []catalog.FieldInfo{
	enumAs("protocol", "protocol", protocolValues...),
	col("protocol_version", ast.TypeKeyword),
	col("cipher_suite", ast.TypeKeyword),
	colAs("key_exchange", "key_exchange_algorithm", ast.TypeKeyword),
	col("signature_algorithm", ast.TypeKeyword),
	colAs("symmetric_algorithm", "symmetric_encryption", ast.TypeKeyword),
	col("hash_algorithm", ast.TypeKeyword),
	col("key_size", ast.TypeNumber),
	col("risk_score", ast.TypeNumber),
	{
		// No AssessedBy: crypto_implementations.risk_score has no companion
		// column proving the row was assessed, so `risk:not_assessed` is not
		// offered here rather than answered from a default of 0 (§5.2).
		Name: "risk", Type: ast.TypeBand,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "risk_score"},
	},
	withEnum(
		withDescription(derived("strength", "crypto.strength", ast.TypeKeyword),
			"algorithms.strength of the worst linked component, via the shared helper"),
		cryptoStrengthValues...),
	derived("algorithm.deprecated", "crypto.algorithm_deprecated", ast.TypeBoolean),
	colAs("first_seen", "first_discovered_at", ast.TypeTimestamp),
	colAs("last_seen", "last_verified_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

// findingFields takes its three vocabularies from shared/findings, the
// generated registry of standards/findings-registry.yaml. The findings table
// carries no CHECK on producer, kind or subject_type — that registry is the
// enforcement point for writes (findings.Validate) and this is the same
// vocabulary for reads.
var findingFields = []catalog.FieldInfo{
	enumAs("producer", "producer", findingProducers()...),
	enumAs("kind", "kind", findingKinds()...),
	enumAs("subject_type", "subject_type", findings.SubjectTypes...),
	enumAs("detection_state", "detection_state", findingDetectionStateValues...),
	enumAs("workflow_status", "workflow_status", findingWorkflowStatusValues...),
	{
		// findings carry a stored severity label AND a score. §13 A2: equality
		// and a range both select their column the same way, through
		// LabelColumn, so `severity:low` and `severity:[low to low]` cannot
		// read two different columns.
		Name: "severity", Type: ast.TypeBand,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "score", LabelColumn: "severity"},
	},
	col("score", ast.TypeNumber),
	col("summary", ast.TypeText),
	col("first_seen", ast.TypeTimestamp),
	col("last_seen", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

// softwareFields reaches software_products through the "product" relation the
// translator joins; install_path and status are the install's own.
var softwareFields = []catalog.FieldInfo{
	relCol("product", "name", "name", ast.TypeText),
	relCol("product", "vendor", "vendor", ast.TypeText),
	{
		Name: "version", Type: ast.TypeVersion,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Rel: "product", Column: "version", SortColumn: "version_sort"},
	},
	relCol("product", "cpe", "cpe", ast.TypeKeyword),
	relCol("product", "purl", "purl", ast.TypeKeyword),
	col("install_path", ast.TypeText),
	enumAs("status", "status", softwareInstallStatusValues...),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
	colAs("last_seen", "last_seen_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

// identifierFields is the `identifier` target — rows of asset_identifiers seen
// as a collection, which is a different thing from the `id.` namespace.
//
// `kind` is the STORED vocabulary and therefore does NOT include the `mac`
// alias. `id.mac` is a spelling of the namespace that resolves to the stored
// kind `mac_address` (§12 amendment 4); `identifier:(kind:mac)` would compare
// the column against "mac" and match nothing, forever and silently.
var identifierFields = []catalog.FieldInfo{
	enumAs("kind", "kind", storedIdentifierKinds()...),
	col("value", ast.TypeKeyword),
	col("scope", ast.TypeKeyword),
	col("confidence", ast.TypeNumber),
	enumAs("source_kind", "source_kind", sourceKindValues...),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
	colAs("last_seen", "last_seen_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

var relationshipFields = []catalog.FieldInfo{
	enumAs("type", "type", ast.RelationshipTypes...),
	enumAs("status", "status", relationshipStatusValues...),
	enumAs("source", "source_kind", sourceKindValues...),
	col("confidence", ast.TypeNumber),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
	colAs("last_seen", "last_seen_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

// observationFields is the approval-rule shape (§8, §13 A8). Dotted names
// because an observation carries the network it was seen on as a nested object;
// the "columns" are the engine's field paths, not a table's.
var observationFields = []catalog.FieldInfo{
	enumAs("source", "source", observationSourceValues...),
	enumAs("kind", "kind", observationKindValues...),
	col("confidence", ast.TypeNumber),
	{
		Name: "class", Type: ast.TypeClass,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "class_key", PathColumn: "class_path"},
	},
	col("hostname", ast.TypeText),
	col("address", ast.TypeInet),
	enumAs("network.ownership", "network_ownership", observationNetworkOwnershipValues...),
	enumAs("network.type", "network_type", observationNetworkTypeValues...),
	colAs("network.segment_id", "network_segment_id", ast.TypeUUID),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
}

// measurementFields carries only §8's reserved scalar; everything else a
// measurement reads is a fact path.
var measurementFields = []catalog.FieldInfo{
	withDescription(col("value", ast.TypeNumber), "the scalar the measurement extracted"),
}

var firstClass = map[string][]catalog.FieldInfo{
	"asset":                assetFields,
	"endpoint":             endpointFields,
	"certificate":          certificateFields,
	"crypto_configuration": cryptoFields,
	"finding":              findingFields,
	"software_install":     softwareFields,
	"identifier":           identifierFields,
	"relationship":         relationshipFields,
	"observation":          observationFields,
	"measurement":          measurementFields,
}

// FirstClassFields returns a target's first-class fields — the hand-written
// half, without the generated namespaces. It is what a TypeScript-mirror
// generator reads; a caller that wants the whole vocabulary wants
// (*Catalog).Fields.
//
// The slice is a copy, sorted by name for determinism.
func FirstClassFields(target string) []catalog.FieldInfo {
	base := firstClass[strings.ToLower(target)]
	out := make([]catalog.FieldInfo, len(base))
	copy(out, base)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// findingProducers and findingKinds flatten shared/findings into value sets.
// Kinds are unique across the whole registry, not just within a producer, which
// is what lets `kind:` be one closed set rather than one per producer.
func findingProducers() []string {
	out := make([]string, 0, len(findings.Producers))
	for _, p := range findings.Producers {
		out = append(out, p.Key)
	}
	return out
}

func findingKinds() []string {
	out := make([]string, 0, len(findings.All))
	seen := make(map[string]bool, len(findings.All))
	for _, k := range findings.All {
		if seen[k.Key] {
			continue
		}
		seen[k.Key] = true
		out = append(out, k.Key)
	}
	return out
}
