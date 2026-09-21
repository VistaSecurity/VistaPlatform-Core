// Package testcatalog is a static implementation of catalog.Catalog holding
// QUERY_LANGUAGE.md §4.3's field tables for every target, plus representative
// keys in the four namespaces.
//
// It is the catalogue the conformance fixtures resolve against, and the
// worked example of what the generated catalogue must produce. The production
// catalogue will read the generated registries (shared/assetclass from
// standards/asset-classes.yaml, shared/facts from standards/fact-keys.yaml)
// and register the same shapes; nothing outside this package changes when it
// does.
//
// Column names come from DATA_MODEL.md, which is why so many entries rename:
// the language says `first_seen` and the column is `first_discovered_at`, and
// the accessor is the only place that knows.
package testcatalog

import (
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/query/ast"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog"
	"github.com/vistasecurity/vistaplatform/shared/query/catalog/ladder"
)

// Catalog is the static catalogue.
type Catalog struct{}

// New returns the static catalogue.
func New() *Catalog { return &Catalog{} }

// CVSSLadder adapts the shared owner for conformance fixtures.
type CVSSLadder struct{}

func (CVSSLadder) Bands() []catalog.Band { return ladder.CVSS.Bands() }

// Ladder is the ladder instance callers pass to the translator.
var Ladder = CVSSLadder{}

// ---------------------------------------------------------------- targets --

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
		// The approval-rule target (§4.1, §8). It has no table: an observation
		// is the in-flight discovery the identification engine holds in
		// memory, so a query over it is evaluated there, never in SQL.
		Name: "observation", Table: "", Alias: "o", IDColumn: "",
		InMemory: true,
	},
	{
		// The compliance-measurement target. §4.1 does not list it, but §8
		// reserves the name `value` for a measurement's extracted scalar and
		// allows fact paths beside it, and a predicate needs a target to
		// resolve against. Like observation it has no table: the measurement
		// extractor evaluates it. See README, spec contradiction 3.
		Name: "measurement", Table: "", Alias: "m", IDColumn: "",
		InMemory: true,
	},
}

// Targets implements catalog.Catalog.
func (c *Catalog) Targets() []catalog.Target { return targets }

// ----------------------------------------------------------------- fields --

func col(name string, t ast.FieldType) catalog.FieldInfo {
	return catalog.FieldInfo{Name: name, Type: t, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: name}}
}

func colAs(name, column string, t ast.FieldType) catalog.FieldInfo {
	return catalog.FieldInfo{Name: name, Type: t, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: column}}
}

// enumAs is a keyword column with a closed value set, read through a ::text
// cast. The cast is what a Postgres ENUM column needs — neither lower() nor a
// text comparison exists for one — and a no-op on a text column with a CHECK,
// so it is applied to both rather than tracked per column.
//
// (castCol, an un-enumerated version of this, was the last home of the open
// `environment` field and went with it.)
func enumAs(name, column string, values ...string) catalog.FieldInfo {
	f := colAs(name, column, ast.TypeKeyword)
	f.Accessor.Cast = "text"
	f.Enum = values
	return f
}

func derived(name, builder string, t ast.FieldType) catalog.FieldInfo {
	return catalog.FieldInfo{
		Name: name, Type: t,
		Accessor: ast.Accessor{Kind: ast.AccessorDerived, Derived: builder},
	}
}

// enumDerived is a derived keyword field with a closed value set. A derived
// field can have one: `strength` is computed by a shared helper from the
// `algorithms` catalogue, and what it can return is exactly that table's
// `valid_strength` CHECK.
func enumDerived(name, builder string, values ...string) catalog.FieldInfo {
	f := derived(name, builder, ast.TypeKeyword)
	f.Enum = values
	return f
}

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
	// `environment` is the four `environment_type` values, closed (§12 A1).
	//
	// It used to be left open, because §8's scope mapping and §9 example 18
	// both wrote `prod`, which is not a member. §12 amendment 1 settled that
	// the other way — "Enum wins. No legacy data exists to carry `prod`; §8 row
	// and ex. 18 rewritten" — and the spec was amended, but this catalogue and
	// three fixtures were not, so `prod` went on validating here long after the
	// document stopped asking for it.
	//
	// It is not a close call: `assets.environment` IS the Postgres type, so a
	// row holding `prod` cannot exist. An open set turns a typo into an empty
	// result where a closed one gives a diagnostic with a suggestion.
	//
	// The ::text cast is not cosmetic: neither lower() nor a text comparison
	// exists for an enum. Without it a value outside the enum raises "invalid
	// input value for enum" at query time — an error where the honest answer
	// is "no rows".
	enumAs("environment", "environment", "production", "staging", "development", "test"),
	col("business_unit", ast.TypeKeyword),
	col("owner_email", ast.TypeKeyword),
	col("support_group", ast.TypeKeyword),
	col("site", ast.TypeKeyword),
	col("region", ast.TypeKeyword),
	col("zone", ast.TypeKeyword),
	enumAs("status", "asset_status", "pending_approval", "monitoring", "denied", "archived"),
	enumAs("ownership", "asset_ownership", "internal", "third_party", "unknown"),
	enumAs("stale_status", "stale_status", "active", "stale", "archived"),
	enumAs("identity_status", "identity_status", "legacy", "established", "provisional", "operator_confirmed"),
	// Five, and ONLY on the asset target. `assets.class_source_kind` is the one
	// column that accepts `rule` (asset-inventory workstream 2.10b): a class
	// argued from a curated classification_rules row is not `measured` — the MAC
	// was measured, the MAC-to-class mapping was not — and not `inferred`, which
	// ADR-0008 D4.2 defines as a model's proposal. The `source_kind` sets on
	// identifiers, relationships, facts and the rest stay at four, because their
	// CHECKs do: widening those here would make the editor accept a predicate the
	// database answers with no rows, for ever.
	enumAs("source", "class_source_kind", "measured", "declared", "imported", "inferred", "rule"),
	derived("proposed_by", "asset.proposed_by", ast.TypeKeyword),
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
	col("id", ast.TypeUUID),
}

var endpointFields = []catalog.FieldInfo{
	col("address", ast.TypeInet),
	col("fqdn", ast.TypeText),
	col("port", ast.TypeNumber),
	enumAs("transport", "transport", "tcp", "udp", "none"),
	// The full `protocol_type` vocabulary, matching the registry-derived
	// catalogue and the database CHECK. The five OT protocols added after this
	// list was written — BACnet, BACnet_SC, EtherNet_IP, HART_IP, S7 — were
	// missing, so `protocol:S7` read as an invalid field value in the spec
	// fixture while the column accepted it.
	enumAs("protocol", "protocol",
		"TLS", "SSH", "IPSec", "VPN", "Database", "API", "SMB", "Kerberos", "QUIC", "PPTP",
		"Modbus", "DNP3", "MMS", "ICCP", "IEC62351", "OPC_UA",
		"EtherNet_IP", "BACnet", "BACnet_SC", "HART_IP", "S7"),
	col("service_name", ast.TypeKeyword),
	{
		Name: "service_version", Type: ast.TypeVersion,
		// SortColumn is required for a version field (§5.5 forbids a lexical
		// fallback). DATA_MODEL gives `version_sort` to software_products only,
		// so asset_endpoints needs the same column; see README.
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "service_version", SortColumn: "service_version_sort"},
	},
	enumAs("status", "status", "active", "stale", "closed"),
	// Three-valued; NULL matches neither `= true` nor `= false`, which is the
	// point. See the registry catalogue's copy for why.
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
	enumAs("certificate_state", "certificate_state",
		"pre-activation", "active", "suspended", "deactivated", "revoked", "expired", "destroyed"),
	colAs("key_size", "public_key_size", ast.TypeNumber),
	col("not_before", ast.TypeTimestamp),
	col("not_after", ast.TypeTimestamp),
	colAs("self_signed", "is_self_signed", ast.TypeBoolean),
	col("id", ast.TypeUUID),
}

// crypto_configuration has no field table in §4.3; these are the
// crypto_implementations columns the lens already exposes, plus the two derived
// fields §8 calls for.
//
// The three algorithm fields are named as §12 amendment 5 names them —
// `signature_algorithm`, `symmetric_algorithm`, `hash_algorithm`. They were
// `signature`, `symmetric` and `hash` here while registrycatalog used the long
// forms, and no conformance fixture touched any of the six, so the two
// catalogues disagreed about a field name with nothing to notice: the exemption
// list only catches a case that RUNS. Renamed rather than exempted, because
// which spelling is right is not a difference between two catalogues.
var cryptoFields = []catalog.FieldInfo{
	// The full `protocol_type` vocabulary, matching the registry-derived
	// catalogue and the database CHECK. The five OT protocols added after this
	// list was written — BACnet, BACnet_SC, EtherNet_IP, HART_IP, S7 — were
	// missing, so `protocol:S7` read as an invalid field value in the spec
	// fixture while the column accepted it.
	enumAs("protocol", "protocol",
		"TLS", "SSH", "IPSec", "VPN", "Database", "API", "SMB", "Kerberos", "QUIC", "PPTP",
		"Modbus", "DNP3", "MMS", "ICCP", "IEC62351", "OPC_UA",
		"EtherNet_IP", "BACnet", "BACnet_SC", "HART_IP", "S7"),
	col("protocol_version", ast.TypeKeyword),
	col("cipher_suite", ast.TypeKeyword),
	colAs("key_exchange", "key_exchange_algorithm", ast.TypeKeyword),
	col("signature_algorithm", ast.TypeKeyword),
	colAs("symmetric_algorithm", "symmetric_encryption", ast.TypeKeyword),
	col("hash_algorithm", ast.TypeKeyword),
	col("key_size", ast.TypeNumber),
	col("risk_score", ast.TypeNumber),
	{
		Name: "risk", Type: ast.TypeBand,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "risk_score"},
	},
	// The four values the `algorithms` catalogue's `valid_strength` CHECK
	// allows. It published NO closed set, so `strength:strng` validated and
	// returned nothing rather than being refused with a suggestion.
	enumDerived("strength", "crypto.strength", "weak", "acceptable", "strong", "recommended"),
	derived("algorithm.deprecated", "crypto.algorithm_deprecated", ast.TypeBoolean),
	colAs("first_seen", "first_discovered_at", ast.TypeTimestamp),
	colAs("last_seen", "last_verified_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

var findingFields = []catalog.FieldInfo{
	enumAs("producer", "producer",
		"compliance", "crypto", "eol", "vulnerability", "configuration", "hygiene", "drift"),
	enumAs("kind", "kind",
		"control_noncompliant", "weak_configuration", "weak_certificate", "pqc_vulnerable",
		"os_end_of_life", "software_end_of_life", "hardware_end_of_support", "known_vulnerability",
		"plaintext_management", "default_credentials_exposed", "insecure_service_exposed",
		"no_owner", "no_class", "no_location", "duplicate_suspected", "stale", "orphan_relationship",
		"new_class_in_segment", "unexpected_protocol", "port_profile_changed", "new_issuer"),
	enumAs("subject_type", "subject_type",
		"asset", "endpoint", "certificate", "key", "crypto_configuration", "software_install",
		"relationship", "control", "framework"),
	enumAs("detection_state", "detection_state", "ACTIVE", "INACTIVE", "ARCHIVED"),
	enumAs("workflow_status", "workflow_status", "NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"),
	{
		Name: "severity", Type: ast.TypeBand,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "score", LabelColumn: "severity"},
	},
	col("score", ast.TypeNumber),
	col("summary", ast.TypeText),
	colAs("first_seen", "first_seen", ast.TypeTimestamp),
	colAs("last_seen", "last_seen", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

var softwareFields = []catalog.FieldInfo{
	{Name: "name", Type: ast.TypeText, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Rel: "product", Column: "name"}},
	{Name: "vendor", Type: ast.TypeText, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Rel: "product", Column: "vendor"}},
	{
		Name: "version", Type: ast.TypeVersion,
		Accessor: ast.Accessor{Kind: ast.AccessorColumn, Rel: "product", Column: "version", SortColumn: "version_sort"},
	},
	{Name: "cpe", Type: ast.TypeKeyword, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Rel: "product", Column: "cpe"}},
	{Name: "purl", Type: ast.TypeKeyword, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Rel: "product", Column: "purl"}},
	col("install_path", ast.TypeText),
	enumAs("status", "status", "active", "stale", "removed"),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
	colAs("last_seen", "last_seen_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

var identifierFields = []catalog.FieldInfo{
	// The STORED kinds, not every spelling `id.<kind>` accepts: `id.mac` is a
	// documented path alias rewritten to `mac_address`, and offering `mac` as a
	// value of the `kind` column would validate a predicate no row can satisfy.
	enumAs("kind", "kind", storedIdentifierKinds...),
	col("value", ast.TypeKeyword),
	col("scope", ast.TypeKeyword),
	col("confidence", ast.TypeNumber),
	enumAs("source_kind", "source_kind", "measured", "declared", "imported", "inferred"),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
	colAs("last_seen", "last_seen_at", ast.TypeTimestamp),
	col("id", ast.TypeUUID),
}

var relationshipFields = []catalog.FieldInfo{
	enumAs("type", "type", ast.RelationshipTypes...),
	enumAs("status", "status", "pending", "active", "rejected", "stale"),
	enumAs("source", "source_kind", "measured", "declared", "imported", "inferred"),
	col("confidence", ast.TypeNumber),
	col("id", ast.TypeUUID),
}

// observation is the approval-rule shape (§8). Its fields are dotted because
// the observation carries the network it was seen on as a nested object.
var observationFields = []catalog.FieldInfo{
	enumAs("source", "source", "sensor", "cloud", "interrogation", "import", "manual", "agent"),
	// What the observation IS, as distinct from who produced it. Both halves
	// are needed and neither implies the other: a sensor produces a
	// cryptographic measurement and a passive host-presence row alike, so
	// `source` alone cannot name either one.
	//
	// It is here, in the SPEC catalogue, and not only in registrycatalog,
	// because a field only one of the two tables carries is a field no
	// conformance fixture can ever write — and a difference nothing exercises
	// is one nobody notices. That is exactly how crypto_configuration's
	// signature/symmetric/hash names drifted for as long as they did (§12 A5):
	// the exemption list only catches a case that RUNS.
	enumAs("kind", "kind", "crypto", "host_observation"),
	col("confidence", ast.TypeNumber),
	{Name: "class", Type: ast.TypeClass, Accessor: ast.Accessor{Kind: ast.AccessorColumn, Column: "class_key", PathColumn: "class_path"}},
	col("hostname", ast.TypeText),
	col("address", ast.TypeInet),
	// The vocabulary is the live classifier's (shared/approval's
	// Classification), not an invented one: ownership is internal /
	// third_party / unknown. §8 mapped `conditions.network_type` to
	// `network.type:corporate`, and nothing in the platform has ever emitted
	// "corporate" — §13 A8.
	//
	// `network.type` is FOUR values, not two — §14 B1. The classifier copies
	// the matching segment's `network_type` column through and
	// `network_segments_network_type_check` allows private / public / vpn /
	// cloud; published as two, an auto-approval rule for a cloud or VPN segment
	// was refused outright and that segment silently stopped generating one.
	// The registry-derived catalogue was corrected then; this copy was not.
	enumAs("network.ownership", "network_ownership", "internal", "third_party", "unknown"),
	enumAs("network.type", "network_type", "private", "public", "vpn", "cloud"),
	colAs("network.segment_id", "network_segment_id", ast.TypeUUID),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
}

// measurement carries only the reserved scalar; everything else it reads is a
// fact path (§8's compliance rows).
var measurementFields = []catalog.FieldInfo{
	{
		Name: "value", Type: ast.TypeNumber,
		Accessor:    ast.Accessor{Kind: ast.AccessorColumn, Column: "value"},
		Description: "the scalar the measurement extracted",
	},
}

var fieldsByTarget = map[string][]catalog.FieldInfo{
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

// namespacesByTarget says which of the four namespaces resolve on a target
// (§4.2). Only an asset-shaped row carries class attributes, facts,
// identifiers and tags; a measurement predicate reads facts and nothing else.
var namespacesByTarget = map[string][]ast.Namespace{
	"asset":       {ast.NamespaceAttr, ast.NamespaceFact, ast.NamespaceID, ast.NamespaceTag},
	"observation": {ast.NamespaceAttr, ast.NamespaceFact, ast.NamespaceID, ast.NamespaceTag},
	"measurement": {ast.NamespaceFact},
}

func namespaceAllowed(target string, ns ast.Namespace) bool {
	for _, n := range namespacesByTarget[target] {
		if n == ns {
			return true
		}
	}
	return false
}

// Fields implements catalog.Catalog. Namespaced entries are appended so
// autocomplete and the unknown_field suggestion see the whole vocabulary.
func (c *Catalog) Fields(target string) []catalog.FieldInfo {
	target = strings.ToLower(target)
	base := fieldsByTarget[target]
	if len(namespacesByTarget[target]) == 0 {
		return base
	}
	out := make([]catalog.FieldInfo, 0, len(base)+len(attrKeys)+len(factKeys)+len(identifierKinds)+2)
	out = append(out, base...)
	if namespaceAllowed(target, ast.NamespaceAttr) {
		for _, k := range sortedKeys(attrKeys) {
			f := attrKeys[k]
			f.Name = "attr." + k
			out = append(out, f)
		}
	}
	if namespaceAllowed(target, ast.NamespaceFact) {
		for _, k := range sortedKeys(factKeys) {
			f := factKeys[k]
			f.Name = "fact." + k
			out = append(out, f)
		}
	}
	if namespaceAllowed(target, ast.NamespaceID) {
		for _, k := range identifierKinds {
			out = append(out, catalog.FieldInfo{
				Name: "id." + k, Type: ast.TypeKeyword,
				Accessor: ast.Accessor{Kind: ast.AccessorIdentifier, Column: "value", Key: k},
			})
		}
		// The any-kind form is `id.any`, NOT a second entry named `id`: a
		// bare `id` is the row's uuid column, and publishing two fields under
		// one name made autocomplete and the "did you mean" suggestion both
		// wrong about which one a user would get (§13 A1).
		out = append(out, catalog.FieldInfo{
			Name: "id." + IdentifierAnyKind, Type: ast.TypeKeyword,
			Accessor: ast.Accessor{Kind: ast.AccessorIdentifierAny, Column: "value"},
		})
	}
	if namespaceAllowed(target, ast.NamespaceTag) {
		out = append(out, catalog.FieldInfo{
			Name: "tag", Type: ast.TypeText,
			Accessor: ast.Accessor{Kind: ast.AccessorTagAny, JSONColumn: "tags"},
		})
	}
	return out
}

// RelationshipNames implements catalog.Catalog.
func (c *Catalog) RelationshipNames() []ast.Relationship { return ast.Relationships }

// EnumValues implements catalog.Catalog.
func (c *Catalog) EnumValues(field ast.FieldRef) ([]string, bool) {
	if len(field.Enum) == 0 {
		return nil, false
	}
	return field.Enum, true
}

func sortedKeys(m map[string]catalog.FieldInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion sort keeps the dependency list empty and the order stable
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
