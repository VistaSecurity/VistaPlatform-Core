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
// `first_discovered_at`, `network.prefix_id` where it is `network_prefix_id`, `risk`
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
		Subs:         []string{"endpoint", "software", "finding", "cert", "crypto", "identifier", "relationship", "interface"},
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
		// DCIM BUILD_PLAN row 1.2 (QUERY_LANGUAGE §15): an asset's interfaces,
		// `interface:(mac_address:"00:11:22:33:44:55")`.
		Name: "interface", Table: "interfaces", Alias: "ifc", IDColumn: "id",
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
	// business_unit is an OBJECT-valued field (DCIM 1.1): the asset points at a
	// business_units row. A bare reference matches the unit's name or slug;
	// `.id` is the row's uuid and `.parent` matches the named unit and every
	// descendant, so `business_unit.parent = Corporate` finds Finance beneath it.
	derived("business_unit", "asset.business_unit", ast.TypeKeyword),
	colAs("business_unit.id", "business_unit_id", ast.TypeUUID),
	derived("business_unit.parent", "asset.business_unit_parent", ast.TypeKeyword),
	col("owner_email", ast.TypeKeyword),
	col("support_group", ast.TypeKeyword),
	// Placement (DCIM row 2.1, QUERY_LANGUAGE §15 D3): `site` matches the
	// asset's site by name or slug; `.id` is its uuid; `.group` and `.region`
	// match the site's group or region by name/slug AND every descendant; and
	// `location` matches the asset's location or any location above it, by
	// name, slug or name path ("HQ / Floor 2").
	derived("site", "asset.site", ast.TypeKeyword),
	colAs("site.id", "site_id", ast.TypeUUID),
	derived("site.group", "asset.site_group", ast.TypeKeyword),
	derived("site.region", "asset.site_region", ast.TypeKeyword),
	derived("location", "asset.location", ast.TypeKeyword),
	// `region` is the location region, or a cloud resource's provider region
	// when it has no location region (DCIM row 4.6, ADR-0009 D7).
	withDescription(derived("region", "asset.region", ast.TypeKeyword),
		"the location region, or the provider region of a cloud resource that has none"),
	col("zone", ast.TypeKeyword),
	// The device catalogue (DCIM row 2.2): device_type, device_role and
	// platform are OBJECT-valued like business_unit. A bare reference matches
	// the device type's model, slug or part number (the role's and platform's
	// name or slug); `.id` is the row's uuid; device_type.manufacturer matches
	// the type's manufacturer by name or slug. serial and asset_tag are the
	// promoted asset columns.
	derived("device_type", "asset.device_type", ast.TypeKeyword),
	colAs("device_type.id", "device_type_id", ast.TypeUUID),
	derived("device_type.manufacturer", "asset.device_type_manufacturer", ast.TypeKeyword),
	derived("device_role", "asset.device_role", ast.TypeKeyword),
	colAs("device_role.id", "device_role_id", ast.TypeUUID),
	derived("platform", "asset.platform", ast.TypeKeyword),
	colAs("platform.id", "platform_id", ast.TypeUUID),
	col("serial", ast.TypeKeyword),
	col("asset_tag", ast.TypeKeyword),
	// Virtualisation (DCIM row 4.2): the asset's cluster — a VM's
	// (assets.cluster_id) or a hypervisor's (cluster_hosts). `cluster`
	// matches the cluster's name, `cluster.type` its type's name or slug,
	// `cluster.group` its group's name or slug; `cluster.id` is a VM's
	// assets.cluster_id.
	derived("cluster", "asset.cluster", ast.TypeKeyword),
	colAs("cluster.id", "cluster_id", ast.TypeUUID),
	derived("cluster.type", "asset.cluster_type", ast.TypeKeyword),
	derived("cluster.group", "asset.cluster_group", ast.TypeKeyword),
	// Circuits (DCIM row 4.1): circuits terminating at the asset's location.
	// `circuit` matches a circuit's cid or its type's name or slug;
	// circuit.cid the cid alone; circuit.provider the provider's name or slug.
	derived("circuit", "asset.circuit", ast.TypeKeyword),
	derived("circuit.cid", "asset.circuit_cid", ast.TypeKeyword),
	derived("circuit.provider", "asset.circuit_provider", ast.TypeKeyword),
	// Rack placement (DCIM row 2.3, QUERY_LANGUAGE §15 D7): `rack` matches the
	// asset's rack by name or facility id; `.id` is assets.rack_id; `.site` and
	// `.role` match the rack's site and rack role by name or slug. position is
	// the lowest unit the asset occupies (half-U steps), face front or rear.
	derived("rack", "asset.rack", ast.TypeKeyword),
	colAs("rack.id", "rack_id", ast.TypeUUID),
	derived("rack.site", "asset.rack_site", ast.TypeKeyword),
	derived("rack.role", "asset.rack_role", ast.TypeKeyword),
	// Hardware (DCIM row 2.4, QUERY_LANGUAGE §15 D8): `module_type` matches a
	// module installed in the asset by its module type's model, part number or
	// slug; `inventory_item.serial` matches the serial of any of its inventory
	// items; `virtual_chassis` matches the chassis it is a member of by name or
	// domain.
	derived("module_type", "asset.module_type", ast.TypeKeyword),
	derived("inventory_item.serial", "asset.inventory_item_serial", ast.TypeKeyword),
	derived("virtual_chassis", "asset.virtual_chassis", ast.TypeKeyword),
	col("position", ast.TypeNumber),
	enumAs("face", "face", rackFaceValues...),
	// Cloud (DCIM row 4.6, ADR-0009 D7; QUERY_LANGUAGE §15): the
	// cloud_resource attributes every cloud collector writes. `provider` and
	// `account` are the resource's provider and account / subscription /
	// project id; `cloud.type` is the provider's own type string
	// (AWS::EC2::Instance, Microsoft.Compute/virtualMachines, …).
	withEnum(derived("provider", "asset.cloud_provider", ast.TypeKeyword), "aws", "azure", "gcp", "oci", "other"),
	derived("account", "asset.cloud_account", ast.TypeKeyword),
	derived("cloud.type", "asset.cloud_type", ast.TypeKeyword),
	enumAs("status", "asset_status", assetStatusValues...),
	enumAs("identity_status", "identity_status", identityStatusValues...),
	enumAs("ownership", "asset_ownership", assetOwnershipValues...),
	enumAs("stale_status", "stale_status", staleStatusValues...),
	enumAs("source", "class_source_kind", classSourceKindValues...),
	withDescription(derived("proposed_by", "asset.proposed_by", ast.TypeKeyword),
		"sugar for source in (inferred, rule) and class_source_ref=<producer> (§12 amendment 7)"),
	withEnum(withDescription(derived("cert_trust", "asset.cert_trust", ast.TypeKeyword),
		"worst trust status of the asset's certificates; unevaluated = none evaluated yet, none = no certificate"),
		certTrustAssetValues...),
	// IPAM (DCIM row 1.3; QUERY_LANGUAGE §15 D2): the asset's addresses, the
	// longest-match prefix of each within its VRF, that prefix's VLAN and the
	// address's VRF. Computed at query time (shared/query/sql/ipam.go).
	withDescription(derived("ip.address", "asset.ip.address", ast.TypeInet),
		"an IP address of the asset; ':' is CIDR containment (ip.address:10.0.0.0/24)"),
	withDescription(derived("ip.dns_name", "asset.ip.dns_name", ast.TypeKeyword), "the DNS name recorded on one of the asset's addresses"),
	withEnum(derived("ip.status", "asset.ip.status", ast.TypeKeyword), ipStatusValues...),
	withEnum(derived("ip.role", "asset.ip.role", ast.TypeKeyword), ipRoleValues...),
	withDescription(derived("prefix.prefix", "asset.prefix.prefix", ast.TypeInet),
		"the longest-match prefix (within its VRF) of one of the asset's addresses"),
	withEnum(derived("prefix.status", "asset.prefix.status", ast.TypeKeyword), prefixStatusValues...),
	derived("prefix.network_type", "asset.prefix.network_type", ast.TypeKeyword),
	withDescription(derived("vlan.vid", "asset.vlan.vid", ast.TypeNumber), "the VLAN of the prefix one of the asset's addresses is in"),
	derived("vlan.name", "asset.vlan.name", ast.TypeKeyword),
	withDescription(derived("vrf.name", "asset.vrf.name", ast.TypeKeyword), "the VRF one of the asset's addresses is in"),
	// VPN (DCIM row 4.3): a tunnel one of the asset's interfaces terminates.
	withDescription(derived("tunnel", "asset.tunnel", ast.TypeKeyword), "a tunnel one of the asset's interfaces terminates, by name"),
	withEnum(derived("tunnel.encapsulation", "asset.tunnel.encapsulation", ast.TypeKeyword), tunnelEncapsulationValues...),
	withDescription(derived("tunnel.ike_version", "asset.tunnel.ike_version", ast.TypeNumber), "the IKE version (1 or 2) of a tunnel the asset terminates"),
	withDescription(derived("tunnel.pfs_group", "asset.tunnel.pfs_group", ast.TypeNumber), "the phase-2 PFS Diffie-Hellman group of a tunnel the asset terminates"),
	// Wireless (DCIM row 4.4; QUERY_LANGUAGE §15): the wireless LANs the
	// asset's interfaces serve (shared/query/sql/wireless.go).
	withDescription(derived("wireless_lan.ssid", "asset.wireless_lan.ssid", ast.TypeKeyword), "the SSID of a wireless LAN one of the asset's interfaces serves"),
	withDescription(withEnum(derived("wireless_lan.auth_type", "asset.wireless_lan.auth_type", ast.TypeKeyword), wirelessAuthTypeValues...),
		"the authentication of a wireless LAN the asset serves"),
	// Cabling (DCIM row 3.2; QUERY_LANGUAGE §15): the cables on the asset's
	// components (shared/query/sql/cabling.go). cable.status is the cable's
	// operational status; cabled_to the asset on a cable's far end.
	withDescription(withEnum(derived("cable.type", "asset.cable.type", ast.TypeKeyword), cableTypeValues()...),
		"the type of a cable on one of the asset's ports"),
	withDescription(withEnum(derived("cable.status", "asset.cable.status", ast.TypeKeyword), cableStatusValues()...),
		"the operational status (connected, planned, decommissioning) of a cable on one of the asset's ports"),
	withDescription(derived("cabled_to", "asset.cabled_to", ast.TypeKeyword),
		"an asset on the far end of one of the asset's cables, by hostname or display name"),
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
	// The asset-level scan fact: when the newest finished active or automatic
	// scan that reached this asset completed. It lives in `assets.metadata`
	// (inventory-service's autoscan.MetaLastScannedAt) because a scan of an
	// asset with NO endpoint — nothing answered — has no endpoint row to carry
	// `endpoint.last_scanned`, and such an asset could otherwise never be told
	// apart from one nobody ever scanned. A failed scan never writes it.
	withDescription(catalog.FieldInfo{
		Name: "last_scanned", Type: ast.TypeTimestamp,
		Accessor: ast.Accessor{Kind: ast.AccessorJSONB, JSONColumn: "metadata", Key: "last_scanned_at"},
	}, "when the newest finished active or automatic scan reached this asset; absent if none has"),
	col("created_at", ast.TypeTimestamp),
	col("updated_at", ast.TypeTimestamp),
	// The prefix the asset's identity is scoped within (DCIM row 1.6,
	// QUERY_LANGUAGE §15 D6) — what the inventory rail's Prefix facet writes.
	col("prefix_id", ast.TypeUUID),
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
	enumAs("trust_status", "trust_status", certificateTrustStatusValues...),
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
	// DCIM row 1.4 (QUERY_LANGUAGE §15): the IPAM prefix the observation's
	// address falls in (longest match), its VRF, and the interface the
	// observation names. A prefix-scoped rule is read before any other.
	colAs("network.prefix_id", "network_prefix_id", ast.TypeUUID),
	colAs("network.vrf_id", "network_vrf_id", ast.TypeUUID),
	colAs("interface_id", "interface_id", ast.TypeUUID),
	// The cloud account a provider's listing placed the resource in — the
	// scope term of an account-level auto-approval rule (ADR-0009 D5,
	// QUERY_LANGUAGE §15). Keyword, not text: an account id is matched whole.
	colAs("cloud.account_id", "cloud_account_id", ast.TypeKeyword),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
}

// interfaceFields are an interface's first-class fields (§15; DATA_MODEL
// §2.4). `mac_address` is derived: the column is macaddr8, which renders an
// EUI-48 as its EUI-64 form (00:11:22:ff:fe:33:44:55), so the field compares
// against the form a person writes and the API returns.
var interfaceFields = []catalog.FieldInfo{
	col("name", ast.TypeKeyword),
	col("type", ast.TypeKeyword),
	withDescription(derived("mac_address", "interface.mac_address", ast.TypeKeyword),
		"the primary MAC, colon form; an EUI-48 compares as 6 octets"),
	col("enabled", ast.TypeBoolean),
	col("mgmt_only", ast.TypeBoolean),
	col("mtu", ast.TypeNumber),
	col("speed_kbps", ast.TypeNumber),
	enumAs("mode", "mode", interfaceModeValues...),
	enumAs("status", "status", interfaceStatusValues...),
	enumAs("operational_status", "operational_status", interfaceOperStatusValues...),
	col("description", ast.TypeText),
	col("id", ast.TypeUUID),
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
	"interface":            interfaceFields,
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
