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
	derived("region", "asset.region", ast.TypeKeyword),
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
	enumAs("face", "face", "front", "rear"),
	// Cloud (DCIM row 4.6, ADR-0009 D7; QUERY_LANGUAGE §15): the
	// cloud_resource attributes every cloud collector writes. `provider` and
	// `account` are the resource's provider and account / subscription /
	// project id; `cloud.type` is the provider's own type string
	// (AWS::EC2::Instance, Microsoft.Compute/virtualMachines, …).
	enumDerived("provider", "asset.cloud_provider", "aws", "azure", "gcp", "oci", "other"),
	derived("account", "asset.cloud_account", ast.TypeKeyword),
	derived("cloud.type", "asset.cloud_type", ast.TypeKeyword),
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
	enumDerived("cert_trust", "asset.cert_trust",
		"public", "private_trusted", "incomplete", "self_signed", "untrusted", "distrusted", "unevaluated", "none"),
	// IPAM (QUERY_LANGUAGE §15 D2): computed from the asset's addresses.
	derived("ip.address", "asset.ip.address", ast.TypeInet),
	derived("ip.dns_name", "asset.ip.dns_name", ast.TypeKeyword),
	enumDerived("ip.status", "asset.ip.status", "active", "reserved", "deprecated", "dhcp", "slaac"),
	enumDerived("ip.role", "asset.ip.role", "loopback", "secondary", "anycast", "vip", "vrrp", "hsrp", "glbp", "carp"),
	derived("prefix.prefix", "asset.prefix.prefix", ast.TypeInet),
	enumDerived("prefix.status", "asset.prefix.status", "container", "active", "reserved", "deprecated"),
	derived("prefix.network_type", "asset.prefix.network_type", ast.TypeKeyword),
	derived("vlan.vid", "asset.vlan.vid", ast.TypeNumber),
	derived("vlan.name", "asset.vlan.name", ast.TypeKeyword),
	derived("vrf.name", "asset.vrf.name", ast.TypeKeyword),
	// VPN (DCIM row 4.3): a tunnel one of the asset's interfaces terminates.
	derived("tunnel", "asset.tunnel", ast.TypeKeyword),
	enumDerived("tunnel.encapsulation", "asset.tunnel.encapsulation", "ipsec-transport", "ipsec-tunnel", "ip-ip", "gre", "wireguard", "l2tp", "pptp", "openvpn"),
	derived("tunnel.ike_version", "asset.tunnel.ike_version", ast.TypeNumber),
	derived("tunnel.pfs_group", "asset.tunnel.pfs_group", ast.TypeNumber),
	derived("wireless_lan.ssid", "asset.wireless_lan.ssid", ast.TypeKeyword),
	enumDerived("wireless_lan.auth_type", "asset.wireless_lan.auth_type", "open", "wep", "wpa-personal", "wpa-enterprise"),
	// Cabling (DCIM row 3.2): the cables on the asset's components.
	enumDerived("cable.type", "asset.cable.type", "cat3", "cat5", "cat5e", "cat6", "cat6a", "cat7", "cat7a", "cat8", "dac-active", "dac-passive", "mrj21-trunk", "coaxial", "mmf", "mmf-om1", "mmf-om2", "mmf-om3", "mmf-om4", "mmf-om5", "smf", "smf-os1", "smf-os2", "aoc", "usb", "power"),
	enumDerived("cable.status", "asset.cable.status", "connected", "planned", "decommissioning"),
	derived("cabled_to", "asset.cabled_to", ast.TypeKeyword),
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
	// §4.3: the asset-level scan fact, a key of `assets.metadata` because a
	// scan of an asset with no endpoint has no endpoint row to carry
	// `endpoint.last_scanned`.
	{
		Name: "last_scanned", Type: ast.TypeTimestamp,
		Accessor: ast.Accessor{Kind: ast.AccessorJSONB, JSONColumn: "metadata", Key: "last_scanned_at"},
	},
	col("created_at", ast.TypeTimestamp),
	col("updated_at", ast.TypeTimestamp),
	col("prefix_id", ast.TypeUUID),
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
		"TLS", "SSH", "IPSec", "VPN", "Database", "API", "SMB", "Kerberos", "QUIC", "PPTP", "IKE",
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
	enumAs("trust_status", "trust_status",
		"public", "private_trusted", "self_signed", "untrusted", "distrusted", "incomplete"),
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
		"TLS", "SSH", "IPSec", "VPN", "Database", "API", "SMB", "Kerberos", "QUIC", "PPTP", "IKE",
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
		"compliance", "crypto", "eol", "vulnerability", "configuration", "hygiene", "drift", "topology"),
	enumAs("kind", "kind",
		"control_noncompliant", "weak_configuration", "weak_certificate", "pqc_vulnerable", "weak_wireless_auth",
		"os_end_of_life", "software_end_of_life", "hardware_end_of_support", "known_vulnerability",
		"plaintext_management", "default_credentials_exposed", "insecure_service_exposed",
		"no_owner", "no_class", "no_location", "duplicate_suspected", "stale", "orphan_relationship",
		"new_class_in_segment", "unexpected_protocol", "port_profile_changed", "new_issuer",
		"host_key_changed", "cable_drift"),
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
	// `network.type` is FOUR values, not two — §14 B1: private / public / vpn
	// / cloud, the prefix network types an auto-approval rule is generated
	// for (DCIM row 1.6). Published as two, a rule for a cloud or VPN network
	// was refused outright and silently stopped being generated.
	enumAs("network.ownership", "network_ownership", "internal", "third_party", "unknown"),
	enumAs("network.type", "network_type", "private", "public", "vpn", "cloud"),
	// DCIM row 1.4 (§15): prefix, VRF and interface of the observation.
	colAs("network.prefix_id", "network_prefix_id", ast.TypeUUID),
	colAs("network.vrf_id", "network_vrf_id", ast.TypeUUID),
	colAs("interface_id", "interface_id", ast.TypeUUID),
	// The account scope term of a cloud auto-approval rule (ADR-0009 D5, §15).
	colAs("cloud.account_id", "cloud_account_id", ast.TypeKeyword),
	colAs("first_seen", "first_seen_at", ast.TypeTimestamp),
}

// interfaceFields mirror the registry catalogue's (§15).
var interfaceFields = []catalog.FieldInfo{
	col("name", ast.TypeKeyword),
	col("type", ast.TypeKeyword),
	derived("mac_address", "interface.mac_address", ast.TypeKeyword),
	col("enabled", ast.TypeBoolean),
	col("mgmt_only", ast.TypeBoolean),
	col("mtu", ast.TypeNumber),
	col("speed_kbps", ast.TypeNumber),
	enumAs("mode", "mode", "access", "tagged", "tagged-all", "q-in-q"),
	enumAs("status", "status", "pending", "active", "rejected", "stale", "archived"),
	enumAs("operational_status", "operational_status", "up", "down", "testing", "unknown"),
	col("description", ast.TypeText),
	col("id", ast.TypeUUID),
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
	"interface":            interfaceFields,
}

// namespacesByTarget says which of the four namespaces resolve on a target
// (§4.2). Only an asset-shaped row carries class attributes, facts,
// identifiers and tags; a measurement predicate reads facts and nothing else.
var namespacesByTarget = map[string][]ast.Namespace{
	"asset":       {ast.NamespaceAttr, ast.NamespaceFact, ast.NamespaceID, ast.NamespaceTag, ast.NamespaceCF},
	"observation": {ast.NamespaceAttr, ast.NamespaceFact, ast.NamespaceID, ast.NamespaceTag},
	"measurement": {ast.NamespaceFact},
	"interface":   {ast.NamespaceCF},
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
