// The static §4.3 field tables — a mirror of Go's `catalog/testcatalog`.
//
// This is the catalogue the 228 cross-language conformance fixtures resolve
// against, so it is not a place to improve anything: a field renamed, retyped
// or given a different value set here changes what those fixtures prove, and
// they are the contract. Where it differs from the production table in the
// generated `registry-fields.gen.ts` — and it does, in six places — the
// difference is deliberate on both sides and asserted one by one in
// `registry-fields.gen.test.ts`. A seventh was not deliberate: this table
// spelled crypto_configuration's three algorithm fields short, and both now use
// §12 amendment 5's names.
//
// Column names come from DATA_MODEL.md, which is why so many entries rename:
// the language says `first_seen` and the column is `first_discovered_at`, and
// the accessor is the only place that knows.

import type { FieldType } from './ast';
import type { FieldInfo } from './catalog';
import { IDENTIFIER_KINDS } from './targets';
import { RELATIONSHIP_TYPES } from './vocabulary';

function col(name: string, type: FieldType): FieldInfo {
  return { name, type, accessor: { kind: 'column', column: name } };
}

function colAs(name: string, column: string, type: FieldType): FieldInfo {
  return { name, type, accessor: { kind: 'column', column } };
}

/**
 * A keyword column with a closed value set, read through a `::text` cast.
 *
 * The cast is what a Postgres ENUM column needs — neither `lower()` nor a text
 * comparison exists for one, and a value outside the type raises "invalid input
 * value for enum" at query time, an error where the honest answer is "no rows".
 * On a text column with a CHECK it is a no-op, so it is applied to both rather
 * than tracked per column.
 */
function enumAs(name: string, column: string, ...values: string[]): FieldInfo {
  return { name, type: 'keyword', accessor: { kind: 'column', column, cast: 'text' }, enum: values };
}

function derived(name: string, builder: string, type: FieldType): FieldInfo {
  return { name, type, accessor: { kind: 'derived', derived: builder } };
}

/**
 * The protocol vocabulary, matching `public.protocol_type` and therefore the
 * production table.
 *
 * It used to stop at OPC_UA, five values short — EtherNet_IP, BACnet,
 * BACnet_SC, HART_IP and S7 — which is the drift a hand-copied list acquires.
 * The consequence was not cosmetic: `protocol:S7` read as an invalid field
 * value in the spec fixtures while the column happily stored it.
 */
const PROTOCOL_VALUES = [
  'TLS', 'SSH', 'IPSec', 'VPN', 'Database', 'API', 'SMB', 'Kerberos', 'QUIC', 'PPTP', 'IKE',
  'Modbus', 'DNP3', 'MMS', 'ICCP', 'IEC62351', 'OPC_UA',
  'EtherNet_IP', 'BACnet', 'BACnet_SC', 'HART_IP', 'S7',
];

const ASSET_FIELDS: FieldInfo[] = [
  {
    name: 'class',
    type: 'class',
    accessor: { kind: 'column', column: 'class_key', pathColumn: 'class_path' },
    description: 'class key; ":" matches the subtree, "=" the class exactly',
  },
  col('display_name', 'text'),
  col('hostname', 'text'),
  col('description', 'text'),
  col('primary_address', 'inet'),
  // `environment` is the four `environment_type` values, closed (§12 A1).
  //
  // It used to be left open here, because §8's scope mapping and §9 example 18
  // both wrote `prod`. §12 amendment 1 settled that the other way — "Enum wins.
  // No legacy data exists to carry `prod`" — and `assets.environment` IS the
  // Postgres type, so a row holding `prod` cannot exist. An open set turns a
  // typo into an empty result where a closed one gives a diagnostic.
  enumAs('environment', 'environment', 'production', 'staging', 'development', 'test'),
  // Object-valued (DCIM 1.1): name or slug of the assigned business unit;
  // `.id` is its uuid and `.parent` matches the unit and its descendants.
  derived('business_unit', 'asset.business_unit', 'keyword'),
  colAs('business_unit.id', 'business_unit_id', 'uuid'),
  derived('business_unit.parent', 'asset.business_unit_parent', 'keyword'),
  col('owner_email', 'keyword'),
  col('support_group', 'keyword'),
  // Placement (DCIM 2.1): site by name/slug, `.id`, `.group`/`.region` with
  // descendants, and `location` by name, slug or path, including ancestors.
  derived('site', 'asset.site', 'keyword'),
  colAs('site.id', 'site_id', 'uuid'),
  derived('site.group', 'asset.site_group', 'keyword'),
  derived('site.region', 'asset.site_region', 'keyword'),
  derived('location', 'asset.location', 'keyword'),
  // The location region, or a cloud resource's provider region (DCIM 4.6).
  derived('region', 'asset.region', 'keyword'),
  col('zone', 'keyword'),
  // Device catalogue (DCIM 2.2): object-valued like business_unit.
  derived('device_type', 'asset.device_type', 'keyword'),
  colAs('device_type.id', 'device_type_id', 'uuid'),
  derived('device_type.manufacturer', 'asset.device_type_manufacturer', 'keyword'),
  derived('device_role', 'asset.device_role', 'keyword'),
  colAs('device_role.id', 'device_role_id', 'uuid'),
  derived('platform', 'asset.platform', 'keyword'),
  colAs('platform.id', 'platform_id', 'uuid'),
  col('serial', 'keyword'),
  col('asset_tag', 'keyword'),
  // Commercial lifecycle (DCIM gap 4): declared dates, the seller, and the
  // effective end of support (device type or platform, declared or catalogue).
  col('purchase_date', 'timestamp'),
  col('warranty_end', 'timestamp'),
  col('support_contract_end', 'timestamp'),
  col('installed_at', 'timestamp'),
  col('decommissioned_at', 'timestamp'),
  col('vendor', 'keyword'),
  derived('end_of_support', 'asset.end_of_support', 'timestamp'),
  // Virtualisation (DCIM 4.2): the asset's cluster (a VM's or a host's).
  derived('cluster', 'asset.cluster', 'keyword'),
  colAs('cluster.id', 'cluster_id', 'uuid'),
  derived('cluster.type', 'asset.cluster_type', 'keyword'),
  derived('cluster.group', 'asset.cluster_group', 'keyword'),
  // Circuits (DCIM 4.1): circuits terminating at the asset's location.
  derived('circuit', 'asset.circuit', 'keyword'),
  derived('circuit.cid', 'asset.circuit_cid', 'keyword'),
  derived('circuit.provider', 'asset.circuit_provider', 'keyword'),
  // Rack placement (DCIM 2.3): object-valued like site.
  derived('rack', 'asset.rack', 'keyword'),
  colAs('rack.id', 'rack_id', 'uuid'),
  derived('rack.site', 'asset.rack_site', 'keyword'),
  derived('rack.role', 'asset.rack_role', 'keyword'),
  // Hardware (DCIM 2.4): modules, inventory items, virtual chassis.
  derived('module_type', 'asset.module_type', 'keyword'),
  derived('inventory_item.serial', 'asset.inventory_item_serial', 'keyword'),
  // DCIM gap 8: the stock state of one of the asset's inventory items.
  { ...derived('inventory_item.stock_state', 'asset.inventory_item_stock_state', 'keyword'), enum: ['installed', 'in_stock', 'reserved', 'rma', 'retired'] },
  derived('virtual_chassis', 'asset.virtual_chassis', 'keyword'),
  col('position', 'number'),
  enumAs('face', 'face', 'front', 'rear'),
  // Cloud (DCIM 4.6, ADR-0009 D7): the cloud_resource attributes.
  { ...derived('provider', 'asset.cloud_provider', 'keyword'), enum: ['aws', 'azure', 'gcp', 'oci', 'other'] },
  derived('account', 'asset.cloud_account', 'keyword'),
  derived('cloud.type', 'asset.cloud_type', 'keyword'),
  enumAs('status', 'asset_status', 'pending_approval', 'monitoring', 'denied', 'archived'),
  enumAs('ownership', 'asset_ownership', 'internal', 'third_party', 'unknown'),
  enumAs('stale_status', 'stale_status', 'active', 'stale', 'archived'),
  enumAs('identity_status', 'identity_status', 'legacy', 'established', 'provisional', 'operator_confirmed'),
  // Five, and ONLY on the asset target. `assets.class_source_kind` is the one
  // column that accepts `rule` (asset-inventory workstream 2.10b): a class
  // argued from a curated classification_rules row is not `measured` — the MAC
  // was measured, the MAC-to-class mapping was not — and not `inferred`, which
  // ADR-0008 D4.2 defines as a model's proposal. The `source_kind` sets below
  // stay at four, because their CHECKs do.
  enumAs('source', 'class_source_kind', 'measured', 'declared', 'imported', 'inferred', 'rule'),
  derived('proposed_by', 'asset.proposed_by', 'keyword'),
  // The worst trust status of the asset's certificates, plus
  // unevaluated (none evaluated yet) and none (no certificate).
  {
    ...derived('cert_trust', 'asset.cert_trust', 'keyword'),
    enum: ['public', 'private_trusted', 'incomplete', 'self_signed', 'untrusted', 'distrusted', 'unevaluated', 'none'],
  },
  // IPAM (QUERY_LANGUAGE §15 D2): computed from the asset's addresses.
  derived('ip.address', 'asset.ip.address', 'inet'),
  derived('ip.dns_name', 'asset.ip.dns_name', 'keyword'),
  { ...derived('ip.status', 'asset.ip.status', 'keyword'), enum: ['active', 'reserved', 'deprecated', 'dhcp', 'slaac'] },
  { ...derived('ip.role', 'asset.ip.role', 'keyword'), enum: ['loopback', 'secondary', 'anycast', 'vip', 'vrrp', 'hsrp', 'glbp', 'carp'] },
  derived('prefix.prefix', 'asset.prefix.prefix', 'inet'),
  { ...derived('prefix.status', 'asset.prefix.status', 'keyword'), enum: ['container', 'active', 'reserved', 'deprecated'] },
  derived('prefix.network_type', 'asset.prefix.network_type', 'keyword'),
  derived('vlan.vid', 'asset.vlan.vid', 'number'),
  derived('vlan.name', 'asset.vlan.name', 'keyword'),
  derived('vrf.name', 'asset.vrf.name', 'keyword'),
  // VPN (DCIM 4.3): a tunnel one of the asset's interfaces terminates.
  derived('tunnel', 'asset.tunnel', 'keyword'),
  { ...derived('tunnel.encapsulation', 'asset.tunnel.encapsulation', 'keyword'), enum: ['ipsec-transport', 'ipsec-tunnel', 'ip-ip', 'gre', 'wireguard', 'l2tp', 'pptp', 'openvpn'] },
  derived('tunnel.ike_version', 'asset.tunnel.ike_version', 'number'),
  derived('tunnel.pfs_group', 'asset.tunnel.pfs_group', 'number'),
  derived('wireless_lan.ssid', 'asset.wireless_lan.ssid', 'keyword'),
  { ...derived('wireless_lan.auth_type', 'asset.wireless_lan.auth_type', 'keyword'), enum: ['open', 'wep', 'wpa-personal', 'wpa-enterprise'] },
  // Virtual circuits (DCIM gap 10): a virtual circuit the asset's interfaces terminate.
  derived('virtual_circuit', 'asset.virtual_circuit', 'keyword'),
  derived('virtual_circuit.cid', 'asset.virtual_circuit.cid', 'keyword'),
  derived('virtual_circuit.provider', 'asset.virtual_circuit.provider', 'keyword'),
  { ...derived('virtual_circuit.role', 'asset.virtual_circuit.role', 'keyword'), enum: ['peer', 'hub', 'spoke'] },
  // Cabling (DCIM 3.2): the cables on the asset's components.
  { ...derived('cable.type', 'asset.cable.type', 'keyword'), enum: ['cat3', 'cat5', 'cat5e', 'cat6', 'cat6a', 'cat7', 'cat7a', 'cat8', 'dac-active', 'dac-passive', 'mrj21-trunk', 'coaxial', 'mmf', 'mmf-om1', 'mmf-om2', 'mmf-om3', 'mmf-om4', 'mmf-om5', 'smf', 'smf-os1', 'smf-os2', 'aoc', 'usb', 'power'] },
  { ...derived('cable.status', 'asset.cable.status', 'keyword'), enum: ['connected', 'planned', 'decommissioning'] },
  derived('cabled_to', 'asset.cabled_to', 'keyword'),
  // Power (DCIM 6.1): the power feeds the asset's power ports reach.
  { ...derived('power_feed.status', 'asset.power_feed.status', 'keyword'), enum: ['offline', 'active', 'planned', 'failed'] },
  { ...derived('power_feed.type', 'asset.power_feed.type', 'keyword'), enum: ['primary', 'redundant'] },
  { ...derived('power_feed.supply', 'asset.power_feed.supply', 'keyword'), enum: ['ac', 'dc'] },
  { ...derived('power_feed.phase', 'asset.power_feed.phase', 'keyword'), enum: ['single-phase', 'three-phase'] },
  derived('power_feed.voltage', 'asset.power_feed.voltage', 'number'),
  derived('power_feed.amperage', 'asset.power_feed.amperage', 'number'),
  derived('power_feed.available_power', 'asset.power_feed.available_power', 'number'),
  derived('power_feed.panel', 'asset.power_feed.panel', 'keyword'),
  derived('power_feed.rack', 'asset.power_feed.rack', 'keyword'),
  derived('power_feed.site', 'asset.power_feed.site', 'keyword'),
  {
    name: 'risk',
    type: 'band',
    accessor: { kind: 'column', column: 'risk_score', assessedBy: 'risk_assessed_by', surface: 'crypto' },
    description: 'risk band; not_assessed means a crypto surface was seen and nobody scored it, no_crypto_observed means nobody scored it and no crypto surface is on record',
  },
  col('risk_score', 'number'),
  col('risk_assessed_by', 'keyword[]'),
  col('confidence_score', 'number'),
  col('class_confidence', 'number'),
  colAs('first_seen', 'first_discovered_at', 'timestamp'),
  colAs('last_seen', 'last_seen_at', 'timestamp'),
  // §4.3: the asset-level scan fact, a key of `assets.metadata` (a scan of an
  // asset with no endpoint has no endpoint row to carry endpoint.last_scanned).
  { name: 'last_scanned', type: 'timestamp', accessor: { kind: 'jsonb', jsonColumn: 'metadata', key: 'last_scanned_at' } },
  col('created_at', 'timestamp'),
  col('updated_at', 'timestamp'),
  col('prefix_id', 'uuid'),
  col('location_id', 'uuid'),
  col('id', 'uuid'),
];

const ENDPOINT_FIELDS: FieldInfo[] = [
  col('address', 'inet'),
  col('fqdn', 'text'),
  col('port', 'number'),
  enumAs('transport', 'transport', 'tcp', 'udp', 'none'),
  enumAs('protocol', 'protocol', ...PROTOCOL_VALUES),
  col('service_name', 'keyword'),
  {
    name: 'service_version',
    type: 'version',
    // A sortColumn is REQUIRED for a version field (§5.5 forbids a lexical
    // fallback). DATA_MODEL gives `version_sort` to software_products only, so
    // asset_endpoints needs the same column — §12 contradiction 6.
    accessor: { kind: 'column', column: 'service_version', sortColumn: 'service_version_sort' },
  },
  enumAs('status', 'status', 'active', 'stale', 'closed'),
  // Three-valued; NULL matches neither `= true` nor `= false`, which is the
  // point. See the registry catalogue's copy for why.
  col('bound_local', 'boolean'),
  col('sni', 'keyword[]'),
  col('alpn', 'keyword[]'),
  colAs('last_seen', 'last_seen_at', 'timestamp'),
  colAs('last_scanned', 'last_scanned_at', 'timestamp'),
  col('id', 'uuid'),
];

const CERTIFICATE_FIELDS: FieldInfo[] = [
  col('subject_dn', 'text'),
  col('issuer_dn', 'text'),
  col('fingerprint_sha256', 'keyword'),
  colAs('key_algorithm', 'public_key_algorithm', 'keyword'),
  colAs('signature_alg', 'signature_algorithm', 'keyword'),
  enumAs(
    'certificate_state',
    'certificate_state',
    'pre-activation', 'active', 'suspended', 'deactivated', 'revoked', 'expired', 'destroyed',
  ),
  colAs('key_size', 'public_key_size', 'number'),
  col('not_before', 'timestamp'),
  col('not_after', 'timestamp'),
  colAs('self_signed', 'is_self_signed', 'boolean'),
  enumAs(
    'trust_status',
    'trust_status',
    'public', 'private_trusted', 'self_signed', 'untrusted', 'distrusted', 'incomplete',
  ),
  col('id', 'uuid'),
];

// crypto_configuration has no field table in §4.3 (§12 contradiction 5); these
// are the crypto_implementations columns the lens already exposes, plus the two
// derived fields §8 calls for.
//
// The three algorithm fields are named as §12 amendment 5 names them. They were
// `signature`, `symmetric` and `hash` here while the production table used the
// long forms, and no conformance fixture touched any of the six — so the two
// catalogues disagreed about a field name with nothing able to notice, because
// the exemption list only catches a case that RUNS. Renamed on both sides
// rather than exempted (workstream 0.8e); `registry-fields.gen.test.ts` now
// asserts the two agree.
const CRYPTO_FIELDS: FieldInfo[] = [
  enumAs('protocol', 'protocol', ...PROTOCOL_VALUES),
  col('protocol_version', 'keyword'),
  col('cipher_suite', 'keyword'),
  colAs('key_exchange', 'key_exchange_algorithm', 'keyword'),
  col('signature_algorithm', 'keyword'),
  colAs('symmetric_algorithm', 'symmetric_encryption', 'keyword'),
  col('hash_algorithm', 'keyword'),
  col('key_size', 'number'),
  col('risk_score', 'number'),
  { name: 'risk', type: 'band', accessor: { kind: 'column', column: 'risk_score' } },
  // The four values the `algorithms` catalogue's `valid_strength` CHECK allows.
  // Published with NO closed set, `strength:strng` validated and then returned
  // nothing rather than being refused with a suggestion.
  {
    ...derived('strength', 'crypto.strength', 'keyword'),
    enum: ['weak', 'acceptable', 'strong', 'recommended'],
  },
  derived('algorithm.deprecated', 'crypto.algorithm_deprecated', 'boolean'),
  colAs('first_seen', 'first_discovered_at', 'timestamp'),
  colAs('last_seen', 'last_verified_at', 'timestamp'),
  col('id', 'uuid'),
];

const FINDING_FIELDS: FieldInfo[] = [
  enumAs(
    'producer', 'producer',
    'compliance', 'crypto', 'eol', 'vulnerability', 'configuration', 'hygiene', 'drift', 'topology',
  ),
  enumAs(
    'kind', 'kind',
    'control_noncompliant', 'weak_configuration', 'weak_certificate', 'pqc_vulnerable', 'weak_wireless_auth', 'unencrypted_at_rest',
    'os_end_of_life', 'software_end_of_life', 'hardware_end_of_support', 'known_vulnerability',
    'plaintext_management', 'default_credentials_exposed', 'insecure_service_exposed',
    'no_owner', 'no_class', 'no_location', 'duplicate_suspected', 'stale', 'orphan_relationship',
    'not_racked', 'no_rack_position', 'planned_cable_stale', 'cable_unconfirmed', 'interface_no_type',
    'duplicate_address', 'warranty_expired', 'past_end_of_support', 'end_of_support_soon',
    'new_class_in_segment', 'unexpected_protocol', 'port_profile_changed', 'new_issuer',
    'host_key_changed', 'cable_drift',
  ),
  enumAs(
    'subject_type', 'subject_type',
    'asset', 'endpoint', 'certificate', 'key', 'crypto_configuration', 'software_install',
    'relationship', 'control', 'framework',
  ),
  enumAs('detection_state', 'detection_state', 'ACTIVE', 'INACTIVE', 'ARCHIVED'),
  enumAs('workflow_status', 'workflow_status', 'NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'),
  {
    // findings carry a stored severity label AND a score. §13 A2: equality and
    // a range both select their column the same way, through labelColumn, so
    // `severity:low` and `severity:[low to low]` cannot read two different
    // columns.
    name: 'severity',
    type: 'band',
    accessor: { kind: 'column', column: 'score', labelColumn: 'severity' },
  },
  col('score', 'number'),
  col('summary', 'text'),
  colAs('first_seen', 'first_seen', 'timestamp'),
  colAs('last_seen', 'last_seen', 'timestamp'),
  col('id', 'uuid'),
];

const SOFTWARE_FIELDS: FieldInfo[] = [
  { name: 'name', type: 'text', accessor: { kind: 'column', rel: 'product', column: 'name' } },
  { name: 'vendor', type: 'text', accessor: { kind: 'column', rel: 'product', column: 'vendor' } },
  {
    name: 'version',
    type: 'version',
    accessor: { kind: 'column', rel: 'product', column: 'version', sortColumn: 'version_sort' },
  },
  { name: 'cpe', type: 'keyword', accessor: { kind: 'column', rel: 'product', column: 'cpe' } },
  { name: 'purl', type: 'keyword', accessor: { kind: 'column', rel: 'product', column: 'purl' } },
  col('install_path', 'text'),
  enumAs('status', 'status', 'active', 'stale', 'removed'),
  colAs('first_seen', 'first_seen_at', 'timestamp'),
  colAs('last_seen', 'last_seen_at', 'timestamp'),
  col('id', 'uuid'),
];

// The static catalogue's `identifier.kind` includes the `mac` ALIAS, where the
// production one carries only the stored kinds. `identifier:(kind:mac)` would
// compare the column against "mac" and match nothing.
const IDENTIFIER_FIELDS: FieldInfo[] = [
  // The STORED kinds, WITHOUT the aliases. `id.mac` is a documented spelling of
  // a PATH, rewritten to `mac_address` before it reaches the column; offering
  // `mac` as a legal VALUE of `kind` validates `identifier:(kind:mac)` and then
  // matches nothing, for ever and silently.
  enumAs('kind', 'kind', ...IDENTIFIER_KINDS),
  col('value', 'keyword'),
  col('scope', 'keyword'),
  col('confidence', 'number'),
  enumAs('source_kind', 'source_kind', 'measured', 'declared', 'imported', 'inferred'),
  colAs('first_seen', 'first_seen_at', 'timestamp'),
  colAs('last_seen', 'last_seen_at', 'timestamp'),
  col('id', 'uuid'),
];

const RELATIONSHIP_FIELDS: FieldInfo[] = [
  enumAs('type', 'type', ...RELATIONSHIP_TYPES),
  enumAs('status', 'status', 'pending', 'active', 'rejected', 'stale'),
  enumAs('source', 'source_kind', 'measured', 'declared', 'imported', 'inferred'),
  col('confidence', 'number'),
  col('id', 'uuid'),
];

// observation is the approval-rule shape (§8). Its fields are dotted because
// the observation carries the network it was seen on as a nested object.
const OBSERVATION_FIELDS: FieldInfo[] = [
  enumAs('source', 'source', 'sensor', 'cloud', 'interrogation', 'import', 'manual', 'agent'),
  // What the observation IS, as distinct from who produced it. Both halves are
  // needed and neither implies the other: a sensor produces a cryptographic
  // measurement and a passive host-presence row alike, so `source` alone cannot
  // name either one. Mirrors testcatalog.observationFields — see the note
  // there for why the spec catalogue carries it too.
  enumAs('kind', 'kind', 'crypto', 'host_observation'),
  col('confidence', 'number'),
  {
    name: 'class',
    type: 'class',
    accessor: { kind: 'column', column: 'class_key', pathColumn: 'class_path' },
  },
  col('hostname', 'text'),
  col('address', 'inet'),
  // The vocabulary is the live classifier's (shared/approval's Classification),
  // not an invented one: ownership is internal / third_party / unknown and type
  // is private / public. §8 mapped `conditions.network_type` to
  // `network.type:corporate`, and nothing in the platform has ever emitted
  // "corporate" — §13 A8.
  enumAs('network.ownership', 'network_ownership', 'internal', 'third_party', 'unknown'),
  // FOUR values, not two: private / public / vpn / cloud, the prefix network
  // types an auto-approval rule is generated for (§14 B1, DCIM row 1.6).
  // Published as two, a rule for a cloud or VPN network was refused outright
  // and silently stopped being generated.
  enumAs('network.type', 'network_type', 'private', 'public', 'vpn', 'cloud'),
  // DCIM row 1.4 (§15): prefix, VRF and interface of the observation.
  colAs('network.prefix_id', 'network_prefix_id', 'uuid'),
  colAs('network.vrf_id', 'network_vrf_id', 'uuid'),
  colAs('interface_id', 'interface_id', 'uuid'),
  // The account scope term of a cloud auto-approval rule (ADR-0009 D5, §15).
  // Mirrors testcatalog.observationFields.
  colAs('cloud.account_id', 'cloud_account_id', 'keyword'),
  colAs('first_seen', 'first_seen_at', 'timestamp'),
];

// measurement carries only §8's reserved scalar; everything else it reads is a
// fact path.
// §15 (DCIM row 1.2). `mac_address` is derived: the column is macaddr8.
const INTERFACE_FIELDS: FieldInfo[] = [
  col('name', 'keyword'),
  col('type', 'keyword'),
  derived('mac_address', 'interface.mac_address', 'keyword'),
  col('enabled', 'boolean'),
  col('mgmt_only', 'boolean'),
  col('mtu', 'number'),
  col('speed_kbps', 'number'),
  enumAs('mode', 'mode', 'access', 'tagged', 'tagged-all', 'q-in-q'),
  enumAs('status', 'status', 'pending', 'active', 'rejected', 'stale', 'archived'),
  enumAs('operational_status', 'operational_status', 'up', 'down', 'testing', 'unknown'),
  derived('virtual_device_context', 'interface.virtual_device_context', 'keyword'),
  col('description', 'text'),
  col('id', 'uuid'),
];

const MEASUREMENT_FIELDS: FieldInfo[] = [
  {
    name: 'value',
    type: 'number',
    accessor: { kind: 'column', column: 'value' },
    description: 'the scalar the measurement extracted',
  },
];

/** The static catalogue's first-class fields, keyed by target name. */
export const TEST_FIELDS_BY_TARGET: Readonly<Record<string, readonly FieldInfo[]>> = {
  asset: ASSET_FIELDS,
  endpoint: ENDPOINT_FIELDS,
  certificate: CERTIFICATE_FIELDS,
  crypto_configuration: CRYPTO_FIELDS,
  finding: FINDING_FIELDS,
  software_install: SOFTWARE_FIELDS,
  identifier: IDENTIFIER_FIELDS,
  relationship: RELATIONSHIP_FIELDS,
  observation: OBSERVATION_FIELDS,
  measurement: MEASUREMENT_FIELDS,
  interface: INTERFACE_FIELDS,
};
