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
  'TLS', 'SSH', 'IPSec', 'VPN', 'Database', 'API', 'SMB', 'Kerberos', 'QUIC', 'PPTP',
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
  col('business_unit', 'keyword'),
  col('owner_email', 'keyword'),
  col('support_group', 'keyword'),
  col('site', 'keyword'),
  col('region', 'keyword'),
  col('zone', 'keyword'),
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
  {
    name: 'risk',
    type: 'band',
    accessor: { kind: 'column', column: 'risk_score', assessedBy: 'risk_assessed_by' },
    description: 'risk band; not_assessed means nobody scored it',
  },
  col('risk_score', 'number'),
  col('risk_assessed_by', 'keyword[]'),
  col('confidence_score', 'number'),
  col('class_confidence', 'number'),
  colAs('first_seen', 'first_discovered_at', 'timestamp'),
  colAs('last_seen', 'last_seen_at', 'timestamp'),
  col('created_at', 'timestamp'),
  col('updated_at', 'timestamp'),
  colAs('segment_id', 'network_segment_id', 'uuid'),
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
    'compliance', 'crypto', 'eol', 'vulnerability', 'configuration', 'hygiene', 'drift',
  ),
  enumAs(
    'kind', 'kind',
    'control_noncompliant', 'weak_configuration', 'weak_certificate', 'pqc_vulnerable',
    'os_end_of_life', 'software_end_of_life', 'hardware_end_of_support', 'known_vulnerability',
    'plaintext_management', 'default_credentials_exposed', 'insecure_service_exposed',
    'no_owner', 'no_class', 'no_location', 'duplicate_suspected', 'stale', 'orphan_relationship',
    'new_class_in_segment', 'unexpected_protocol', 'port_profile_changed', 'new_issuer',
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
  // FOUR values, not two. The classifier copies the matching SEGMENT's
  // `network_type` column through, and `network_segments_network_type_check`
  // allows private / public / vpn / cloud (§14 B1). Published as two, an
  // auto-approval rule for a cloud or VPN segment was refused outright and that
  // segment silently stopped generating one. The production table was corrected
  // then; this copy was not.
  enumAs('network.type', 'network_type', 'private', 'public', 'vpn', 'cloud'),
  colAs('network.segment_id', 'network_segment_id', 'uuid'),
  colAs('first_seen', 'first_seen_at', 'timestamp'),
];

// measurement carries only §8's reserved scalar; everything else it reads is a
// fact path.
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
};
