// The ADR-0002 asset shape, as the UI reads it.
//
// Phase 1 replaced the asset model: an asset is a configuration item with a
// `class_key`, `identifiers[]`, `endpoints[]` and a typed `attributes` bag.
// `ip_address`, `port`, `asset_type` and `operating_system` are GONE from the
// schema — every one of them was a column on the old flat `network_assets` row,
// and every one of them now lives somewhere more specific:
//
//   ip_address / port  →  the asset's ENDPOINTS (an asset has 0..n)
//   asset_type         →  class_key, against the generated taxonomy
//   operating_system   →  attributes, when the class declares it
//
// Every derivation here is pure so the rules below are unit-tested rather than
// eyeballed, and every one of them keeps the honesty rule the old helpers had:
// a field the service does not know renders as an explicit absence, never as a
// confident-looking value.
import { ASSET_CLASSES, ATTRIBUTE_SCHEMAS, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { riskLevelFromScore } from '@vistasecurity/primitives/ratings';
import { probabilityConfidencePercent, percentLabel } from '../../components/ui/ratings';

/** One network face of an asset. Mirrors the AssetEndpoint schema, narrowed to
 *  what display needs, so these stay testable with plain literals. */
export interface EndpointLike {
  id?: string;
  address?: string | null;
  fqdn?: string | null;
  port?: number | null;
  transport?: string | null;
  protocol?: string | null;
  service_name?: string | null;
  service_version?: string | null;
  service_confidence?: string | null;
  service_identification_method?: string | null;
  status?: string | null;
  last_seen_at?: string | null;
  last_scanned_at?: string | null;
}

/** One observed identifier. Mirrors AssetIdentifier. */
export interface IdentifierLike {
  id?: string;
  kind: string;
  value: string;
  scope?: string | null;
  source_kind?: string | null;
  source_ref?: string | null;
  confidence?: number | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
}

/** The minimal read-only asset shape every derivation below takes. Deliberately
 *  NOT the generated `Asset`, so a test can pass a three-field literal. */
export interface AssetLike {
  id?: string;
  class_key?: string | null;
  class_path?: string | null;
  class_source_kind?: string | null;
  class_source_ref?: string | null;
  class_confidence?: number | null;
  display_name?: string | null;
  hostname?: string | null;
  primary_address?: string | null;
  primary_endpoint?: EndpointLike | null;
  endpoints?: EndpointLike[] | null;
  identifiers?: IdentifierLike[] | null;
  attributes?: Record<string, unknown> | null;
  support_group?: string | null;
  environment?: string | null;
  business_unit?: string | null;
  owner_email?: string | null;
  site?: string | null;
  region?: string | null;
  zone?: string | null;
  network_segment_name?: string | null;
  asset_status?: string | null;
  identity_status?: 'legacy' | 'established' | 'operator_confirmed' | null;
  has_identity_conflict?: boolean;
  asset_ownership?: string | null;
  stale_status?: string | null;
  last_seen_at?: string | null;
  risk_score?: unknown;
  risk_level?: string | null;
  risk_assessed_by?: string[] | null;
  certificate_count?: unknown;
  crypto_implementation_count?: unknown;
  protocol_summary?: { protocol: string; count: number; max_risk_score: number }[] | null;
}

const clean = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** Strip an explicit host netmask (/32, /128) off an `inet`-typed address. It is
 *  never meaningful for a single host and reaches the UI baked into stored
 *  values. */
export function stripMask(v?: string | null): string {
  return clean(v).replace(/\/(32|128)$/, '');
}

/**
 * The PRIMARY ENDPOINT rule (phase-1 spec §6, from sub-task B).
 *
 * A list row shows the asset's primary endpoint — the server's
 * `primary_endpoint` when it sent one (the `LATERAL … LIMIT 1` join the read
 * paths already use), else the first of `endpoints[]`. An asset with NO
 * endpoint has none, and the row shows a blank.
 *
 * The rule that matters is the negative one: **never a fabricated port.** The
 * old model gave every asset a `port` column, so an at-rest cloud resource with
 * nothing to connect to still rendered `bucket:0` or `bucket:443`. An asset may
 * genuinely have no network face; saying so is the answer.
 */
export function primaryEndpoint(a: AssetLike): EndpointLike | null {
  if (a.primary_endpoint) return a.primary_endpoint;
  const list = Array.isArray(a.endpoints) ? a.endpoints : [];
  return list.length > 0 ? list[0] : null;
}

/**
 * The address to show when there is room for one: the primary endpoint's
 * address or fqdn, else the convenience `primary_address` column, else ''.
 */
export function primaryAddress(a: AssetLike): string {
  const ep = primaryEndpoint(a);
  if (ep) {
    const addr = stripMask(ep.address) || clean(ep.fqdn);
    if (addr) return addr;
  }
  return stripMask(a.primary_address);
}

/**
 * Address and port together, as one display string. The port is appended ONLY
 * when the primary endpoint carries one — `port` is absent for an at-rest or
 * declared endpoint, and inventing `:0` there is exactly the fabrication this
 * rule exists to stop.
 */
export function primaryAddressPort(a: AssetLike): string {
  const ep = primaryEndpoint(a);
  const addr = primaryAddress(a);
  if (!addr) return '';
  const port = ep && typeof ep.port === 'number' && ep.port > 0 ? ep.port : null;
  return port ? `${addr}:${port}` : addr;
}

/** The human label for a class key, from the generated taxonomy. An unknown key
 *  (a tenant subclass, or a class this build predates) renders as the key
 *  itself rather than as nothing — it is still the truest thing we hold. */
export function classLabel(classKey?: string | null): string {
  const key = clean(classKey);
  if (!key) return '';
  const cls = ASSET_CLASSES[key as AssetClassKey];
  return cls ? cls.label : key;
}

/** `ServerCog` → `server-cog`, `Share2` → `share-2`. The class registry names
 *  its icons as lucide EXPORT names, because the generator validates them
 *  against the package; `Icon` is keyed the way lucide names its files. */
const lucideKebab = (exportName: string): string =>
  exportName.replace(/([a-z0-9])([A-Z])/g, '$1-$2').replace(/([a-zA-Z])(\d)/g, '$1-$2').toLowerCase();

/** The `Icon` name for a class key; `box` for anything unrecognised.
 *
 *  This used to hand back the export name unconverted, and `Icon` — keyed
 *  kebab-case — drew its unknown-name placeholder for every class on the asset
 *  page, the assets lens and Settings → Classes. icon-names.test.ts now walks
 *  the whole taxonomy through this function. */
export function classIcon(classKey?: string | null): string {
  const cls = ASSET_CLASSES[clean(classKey) as AssetClassKey];
  return lucideKebab(cls ? cls.icon : 'Box');
}

/** Does this class declare this attribute? The `attributes` bag is validated
 *  against the class's schema server-side, so a key the class does not declare
 *  should not be there — but a reclassified asset can still carry one, and a
 *  column registry asks this question per class, not per row. */
export function classDeclares(classKey: string | null | undefined, attribute: string): boolean {
  const schema = ATTRIBUTE_SCHEMAS[clean(classKey) as AssetClassKey];
  return !!schema && attribute in schema.properties;
}

/** Read one attribute off the bag as a display string. Numbers and booleans are
 *  rendered; arrays are joined; absent is ''. */
export function attr(a: AssetLike, name: string): string {
  const bag = a.attributes;
  if (!bag || typeof bag !== 'object') return '';
  const v = (bag as Record<string, unknown>)[name];
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return v.map((x) => String(x)).filter(Boolean).join(', ');
  if (typeof v === 'object') return '';
  return String(v).trim();
}

/**
 * Operating system, which is now an ATTRIBUTE and only on the classes that
 * declare one. Returns '' for a class that has no OS concept (a switch, a
 * bucket) rather than an empty-looking "unknown OS" — the distinction is
 * "cannot have one" versus "has one we did not collect", and only the row's
 * class can tell them apart.
 */
export function operatingSystem(a: AssetLike): string {
  if (!classDeclares(a.class_key, 'operating_system')) return '';
  return [attr(a, 'operating_system'), attr(a, 'os_version')].filter(Boolean).join(' ');
}

/**
 * Identity segment: what this thing IS.
 *
 * Title is the display name, else the hostname, else the primary endpoint's
 * address — never a fabricated placeholder. The sub-line carries the address
 * (when the title took a name), the class label, and the OS when the class has
 * one, and is EMPTY when none of those are known rather than repeating the
 * title.
 */
export function assetIdentity(a: AssetLike): { primary: string; secondary: string } {
  const name = clean(a.display_name) || clean(a.hostname);
  const addr = primaryAddressPort(a);
  const primary = name || addr || '—';
  const secondary = [name && addr ? addr : '', classLabel(a.class_key), operatingSystem(a)]
    .filter(Boolean).join(' · ');
  return { primary, secondary };
}

/** Location segment: environment badge + where it lives. `path` is null when
 *  nothing is known — the cell then shows '—', which reads as "unknown", not as
 *  "no segment". */
export function assetLocation(a: AssetLike): { environment: string | null; path: string | null } {
  const geo = [clean(a.site), clean(a.region)].filter(Boolean).join('/');
  const path = [clean(a.network_segment_name) || clean(a.business_unit), geo].filter(Boolean).join(' · ');
  return { environment: clean(a.environment) || null, path: path || null };
}

/**
 * Service segment, now read off the PRIMARY ENDPOINT rather than off the asset.
 * A service is a property of a network face, not of the host: one server runs
 * nginx on 443 and sshd on 22, and the old flat column could hold only one of
 * them. A version with no name is not a service, so both collapse to null
 * together rather than rendering a bare "v1.2.3".
 */
export function assetService(a: AssetLike): { name: string | null; version: string | null } {
  const ep = primaryEndpoint(a);
  const name = clean(ep?.service_name);
  if (!name) return { name: null, version: null };
  const version = clean(ep?.service_version);
  return { name, version: version ? `v${version.replace(/^v/i, '')}` : null };
}

/** How many network faces the asset has. 0 is a real answer for an at-rest
 *  resource; `null` means the payload did not carry the list at all (a list row,
 *  which omits it), and the caller must not render "0 endpoints" for that. */
export function endpointCount(a: AssetLike): number | null {
  return Array.isArray(a.endpoints) ? a.endpoints.length : null;
}

/**
 * Risk, with the three-valued honesty the platform requires.
 *
 * `risk_assessed_by` is the load-bearing field and it is new in phase 1: a
 * score of 0 with an EMPTY `risk_assessed_by` is NOT ASSESSED; a score of 0
 * with a non-empty one is assessed clean. Before this field existed the UI had
 * to guess from the score alone, and it guessed "not assessed" for both — which
 * denied a genuinely clean asset its clean bill of health.
 */
export interface AssetRiskView {
  score: number;
  level: string;
  assessed: boolean;
  assessedBy: string[];
  label: string;
  title: string;
}
export function assetRisk(a: AssetLike): AssetRiskView {
  const score = typeof a.risk_score === 'number' && Number.isFinite(a.risk_score) ? a.risk_score : 0;
  const assessedBy = Array.isArray(a.risk_assessed_by) ? a.risk_assessed_by.filter((s) => clean(s)) : [];
  // A producer having looked is what "assessed" means. A non-zero score implies
  // one looked even on a payload that omitted the array (an older list row).
  const assessed = assessedBy.length > 0 || score > 0;
  const level = assessed ? (clean(a.risk_level) || riskLevelFromScore(score)) : 'Informational';
  return {
    score,
    level,
    assessed,
    assessedBy,
    label: assessed ? String(score) : '—',
    title: assessed
      ? `Risk score ${score} · ${level}${assessedBy.length > 0 ? ` · assessed by ${assessedBy.join(', ')}` : ''}`
      : 'Not assessed — no producer has evaluated this asset',
  };
}

/** The identifier kinds, as words a user can read. */
export const IDENTIFIER_KIND_LABELS: Record<string, string> = {
  agent_id: 'Agent ID',
  cloud_resource_id: 'Cloud resource ID',
  serial_number: 'Serial number',
  cmdb_sys_id: 'CMDB sys_id',
  ssh_host_key_fingerprint: 'SSH host key',
  mac_address: 'MAC address',
  fqdn: 'FQDN',
  hostname: 'Hostname',
  ip_address: 'IP address',
  name: 'Name',
};
export function identifierKindLabel(kind: string): string {
  return IDENTIFIER_KIND_LABELS[clean(kind)] ?? clean(kind).replace(/_/g, ' ');
}

/** Source of an identifier or a class, as a word a user can read. */
export const SOURCE_KIND_LABELS: Record<string, string> = {
  measured: 'Measured',
  declared: 'Declared',
  imported: 'Imported',
  inferred: 'Inferred',
};
export function sourceKindLabel(kind?: string | null): string {
  const k = clean(kind);
  return SOURCE_KIND_LABELS[k] ?? k;
}

/**
 * Relative "last seen", coarser than a timestamp on purpose — a row answers
 * "recently or not", the page answers "exactly when".
 *
 * Go's zero time ("0001-01-01T00:00:00Z") reaches the UI as a real date on rows
 * that were never actually seen. Rendering it as "24237mo ago" would be a
 * confident answer to a question we cannot answer, so it says '' instead.
 */
export function relativeSeen(iso?: string | null): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t) || t <= 0) return '';
  const mins = Math.floor((Date.now() - t) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

/** Confidence as a percentage string, or '' when ABSENT — which means nothing
 *  classified it, not "classified with low confidence". */
export function confidenceLabel(v?: number | null): string {
  const pct = probabilityConfidencePercent(v);
  return pct === null ? '' : percentLabel(pct);
}
