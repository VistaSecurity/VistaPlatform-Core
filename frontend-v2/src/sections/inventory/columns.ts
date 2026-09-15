// The per-class column registry.
//
// ADR-0006 D2: "Columns adapt by the selected class's attribute set (a server
// shows OS and serial; a cloud resource shows provider and account; an
// application shows version and hosts). The column sets are declared per class
// in a registry, not hand-coded per page."
//
// The registry is DERIVED, not written out: the base columns are the ones every
// class has, and the class columns come from the generated attribute schemas
// (`@vistasecurity/primitives/assets`). Adding a class to
// `standards/asset-classes.yaml` therefore gives it columns without a page
// edit, which is the property the ADR asks for and the reason a hand-written
// table would have been the wrong answer — twelve classes would have meant
// twelve lists to forget to update.
import { ATTRIBUTE_SCHEMAS, ASSET_CLASSES, type AssetClassKey } from '@vistasecurity/primitives/assets';
import {
  assetRisk, attr, classLabel, endpointCount, primaryAddressPort, relativeSeen,
  type AssetLike,
} from './asset-shape';

/** One column of the assets table. */
export interface AssetColumn {
  key: string;
  label: string;
  /** CSS grid track for this column. */
  width: string;
  /** Renders the cell's text. Cells are text-only by design — the table is a
   *  dense list, and anything that needs a widget belongs on the asset page. */
  value: (a: AssetLike) => string;
  /** Right-aligned numeric/measure columns. */
  numeric?: boolean;
  /** Monospace — addresses, serials, versions. */
  mono?: boolean;
  /** Which attribute this column reads, when it is a class column. */
  attribute?: string;
}

/** The columns every class has, in the order they are shown. Identity and risk
 *  are rendered by the row itself (they carry the chip and the two-line name),
 *  so they are not in this list — this is what comes AFTER them. */
export const BASE_COLUMNS: AssetColumn[] = [
  { key: 'class', label: 'Class', width: 'minmax(0,1fr)', value: (a) => classLabel(a.class_key) },
  { key: 'address', label: 'Address', width: 'minmax(0,1.2fr)', mono: true, value: (a) => primaryAddressPort(a) },
  { key: 'environment', label: 'Environment', width: 'minmax(0,0.9fr)', value: (a) => a.environment ?? '' },
  { key: 'owner', label: 'Owner', width: 'minmax(0,1.1fr)', value: (a) => a.owner_email ?? '' },
  { key: 'last_seen', label: 'Last seen', width: '96px', value: (a) => relativeSeen(a.last_seen_at) },
];

/**
 * Columns that are only worth a track when the selected class actually has the
 * concept. `support_group` is on every class in the schema but is empty for
 * most tenants, so it is opt-in rather than base.
 */
export const OPTIONAL_BASE_COLUMNS: AssetColumn[] = [
  { key: 'support_group', label: 'Support group', width: 'minmax(0,1fr)', value: (a) => a.support_group ?? '' },
  { key: 'site', label: 'Site', width: 'minmax(0,0.9fr)', value: (a) => a.site ?? '' },
  { key: 'business_unit', label: 'Business unit', width: 'minmax(0,1fr)', value: (a) => a.business_unit ?? '' },
  { key: 'segment', label: 'Segment', width: 'minmax(0,1fr)', value: (a) => a.network_segment_name ?? '' },
  { key: 'endpoints', label: 'Endpoints', width: '84px', numeric: true, value: (a) => { const n = endpointCount(a); return n === null ? '' : String(n); } },
  { key: 'risk_score', label: 'Risk', width: '70px', numeric: true, value: (a) => assetRisk(a).label },
];

/**
 * The attributes worth a column, per class, most-identifying first.
 *
 * A class can declare a dozen attributes and a table has room for three, so the
 * registry ranks them rather than showing all: an operator scanning a list of
 * servers wants OS and serial, not `memory_mb`. Anything not ranked here is
 * still on the asset page's Overview — this list is about the TABLE's budget,
 * not about which attributes exist.
 */
const ATTRIBUTE_RANK: readonly string[] = [
  // identity-ish first
  'operating_system', 'os_version', 'serial_number', 'model', 'vendor',
  'cloud_provider', 'account_id', 'resource_type', 'engine', 'engine_version',
  'version', 'runtime', 'image', 'firmware_version', 'software_version',
  'ip_protocol', 'server_role', 'architecture', 'asset_tag', 'cpu_count', 'memory_mb',
];

/** How many attribute columns a class contributes. Three keeps the row legible
 *  at the narrowest supported width; the rest are one click away on the page. */
export const MAX_CLASS_COLUMNS = 3;

/**
 * The attribute columns for a class, ranked. Returns [] for an unknown class
 * key (a tenant subclass this build has never seen) rather than throwing — the
 * table then shows base columns only, which is correct and not empty.
 */
export function classColumns(classKey: string | null | undefined, limit = MAX_CLASS_COLUMNS): AssetColumn[] {
  const schema = ATTRIBUTE_SCHEMAS[(classKey ?? '') as AssetClassKey];
  if (!schema) return [];
  const declared = Object.keys(schema.properties);
  const ranked = [
    ...ATTRIBUTE_RANK.filter((k) => declared.includes(k)),
    ...declared.filter((k) => !ATTRIBUTE_RANK.includes(k)).sort(),
  ];
  return ranked.slice(0, limit).map((name) => ({
    key: `attr.${name}`,
    label: humanise(name),
    width: 'minmax(0,1fr)',
    attribute: name,
    mono: name === 'serial_number' || name.endsWith('_version') || name === 'version',
    value: (a: AssetLike) => attr(a, name),
  }));
}

/**
 * The full column set for the currently selected class.
 *
 * When the facet is at a PARENT class (or at no class at all) the sensible
 * default applies: a parent's own attribute set is the intersection its
 * children share, so `hardware` contributes vendor/model/asset_tag and nothing
 * class-specific — which is exactly right, because a list mixing servers and
 * switches has no common OS column to show. With no class selected there is no
 * attribute set at all and the table falls back to base columns plus Segment,
 * which is the most useful thing to say about a heterogeneous list.
 */
export function columnsForClass(classKey: string | null | undefined): AssetColumn[] {
  const attributeCols = classColumns(classKey);
  if (attributeCols.length === 0) {
    const segment = OPTIONAL_BASE_COLUMNS.find((c) => c.key === 'segment');
    return segment ? [...BASE_COLUMNS, segment] : [...BASE_COLUMNS];
  }
  // Address stays; environment and owner give up their tracks to the class
  // columns, which are the more specific answer once a class is chosen.
  const keep = BASE_COLUMNS.filter((c) => c.key !== 'owner');
  return [...keep, ...attributeCols];
}

/** The grid template for a column set, with the leading risk-chip and identity
 *  tracks the row itself renders. */
export function gridTemplate(cols: AssetColumn[]): string {
  return ['22px', 'minmax(0,1.6fr)', ...cols.map((c) => c.width)].join(' ');
}

/** `operating_system` → `Operating system`; `os_version` → `OS version`. */
export function humanise(name: string): string {
  const words = name.split('_');
  const first = words[0] === 'os' || words[0] === 'cpu' || words[0] === 'ip'
    ? words[0].toUpperCase()
    : words[0].charAt(0).toUpperCase() + words[0].slice(1);
  const rest = words.slice(1).map((w) => (w === 'id' ? 'ID' : w === 'mb' ? 'MB' : w));
  return [first, ...rest].join(' ');
}

/** Every class key that has at least one declared attribute, for the registry's
 *  own parity test. */
export function classesWithAttributes(): AssetClassKey[] {
  return (Object.keys(ASSET_CLASSES) as AssetClassKey[])
    .filter((k) => Object.keys(ATTRIBUTE_SCHEMAS[k]?.properties ?? {}).length > 0);
}
