// The asset-lens CSV layout, as pure functions so the row builder is testable
// without a DOM (the download itself lives in inventory-page.tsx).
//
// Page-local exports are convenience, not evidence — but they must not lie.
// `assets.risk_score` is NOT NULL DEFAULT 0, so "never assessed" and "assessed
// clean" are both 0 in the column. `assetRisk` (asset-shape.ts) is the single
// rule that tells them apart, and the CSV reuses it: an unassessed asset gets an
// EMPTY risk_score cell, an assessed-clean asset gets 0.
import type { Asset } from '@vistasecurity/api-contract';
import { assetIdentity, assetRisk, businessUnitName, classLabel, primaryAddressPort } from './asset-shape';
import { LIFECYCLE_COLUMN_KEYS, OPTIONAL_BASE_COLUMNS, type AssetColumn } from './columns';

export const ASSET_CSV_HEADER = [
  'name', 'address', 'class', 'environment', 'network', 'status', 'identity_status',
  'has_identity_conflict', 'site', 'location', 'rack', 'u', 'face', 'last_seen_at', 'risk_score',
  // The commercial lifecycle (DCIM gap 4), appended so the columns above keep
  // their positions. Blank when not recorded.
  'warranty_end', 'end_of_support', 'purchase_date', 'vendor',
];

/** The lifecycle cells (DCIM gap 4): the lens's lifecycle columns, as text. */
export function assetLifecycleCsvCells(a: Asset): string[] {
  return LIFECYCLE_COLUMN_KEYS.map((k) => OPTIONAL_BASE_COLUMNS.find((c) => c.key === k)?.value(a) ?? '');
}

/** The placement cells (DCIM rows 2.1/2.3): site, location path, rack, lowest
 *  unit, face — blank when not placed, never a guess. */
export function assetPlacementCsvCells(a: Asset): (string | number)[] {
  const site = a.site && typeof a.site === 'object' ? a.site.name : '';
  const location = a.location && typeof a.location === 'object' ? a.location.path : '';
  const rack = a.rack && typeof a.rack === 'object' ? a.rack : null;
  return [site, location, rack?.name ?? '', rack?.position ?? '', rack?.face ?? ''];
}

/** The risk_score cell: the score when something assessed the asset, blank when
 *  nothing did. Never 0 for "nobody looked". */
export function assetRiskCsvCell(a: Asset): number | '' {
  const risk = assetRisk(a);
  return risk.assessed ? risk.score : '';
}

export function assetCsvRow(a: Asset): (string | number | null | undefined)[] {
  const ident = assetIdentity(a);
  // `address` is the PRIMARY ENDPOINT's address and port (blank when the
  // asset has no network face), and `class` replaces the retired
  // `asset_type`. An importer reading the old header against the new export
  // gets nothing rather than something wrong, which is the point.
  return [
    ident.primary, primaryAddressPort(a), classLabel(a.class_key), a.environment,
    a.prefix || businessUnitName(a.business_unit), a.asset_status, a.identity_status,
    String(a.has_identity_conflict ?? false), ...assetPlacementCsvCells(a), a.last_seen_at, assetRiskCsvCell(a),
    ...assetLifecycleCsvCells(a),
  ];
}

/** The table columns the fixed layout above already carries (as a cell of its
 *  own, often in a fuller form: `last_seen_at` for the relative "Last seen"). */
const COVERED_COLUMN_KEYS: ReadonlySet<string> = new Set([
  'class', 'address', 'environment', 'prefix', 'last_seen', 'risk_score', 'site', ...LIFECYCLE_COLUMN_KEYS,
]);

/** The visible table columns the fixed layout lacks (owner, support group,
 *  business unit, endpoints, the class attributes), in table order. */
export function extraCsvColumns(cols: readonly AssetColumn[]): AssetColumn[] {
  return cols.filter((c) => !COVERED_COLUMN_KEYS.has(c.key));
}

/** An extra column's header: its key, with a class attribute as `attr.<name>`
 *  so a hardware `vendor` attribute (the manufacturer) never reads as the
 *  lifecycle `vendor` column (the seller). */
export function extraCsvHeader(c: AssetColumn): string {
  return c.attribute ? `attr.${c.attribute}` : c.key;
}

/**
 * The export of a set of assets as the lens shows them: the fixed layout
 * (which importers read by header, so its columns keep their names and
 * positions) followed by every VISIBLE column it does not already carry. A
 * column the person turned on in the Columns menu is therefore always in the
 * file; one they never turned on adds nothing.
 */
export function assetCsv(rows: readonly Asset[], visible: readonly AssetColumn[] = []): { header: string[]; rows: (string | number | null | undefined)[][] } {
  const extra = extraCsvColumns(visible);
  return {
    header: [...ASSET_CSV_HEADER, ...extra.map(extraCsvHeader)],
    rows: rows.map((a) => [...assetCsvRow(a), ...extra.map((c) => c.value(a))]),
  };
}
