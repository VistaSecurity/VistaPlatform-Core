// The asset-lens CSV layout, as pure functions so the row builder is testable
// without a DOM (the download itself lives in inventory-page.tsx).
//
// Page-local exports are convenience, not evidence — but they must not lie.
// `assets.risk_score` is NOT NULL DEFAULT 0, so "never assessed" and "assessed
// clean" are both 0 in the column. `assetRisk` (asset-shape.ts) is the single
// rule that tells them apart, and the CSV reuses it: an unassessed asset gets an
// EMPTY risk_score cell, an assessed-clean asset gets 0.
import type { Asset } from '@vistasecurity/api-contract';
import { assetIdentity, assetRisk, classLabel, primaryAddressPort } from './asset-shape';

export const ASSET_CSV_HEADER = [
  'name', 'address', 'class', 'environment', 'segment', 'status', 'identity_status',
  'has_identity_conflict', 'last_seen_at', 'risk_score',
];

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
    a.network_segment_name || a.business_unit, a.asset_status, a.identity_status,
    String(a.has_identity_conflict ?? false), a.last_seen_at, assetRiskCsvCell(a),
  ];
}
