// Posture control grid — pure pivot logic, extracted from posture-overview.tsx
// so it can be unit tested without a DOM/React harness (H-9).
//
// Bug this fixes: the grid used to pivot findings against /infrastructure-assets
// rows ONLY, via `g.ids.has(f.asset_id)`. Live QA data showed 15 of 19
// findings carry asset_ids that are certificate or crypto-configuration ids —
// they can never appear in any (dim value) x (control) cell, because
// AssetFacts is keyed by infrastructure-asset id. Those findings were silently
// dropped from every cell and from every row total, so the grid's totals
// contradicted the scorecards and Top Exposures panel on the same page, which
// both read the same underlying finding set.
//
// Fix: any finding whose asset_id does not resolve to a known infrastructure
// asset is now rolled into an explicit "Certificates / Configurations" row
// instead of vanishing. This keeps the pivot honest — sum of all row totals
// across the grid always equals the number of (control, asset_id) finding
// pairs fed in — without requiring a backend change to resolve every
// certificate/config back to a specific deployed asset (tracked as an open
// question for a fuller fix).
import { levelFromScore, type RiskLevel } from '../../components/ui';
import { sevLevel, sevRank, type BatchFinding } from './model';
import { normalizeControlStatus } from './control-status';
import type { AssetFacts } from './queries';

export const UNATTRIBUTED_ROW_KEY = 'Certificates / Configurations';

export interface GridCol {
  id: string;
  fwId: string;
  name: string;
  fw: string;
  /** Control status from batch-evaluate; absent/unknown is treated as not-assessed. */
  status?: string;
  not_assessed_reason?: string;
}

export interface GridCell {
  fail: number;
  ratio: number;
  /**
   * True when the COLUMN's control was never assessed. Such a cell has
   * no findings, but it is not clean — it must render muted rather than as the
   * green check a zero-finding cell gets, or "we didn't check" and "nothing
   * wrong here" look identical across the whole grid.
   */
  notAssessed: boolean;
  /** Machine-readable reason for the muted cell's tooltip; only set when notAssessed. */
  notAssessedReason?: string;
}

export interface GridRow {
  key: string;
  count: number;
  cells: GridCell[];
  totFail: number;
  level: RiskLevel;
  /** True for the synthetic catch-all row — findings whose asset_id isn't a known infrastructure asset. */
  unattributed?: boolean;
}

/**
 * Pivot compliance findings into a (dim value) x (control) grid.
 *
 * `facts` keys by infrastructure-asset id (the only asset kind that carries
 * environment/business-unit/asset-type dims). `findingsByControl` values may
 * reference asset_ids of ANY kind compliance_findings.asset_type allows
 * (network_asset / certificate / crypto_implementation) — see
 * scripts/database/schema.sql `compliance_findings_asset_type_check`.
 */
export function buildControlGrid(
  facts: Map<string, AssetFacts>,
  cols: GridCol[],
  findingsByControl: Map<string, BatchFinding[]>,
  dim: 'environment' | 'businessUnit' | 'assetType',
): GridRow[] {
  if (!facts.size || !cols.length) return [];

  // A control's not-assessed state is a property of the CONTROL, so it applies
  // to every row's cell in that column — computed once here rather than
  // re-derived per cell.
  const colNotAssessed = cols.map((c) => normalizeControlStatus(c.status) === 'NOT_ASSESSED');

  const groups = new Map<string, { ids: Set<string>; riskSum: number }>();
  facts.forEach((f, id) => {
    const k = f[dim] || 'unspecified';
    if (!groups.has(k)) groups.set(k, { ids: new Set(), riskSum: 0 });
    const g = groups.get(k)!;
    g.ids.add(id);
    g.riskSum += f.riskScore;
  });

  const rows: GridRow[] = [...groups.entries()].map(([key, g]) => {
    const cells = cols.map((ck, ci) => {
      const fs = (findingsByControl.get(ck.id) ?? []).filter((f) => g.ids.has(f.asset_id));
      return {
        fail: fs.length,
        ratio: g.ids.size ? Math.min(1, fs.length / g.ids.size) : 0,
        notAssessed: colNotAssessed[ci],
        notAssessedReason: colNotAssessed[ci] ? ck.not_assessed_reason : undefined,
      };
    });
    const totFail = cells.reduce((sum, c) => sum + c.fail, 0);
    const avg = g.ids.size ? Math.round(g.riskSum / g.ids.size) : 0;
    return { key, count: g.ids.size, cells, totFail, level: levelFromScore(avg) };
  });

  // Findings whose asset_id never matched an infrastructure-asset row — these
  // are the certificate/crypto-configuration-scoped findings the pivot used to
  // drop outright. Collect them into one labeled row instead.
  const unattributedIds = new Set<string>();
  const unattributedFindings: BatchFinding[] = [];
  cols.forEach((ck) => {
    (findingsByControl.get(ck.id) ?? []).forEach((f) => {
      if (!facts.has(f.asset_id)) {
        unattributedIds.add(f.asset_id);
        unattributedFindings.push(f);
      }
    });
  });

  if (unattributedIds.size) {
    const cells = cols.map((ck, ci) => {
      const fs = (findingsByControl.get(ck.id) ?? []).filter((f) => !facts.has(f.asset_id));
      return {
        fail: fs.length,
        ratio: unattributedIds.size ? Math.min(1, fs.length / unattributedIds.size) : 0,
        notAssessed: colNotAssessed[ci],
        notAssessedReason: colNotAssessed[ci] ? ck.not_assessed_reason : undefined,
      };
    });
    const totFail = cells.reduce((sum, c) => sum + c.fail, 0);
    const worst = unattributedFindings.reduce<RiskLevel>((acc, f) => {
      const lvl = sevLevel(f.severity) as RiskLevel;
      return sevRank(lvl) < sevRank(acc) ? lvl : acc;
    }, 'Informational');
    rows.push({ key: UNATTRIBUTED_ROW_KEY, count: unattributedIds.size, cells, totFail, level: worst, unattributed: true });
  }

  return rows.sort((a, b) => b.totFail - a.totFail);
}
