// Regression test for H-9 (live QA): the Posture control grid pivoted
// findings against /infrastructure-assets rows only, so any finding whose
// asset_id pointed at a certificate or crypto-configuration (not an
// infrastructure asset) vanished from every grid cell and every row total —
// contradicting the scorecards and Top Exposures panel fed by the same
// finding set. See buildControlGrid in posture-grid.ts for the fix.
import { describe, it, expect } from 'vitest';
import { buildControlGrid, UNATTRIBUTED_ROW_KEY, type GridCol } from './posture-grid';
import type { AssetFacts } from './queries';
import type { BatchFinding } from './model';

function facts(entries: Array<[string, Partial<AssetFacts>]>): Map<string, AssetFacts> {
  const m = new Map<string, AssetFacts>();
  entries.forEach(([id, f]) =>
    m.set(id, { hostname: '—', environment: 'unspecified', businessUnit: 'Unassigned', assetType: 'unknown', riskScore: 0, ...f }));
  return m;
}

function finding(assetId: string, controlId: string, severity: string): BatchFinding {
  return { id: `${controlId}-${assetId}`, control_id: controlId, asset_id: assetId, severity, summary: 'test finding' };
}

const cols: GridCol[] = [{ id: 'ctrl-1', fwId: 'fw-1', name: 'Control 1', fw: 'PCI-DSS' }];

describe('buildControlGrid', () => {
  it('counts a finding against a known infrastructure asset normally', () => {
    const f = facts([['asset-1', { environment: 'production', riskScore: 50 }]]);
    const findingsByControl = new Map([['ctrl-1', [finding('asset-1', 'ctrl-1', 'High')]]]);
    const rows = buildControlGrid(f, cols, findingsByControl, 'environment');
    expect(rows).toHaveLength(1);
    expect(rows[0].key).toBe('production');
    expect(rows[0].cells[0].fail).toBe(1);
    expect(rows[0].totFail).toBe(1);
  });

  it('does NOT drop findings whose asset_id is not an infrastructure asset (H-9)', () => {
    const f = facts([['asset-1', { environment: 'production', riskScore: 50 }]]);
    // 3 of these 4 findings target certificate/crypto-config ids that never
    // appear in `facts` — the live ratio (15 of 19) reproduced at
    // smaller scale.
    const findingsByControl = new Map([['ctrl-1', [
      finding('asset-1', 'ctrl-1', 'High'),
      finding('cert-1', 'ctrl-1', 'Critical'),
      finding('cert-2', 'ctrl-1', 'Medium'),
      finding('cfg-1', 'ctrl-1', 'Low'),
    ]]]);
    const rows = buildControlGrid(f, cols, findingsByControl, 'environment');

    // reconciliation: total findings fed in === total findings plotted.
    const totalPlotted = rows.reduce((sum, r) => sum + r.totFail, 0);
    expect(totalPlotted).toBe(4);

    const unattributed = rows.find((r) => r.key === UNATTRIBUTED_ROW_KEY);
    expect(unattributed).toBeDefined();
    expect(unattributed!.unattributed).toBe(true);
    expect(unattributed!.count).toBe(3);
    expect(unattributed!.cells[0].fail).toBe(3);
    // worst severity among the unattributed findings is Critical (cert-1).
    expect(unattributed!.level).toBe('Critical');

    const production = rows.find((r) => r.key === 'production');
    expect(production!.cells[0].fail).toBe(1);
  });

  it('omits the unattributed row entirely when every finding resolves', () => {
    const f = facts([['asset-1', { environment: 'production', riskScore: 10 }]]);
    const findingsByControl = new Map([['ctrl-1', [finding('asset-1', 'ctrl-1', 'Low')]]]);
    const rows = buildControlGrid(f, cols, findingsByControl, 'environment');
    expect(rows.find((r) => r.key === UNATTRIBUTED_ROW_KEY)).toBeUndefined();
  });

  it('returns nothing when there are no assets or no columns', () => {
    expect(buildControlGrid(new Map(), cols, new Map(), 'environment')).toEqual([]);
    expect(buildControlGrid(facts([['a', {}]]), [], new Map(), 'environment')).toEqual([]);
  });
});
