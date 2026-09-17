import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

function source(relative: string): string {
  return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
}

describe('rating presentation wiring', () => {
  it('uses percentage presentation for hygiene and high-risk population share', () => {
    const hygiene = source('../../sections/dashboard/inventory-health-hero.tsx');
    const posture = source('../../sections/posture/posture-overview.tsx');
    const dashboard = source('../../sections/dashboard/dashboard-page.tsx');

    expect(hygiene).toContain('<PercentageGauge value={hygiene.score}');
    expect(hygiene).toContain('hygienePercentageColor(hygiene.score)');
    expect(posture).toContain('<PercentageGauge value={pctHigh}');
    expect(posture).toContain('proportionPercent(s?.high_risk ?? 0, total)');
    expect(posture).toContain('{assessedAssets.toLocaleString()} assessed');
    expect(dashboard).toContain('proportionPercent(high, total)');
    expect(dashboard).toContain('dashboard-high-risk-percent');
    expect(posture).not.toContain('<RiskGauge score={pctHigh}');
    expect(hygiene).not.toContain('<RiskGauge');
  });

  it('keeps PQC adoption off the individual-risk gauge', () => {
    const dashboard = source('../../sections/dashboard/dashboard-page.tsx');
    expect(dashboard).toContain('<PercentageGauge value={pqc.isError || pqc.isLoading ? null : pqcPct}');
    expect(dashboard).not.toContain('<RiskGauge score={pqcPct}');
  });
});
