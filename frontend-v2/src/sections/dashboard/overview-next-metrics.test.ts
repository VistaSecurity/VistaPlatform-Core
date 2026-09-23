// Guards for the Overview 2 arithmetic.
//
// Each block pins a case that was WRONG on the original Overview, or that the
// obvious implementation gets wrong. The fixtures are built so that deleting
// the line under test fails the assertion — a grid whose unscored column is not
// the biggest cell, or a trend with equal seeded endpoints, would let the bug
// through while still reading like a test.
import { describe, expect, it } from 'vitest';
import type { PostureTrendPoint } from '../../components/posture-trend-chart';
import {
  EXPIRY_HORIZON_DAYS, GRID_COLUMNS, expiryOutlook, gridCellQuery, pqcSegments, riskGrid, trendDelta,
} from './overview-next-metrics';

const cert = (d: number | null | undefined) => ({ days_until_expiry: d });
const bucket = (value: string, count: number, label?: string) => ({ value, count, label });

describe('expiryOutlook', () => {
  it('splits expired, the charted weeks, and the far future', () => {
    const o = expiryOutlook([cert(-4), cert(0), cert(6), cert(7), cert(90), cert(91), cert(300)], 1000);
    expect(o.expired).toBe(1);
    expect(o.weeks[0].count).toBe(2); // days 0 and 6
    expect(o.weeks[1].count).toBe(1); // day 7
    expect(o.weeks[12].count).toBe(1); // day 90, the last charted column
    expect(o.beyond).toBe(2); // 91 and 300
  });

  it('paints a column urgent when it contains any day inside the window', () => {
    const o = expiryOutlook([], 1000);
    expect(o.weeks[0].tone).toBe('critical'); // days 0–6
    expect(o.weeks[1].tone).toBe('high'); // days 7–13
    // Days 28–34 straddle the 30-day boundary. Keyed on the week's LAST day it
    // would fall out of the urgent window; keyed on its first it stays in.
    expect(o.weeks[4].tone).toBe('high');
    expect(o.weeks[5].tone).toBe('caution'); // days 35–41
  });

  it('counts the 30-day tile from raw days, not by summing whole weeks', () => {
    // Days 28, 29 and 30 live in the week ENDING on day 34. Summing the columns
    // that end on or before day 30 drops all three.
    const o = expiryOutlook([cert(28), cert(29), cert(30), cert(31), cert(5)], 1000);
    expect(o.dueWithin30).toBe(4);
    const byWholeWeeks = o.weeks.filter((w) => w.to <= 30).reduce((n, w) => n + w.count, 0);
    expect(byWholeWeeks).toBe(1);
  });

  it('drops rows with no numeric expiry rather than counting them as due today', () => {
    const o = expiryOutlook([cert(null), cert(undefined), cert(Number.NaN), cert(3)], 1000);
    expect(o.weeks[0].count).toBe(1);
    expect(o.expired).toBe(0);
  });

  it('flags truncation when the response filled the row limit', () => {
    expect(expiryOutlook([cert(1), cert(2)], 2).truncated).toBe(true);
    expect(expiryOutlook([cert(1), cert(2)], 3).truncated).toBe(false);
  });

  it('floors max at 1 so an empty outlook still divides', () => {
    expect(expiryOutlook([], 1000).max).toBe(1);
    expect(expiryOutlook([], 1000).weeks).toHaveLength(EXPIRY_HORIZON_DAYS / 7);
  });
});

describe('riskGrid', () => {
  // `hardware.computer` is a CHILD of `hardware` and the facet returns both —
  // counting it would put a parent and its own descendant in adjacent rows and
  // inflate every column total.
  const byBand = {
    critical: [bucket('hardware', 3), bucket('hardware.computer', 3), bucket('software', 1)],
    high: [bucket('hardware', 9), bucket('software', 2)],
    not_assessed: [bucket('hardware', 400), bucket('software', 120)],
  };

  it('keeps root classes only', () => {
    const g = riskGrid(byBand);
    expect(g.rows.map((r) => r.path)).toEqual(['hardware', 'software']);
  });

  it('puts each band in its own column, in GRID_COLUMNS order', () => {
    const g = riskGrid(byBand);
    const hardware = g.rows.find((r) => r.path === 'hardware')!;
    const at = (key: string) => hardware.cells[GRID_COLUMNS.findIndex((c) => c.key === key)];
    expect(at('critical')).toBe(3);
    expect(at('high')).toBe(9);
    expect(at('medium')).toBe(0);
    expect(at('not_assessed')).toBe(400);
  });

  it('scales the heat ramp on scored cells only', () => {
    // 400 unscored dwarfs every real risk cell. If it set the scale, the 9 in
    // the High column would be 2% of the ramp and the grid would say nothing.
    expect(riskGrid(byBand).max).toBe(9);
  });

  it('records a failed band instead of reporting it as zeros', () => {
    const g = riskGrid({ critical: [bucket('hardware', 3)] }, ['high']);
    expect(g.failed).toEqual(['high']);
  });

  it('sorts rows by total, biggest first', () => {
    expect(riskGrid(byBand).rows[0].path).toBe('hardware');
  });

  it('builds a cell query that names both the class and the band', () => {
    expect(gridCellQuery('hardware', 'not_assessed')).toBe('class:hardware and risk:not_assessed');
  });
});

describe('pqcSegments', () => {
  const metric = { adoptionPercent: 7, pqcReady: 98, total: 1478, needsMigration: 1284, unclassified: 96 };

  it('keeps not-yet-assessed out of awaiting-migration', () => {
    const [ready, awaiting, unassessed] = pqcSegments(metric);
    expect(ready.count).toBe(98);
    expect(awaiting.count).toBe(1284);
    expect(unassessed.count).toBe(96);
  });

  it('gives widths that sum to the whole', () => {
    const sum = pqcSegments(metric).reduce((n, s) => n + s.pct, 0);
    expect(sum).toBeCloseTo(100, 6);
  });

  it('yields zero widths rather than NaN on an empty tenant', () => {
    const empty = pqcSegments({ adoptionPercent: 0, pqcReady: 0, total: 0, needsMigration: 0, unclassified: 0 });
    for (const s of empty) expect(s.pct).toBe(0);
  });
});

describe('trendDelta', () => {
  const pt = (risk_index: number, seeded: boolean): PostureTrendPoint => ({ date: '2026-09-01', risk_index, seeded });

  it('ignores the seeded baseline prefix', () => {
    // The seeded prefix is flat at 40 and the measured tail RISES. Including
    // the seeded points would put the window's start at 40 and report +2;
    // the measured change is +8.
    const d = trendDelta([pt(40, true), pt(40, true), pt(40, true), pt(34, false), pt(38, false), pt(42, false)])!;
    expect(d.delta).toBe(8);
    expect(d.days).toBe(3);
    expect(d.series).toEqual([34, 38, 42]);
  });

  it('is null when there is not enough measured history to have a direction', () => {
    expect(trendDelta([pt(40, true), pt(40, true), pt(40, false)])).toBeNull();
    expect(trendDelta([])).toBeNull();
    expect(trendDelta(undefined)).toBeNull();
  });

  it('reports an improvement as a negative delta', () => {
    expect(trendDelta([pt(50, false), pt(31, false)])!.delta).toBe(-19);
  });
});
