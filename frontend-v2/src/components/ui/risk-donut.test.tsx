import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { RiskDonut, donutArcs } from './risk-donut';

describe('donutArcs', () => {
  it('lays slices end to end proportionally, with a gap between neighbours', () => {
    const arcs = donutArcs([{ key: 'a', count: 1 }, { key: 'b', count: 3 }], 100, 2);
    expect(arcs).toEqual([
      { key: 'a', length: 23, offset: 0 },
      { key: 'b', length: 73, offset: 25 },
    ]);
  });

  it('drops empty slices and gives a lone slice a gapless full ring', () => {
    expect(donutArcs([{ key: 'a', count: 0 }, { key: 'b', count: 7 }], 100)).toEqual([{ key: 'b', length: 100, offset: 0 }]);
  });

  it('draws nothing for an empty population', () => {
    expect(donutArcs([{ key: 'a', count: 0 }], 100)).toEqual([]);
    expect(donutArcs([], 100)).toEqual([]);
  });
});

describe('RiskDonut', () => {
  const segs = [
    { key: 'high', label: 'High', count: 0, color: 'red' },
    { key: 'unassessed', label: 'Not assessed', count: 5, color: 'grey', muted: true },
  ];

  it('renders arcs only for populated slices but keeps every legend row', () => {
    const html = renderToStaticMarkup(<RiskDonut segments={segs} centerValue="0%" centerLabel="low risk or clean" ariaLabel="x" />);
    expect(html).toContain('risk-donut-arc-unassessed');
    expect(html).not.toContain('risk-donut-arc-high');
    expect(html).toContain('risk-donut-legend-high');
    expect(html).toContain('risk-donut-legend-unassessed');
  });
});
