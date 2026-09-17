import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { PercentageGauge } from './percentage-viz';

describe('PercentageGauge', () => {
  it('renders a percentage and its supplied policy colour without risk words', () => {
    const html = renderToStaticMarkup(<PercentageGauge value={82} color="var(--warn)" label="Inventory hygiene" />);
    expect(html).toContain('82%');
    expect(html).toContain('Inventory hygiene');
    expect(html).toContain('stroke="var(--warn)"');
    expect(html).not.toMatch(/Critical|High risk|Medium risk|Low risk/);
  });

  it('renders an unknown percentage neutrally and draws no scored arc', () => {
    const html = renderToStaticMarkup(<PercentageGauge value={null} label="of assets high-risk" />);
    expect(html).toContain('—');
    expect(html).toContain('of assets high-risk unavailable');
    expect(html).toContain('color:var(--neutral)');
    expect((html.match(/<circle/g) ?? [])).toHaveLength(1);
  });
});
