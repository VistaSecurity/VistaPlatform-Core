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

  // Callers hand this gauge raw API floats (`pqc_percentage`, a framework's
  // `preview_score`), so the rounding belongs here rather than at each site —
  // the dashboard's quantum-readiness ring read "36.36363636363637%".
  it('rounds a fractional percentage to a whole percent, in the label too', () => {
    const html = renderToStaticMarkup(<PercentageGauge value={(4 / 11) * 100} label="PQC ready" />);
    expect(html).toContain('36%');
    expect(html).toContain('aria-label="36% PQC ready"');
    expect(html).not.toContain('36.3');
  });

  it('rounds half up and keeps the arc on the rounded value', () => {
    expect(renderToStaticMarkup(<PercentageGauge value={66.6} />)).toContain('67%');
    expect(renderToStaticMarkup(<PercentageGauge value={0.4} />)).toContain('0%');
    expect(renderToStaticMarkup(<PercentageGauge value={99.5} />)).toContain('100%');
  });

  it('renders an unknown percentage neutrally and draws no scored arc', () => {
    const html = renderToStaticMarkup(<PercentageGauge value={null} label="of assets high-risk" />);
    expect(html).toContain('—');
    expect(html).toContain('of assets high-risk unavailable');
    expect(html).toContain('color:var(--neutral)');
    expect((html.match(/<circle/g) ?? [])).toHaveLength(1);
  });
});
