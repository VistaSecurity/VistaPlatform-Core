import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { CryptoRiskChip, cryptoRiskPresentation } from './crypto-risk-presentation';

describe('crypto risk presentation', () => {
  it('renders an explicit assessed zero as Informational', () => {
    const risk = cryptoRiskPresentation({ risk_score: 0, risk_score_assessed: true, risk_level: 'Informational' });
    expect(risk).toMatchObject({ assessed: true, score: 0, level: 'Informational' });
    const html = renderToStaticMarkup(<CryptoRiskChip config={{ risk_score: 0, risk_score_assessed: true, risk_level: 'Informational' }} />);
    expect(html).toContain('aria-label="Informational"');
    expect(html).toContain('Risk score 0');
  });

  it.each([
    { risk_score: null, risk_score_assessed: false },
    { risk_score: 0, risk_score_assessed: false },
  ])('renders absent numeric evidence as unassessed (%o)', (config) => {
    const risk = cryptoRiskPresentation(config);
    expect(risk).toMatchObject({ assessed: false, score: null });
    const html = renderToStaticMarkup(<CryptoRiskChip config={config} />);
    expect(html).toContain('aria-label="Not assessed"');
    expect(html).toContain('no numeric catalogue or stored score');
    expect(html).not.toContain('Risk score 0');
  });

  it('keeps a positive legacy score visible during additive-field rollout', () => {
    expect(cryptoRiskPresentation({ risk_score: 100, risk_level: 'Informational' }))
      .toMatchObject({ assessed: true, score: 100, level: 'Critical' });
  });

  it.each([-1, 101, Number.NaN, Number.POSITIVE_INFINITY])(
    'renders an invalid score as unassessed even when its flag is true (%s)',
    (risk_score) => {
      expect(cryptoRiskPresentation({ risk_score, risk_score_assessed: true, risk_level: 'Critical' }))
        .toMatchObject({ assessed: false, score: null });
    },
  );
});
