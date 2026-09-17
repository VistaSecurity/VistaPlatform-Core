import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { RiskExplanationPanel } from './drawers';
import type { CryptoComponent } from './risk-explanation';

const component: CryptoComponent = {
  algorithm_type: 'symmetric',
  algorithm_id: 'aes256',
  code: 'AES256',
  name: 'AES-256',
  category: 'symmetric',
  strength: 'strong',
  deprecation_status: 'current',
  risk_score: 20,
  risk_level: 'Low',
  sets_score: true,
  is_inferred: false,
  recommended_alternatives: [],
  is_pqc: false,
};

describe('RiskExplanationPanel evidence copy', () => {
  it('describes the numeric contribution without turning it into qualitative strength', () => {
    const html = renderToStaticMarkup(<RiskExplanationPanel components={[component]} score={20} />);

    expect(html).toContain('highest numeric catalogue contribution');
    expect(html).not.toContain('only as strong');
  });

  it('does not invent the cause of a stored score above current catalogue evidence', () => {
    const html = renderToStaticMarkup(<RiskExplanationPanel components={[component]} score={95} />);

    expect(html).toContain('does not establish whether the difference comes from a catalogue change or from other checks');
    expect(html).not.toContain('chiefly key size');
  });
});
