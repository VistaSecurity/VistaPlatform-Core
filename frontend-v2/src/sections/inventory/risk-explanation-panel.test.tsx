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

describe('RiskExplanationPanel remediation guidance', () => {
  const weak: CryptoComponent = {
    ...component,
    code: 'RC4',
    name: 'RC4',
    strength: 'weak',
    risk_score: 90,
    risk_level: 'Critical',
    remediation_guidance: {
      summary: 'RC4 is broken.',
      steps: ['1. Remove RC4 from the cipher list', '2. Prefer AES-GCM'],
      timeline: 'Immediate - within 7 days',
      cve_references: ['CVE-2013-2566'],
      resources: ['https://www.rfc-editor.org/rfc/rfc7465', 'javascript:alert(1)'],
    },
  };

  it("renders the catalogue's steps, timeline and references for the component that records them", () => {
    const html = renderToStaticMarkup(<RiskExplanationPanel components={[weak]} score={90} />);

    expect(html).toContain('How to fix');
    expect(html).toContain('<li>Remove RC4 from the cipher list</li>');
    expect(html).toContain('Suggested timeline (catalogue): Immediate - within 7 days');
    expect(html).toContain('CVE-2013-2566');
    expect(html).toContain('href="https://www.rfc-editor.org/rfc/rfc7465"');
    expect(html).toContain('rel="noopener noreferrer"');
  });

  it('never turns a non-http(s) resource into a link', () => {
    const html = renderToStaticMarkup(<RiskExplanationPanel components={[weak]} score={90} />);

    expect(html).toContain('javascript:alert(1)');
    expect(html).not.toContain('href="javascript:');
  });

  it('is open on the score-setter and collapsed on the others', () => {
    const offered: CryptoComponent = { ...weak, code: '3DES', sets_score: false, is_inferred: true, risk_score: 70, risk_level: 'High' };
    const html = renderToStaticMarkup(<RiskExplanationPanel components={[weak, offered]} score={90} />);
    const blocks = html.match(/<details[^>]*data-testid="remediation-guidance"[^>]*>/g) ?? [];

    expect(blocks).toHaveLength(2);
    expect(blocks[0]).toContain(' open=""');
    expect(blocks[1]).not.toContain(' open');
  });

  it('shows no "How to fix" for a component whose catalogue row records none', () => {
    const html = renderToStaticMarkup(<RiskExplanationPanel components={[component]} score={20} />);

    expect(html).not.toContain('How to fix');
  });
});
