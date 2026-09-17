import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { CryptoRisk } from './model';
import { CryptoAssessment } from './crypto-assessment';

function risk(over: Partial<CryptoRisk>): CryptoRisk {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    tenant_id: '22222222-2222-2222-2222-222222222222',
    asset_id: '33333333-3333-3333-3333-333333333333',
    crypto_implementation_id: '44444444-4444-4444-4444-444444444444',
    severity: 'high',
    category: 'algorithm',
    issue_type: 'weak_configuration',
    current_value: 'SHA-1',
    description: 'Weak component observed',
    recommendation: 'Replace it',
    detected_at: '2026-09-17T00:00:00Z',
    ...over,
  };
}

describe('CryptoAssessment', () => {
  it('shows configuration score contributors and explicit evidence limits', () => {
    const html = renderToStaticMarkup(<CryptoAssessment risk={risk({
      assessment_basis: 'configuration',
      risk_score: 70,
      score_sources: ['SHA-1 [hash]', 'key_size rule: RSA'],
      assessment_limitations: ['observed cipher has no resolved catalogue component'],
    })} />);

    expect(html).toContain('Configuration risk');
    expect(html).toContain('Risk score');
    expect(html).toContain('>70<');
    expect(html).toContain('Numeric contributors');
    expect(html).toContain('SHA-1 [hash]');
    expect(html).toContain('key_size rule: RSA');
    expect(html).toContain('Assessment limitations');
    expect(html).toContain('observed cipher has no resolved catalogue component');
  });

  it('keeps certificate lifecycle severity separate from a configuration score', () => {
    const html = renderToStaticMarkup(<CryptoAssessment risk={risk({
      assessment_basis: 'certificate_lifecycle',
      severity: 'critical',
      risk_score: 20,
      score_sources: ['AES-256-GCM [cipher_suite]'],
    })} />);

    expect(html).toContain('Certificate lifecycle');
    expect(html).toContain('Severity follows certificate lifecycle evidence');
    expect(html).toContain('configuration risk score, when shown, is a separate assessment');
    expect(html).toContain('>20<');
    expect(html).toContain('AES-256-GCM [cipher_suite]');
  });

  it('explains retained history without fabricating a current numeric assessment', () => {
    const html = renderToStaticMarkup(<CryptoAssessment risk={risk({
      assessment_basis: 'retained_finding',
      severity: null,
      risk_score: null,
      score_sources: [],
      assessment_limitations: ['Current evidence is incomplete'],
    })} />);

    expect(html).toContain('Retained finding');
    expect(html).toContain('previous active issue remains visible');
    expect(html).toContain('Not scored');
    expect(html).not.toContain('Numeric contributors');
    expect(html).toContain('Current evidence is incomplete');
  });
});
