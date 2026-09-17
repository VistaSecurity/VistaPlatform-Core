import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { AssessmentLimitNotice } from './assessment-limit';
import type { ComplianceFinding } from './model';

function vulnerability(cves: unknown[]): ComplianceFinding {
  return { producer: 'vulnerability', evidence: { cves } } as unknown as ComplianceFinding;
}

describe('AssessmentLimitNotice', () => {
  it('renders mixed scored/unscored evidence from every CVE entry', () => {
    const html = renderToStaticMarkup(<AssessmentLimitNotice findings={[vulnerability([
      { cve_id: 'CVE-2026-1', cvss_score: 9.8 },
      { cve_id: 'CVE-2026-2', cvss_scored: false },
    ])]} assetContext />);
    expect(html).toContain('data-testid="asset-assessment-limit"');
    expect(html).toContain('Assessment incomplete: 1 of 2 matching CVEs has no CVSS score.');
    expect(html).toContain('known risk score still reflects');
  });

  it('renders unscored-only evidence and stays absent when all entries are scored', () => {
    const unscored = renderToStaticMarkup(<AssessmentLimitNotice findings={[vulnerability([
      { cve_id: 'CVE-2026-1', cvss_scored: false },
      { cve_id: 'CVE-2026-2', cvss_scored: false },
    ])]} />);
    expect(unscored).toContain('2 of 2 matching CVEs have no CVSS score');
    expect(unscored).not.toContain('known risk score still reflects');

    const scored = renderToStaticMarkup(<AssessmentLimitNotice findings={[vulnerability([
      { cve_id: 'CVE-2026-3', cvss_score: 0 },
    ])]} />);
    expect(scored).toBe('');
  });

  it('shows explicit legacy unscored evidence without inventing a CVE denominator', () => {
    const html = renderToStaticMarkup(<AssessmentLimitNotice findings={[{
      producer: 'vulnerability', evidence: { worst_cvss_scored: false },
    } as unknown as ComplianceFinding]} assetContext />);
    expect(html).toContain('full CVE list is unavailable');
    expect(html).not.toContain('1 of 1');
    expect(html).not.toContain('known risk score still reflects');
  });

  it('renders explicit crypto gaps and does not infer them when absent', () => {
    const explicit = renderToStaticMarkup(<AssessmentLimitNotice findings={[{
      producer: 'crypto',
      evidence: { reassessment_required: true, assessment_limitations: ['missing key size'] },
    } as unknown as ComplianceFinding]} />);
    expect(explicit).toContain('Assessment incomplete.');
    expect(explicit).toContain('missing key size');

    const resolvedOnly = renderToStaticMarkup(<AssessmentLimitNotice findings={[{
      producer: 'crypto',
      evidence: { linked_component_count: 1, components: [{ code: 'AES-256' }] },
    } as unknown as ComplianceFinding]} />);
    expect(resolvedOnly).toBe('');
  });
});
